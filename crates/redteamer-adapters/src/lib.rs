// crates/redteamer-adapters/src/lib.rs

//! Concrete [`TargetAdapter`](redteamer_core::traits::TargetAdapter)
//! implementations for popular LLM backends, plus a config-driven factory.

pub mod anthropic;
pub mod ollama;
pub mod openai;

use redteamer_core::error::{RedTeamerError, Result};
use std::time::{Duration, Instant};

pub use anthropic::AnthropicAdapter;
pub use ollama::OllamaAdapter;
pub use openai::OpenAiAdapter;

/// Error alias for adapter construction, matching the framework-wide
/// error model while giving factory call sites a domain-specific name.
pub type AdapterError = RedTeamerError;

/// Declarative description of a scan target, deserializable from CLI
/// args or YAML campaign files.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum AdapterConfig {
    /// OpenAI or any OpenAI-compatible gateway.
    OpenAi {
        api_key: String,
        model: String,
        #[serde(default)]
        base_url: Option<String>,
    },
    /// Anthropic Messages API.
    Anthropic {
        api_key: String,
        model: String,
        #[serde(default)]
        base_url: Option<String>,
    },
    /// Local Ollama server (no auth).
    Ollama {
        #[serde(default = "default_ollama_url")]
        base_url: String,
        model: String,
    },
}

fn default_ollama_url() -> String {
    "http://localhost:11434".to_owned()
}

impl AdapterConfig {
    /// Loads an [`AdapterConfig`] from a JSON or YAML string (sniffed by
    /// first non-whitespace character).
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Serialization`] on malformed input.
    pub fn from_str_any_format(raw: &str) -> Result<Self> {
        if raw.trim_start().starts_with('{') {
            Ok(serde_json::from_str(raw)?)
        } else {
            serde_yaml_compat(raw)
        }
    }
}

fn serde_yaml_compat(raw: &str) -> Result<AdapterConfig> {
    let _ = raw;
    // TODO(Phase 5): pull `serde_yaml` into this crate for campaign-file
    // support; JSON is the only file format wired up today.
    Err(RedTeamerError::Unsupported(
        "YAML target configs land in Phase 5; use JSON".into(),
    ))
}

/// Instantiates the concrete adapter described by `config`.
///
/// # Errors
/// Transport-client construction failures surface as
/// [`RedTeamerError::Adapter`].
pub fn create_adapter(
    config: &AdapterConfig,
) -> Result<Box<dyn redteamer_core::traits::TargetAdapter>> {
    let adapter: Box<dyn redteamer_core::traits::TargetAdapter> = match config {
        AdapterConfig::OpenAi {
            api_key,
            model,
            base_url,
        } => match base_url {
            Some(url) => Box::new(OpenAiAdapter::with_base_url(api_key, model, url.clone())?),
            None => Box::new(OpenAiAdapter::new(api_key, model)?),
        },
        AdapterConfig::Anthropic {
            api_key,
            model,
            base_url,
        } => match base_url {
            Some(url) => Box::new(AnthropicAdapter::with_base_url(
                api_key,
                model,
                url.clone(),
            )?),
            None => Box::new(AnthropicAdapter::new(api_key, model)?),
        },
        AdapterConfig::Ollama { base_url, model } => {
            Box::new(OllamaAdapter::new(base_url.clone(), model.clone())?)
        }
    };
    Ok(adapter)
}

/// Minimal token-bucket rate limiter shared by adapters.
///
/// Tokens refill continuously at `refill_per_sec`; each request consumes
/// one token. Callers `.await` [`RateLimiter::acquire`] before dispatching.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Creates a limiter with `capacity` burst tokens refilling at
    /// `refill_per_sec`.
    #[must_use]
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last_refill = Instant::now();
        }
    }

    /// Waits until a token is available and consumes it.
    pub async fn acquire(&mut self) {
        loop {
            self.refill();
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            let deficit = 1.0 - self.tokens;
            let wait = Duration::from_secs_f64(deficit / self.refill_per_sec);
            tokio::time::sleep(wait).await;
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Conservative default: bursts of 5, sustained 1 req/s.
        Self::new(5.0, 1.0)
    }
}

/// Combines an adapter's default system prompt (e.g. from CLI `--system-prompt`)
/// with a per-request probe system prompt (`opts.system_prompt`) so neither is lost.
pub(crate) fn merge_system_prompts(
    default_sp: Option<&str>,
    probe_sp: Option<&str>,
) -> Option<String> {
    match (
        default_sp.filter(|s| !s.is_empty()),
        probe_sp.filter(|s| !s.is_empty()),
    ) {
        (Some(def), Some(probe)) => Some(format!("{def}\n\n{probe}")),
        (Some(def), None) => Some(def.to_owned()),
        (None, Some(probe)) => Some(probe.to_owned()),
        (None, None) => None,
    }
}

/// Returns `true` when `url` targets a loopback interface (`localhost`, `127.0.0.1`, `[::1]`),
/// so the HTTP client bypasses any ambient `HTTP_PROXY` for local inference servers.
pub(crate) fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host = rest.split(['/', ':']).next().unwrap_or_default();
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "[::1]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use redteamer_core::traits::adapter::{
        ChatMessage, GenerationOptions, TargetAdapter, ToolDefinition,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct CapturedRequest {
        request_line: String,
        headers_lower: String,
        body: serde_json::Value,
    }

    async fn spawn_mock_http_server(
        responses: Vec<(&'static str, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<CapturedRequest>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            let mut captured = Vec::with_capacity(responses.len());
            for (status_line, resp_body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end = loop {
                    let n = stream.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break 0;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };

                let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let mut lines = header_str.split("\r\n");
                let request_line = lines.next().unwrap_or_default().to_owned();
                let headers_lower = header_str.to_lowercase();

                let content_length: usize = headers_lower
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);

                while buf.len() < header_end + content_length {
                    let n = stream.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                let body_bytes = &buf[header_end..(header_end + content_length).min(buf.len())];
                let body: serde_json::Value = if body_bytes.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(body_bytes).unwrap_or(serde_json::Value::Null)
                };

                captured.push(CapturedRequest {
                    request_line,
                    headers_lower,
                    body,
                });

                let http_resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                stream.write_all(http_resp.as_bytes()).await.unwrap();
                let _ = stream.shutdown().await;
            }
            captured
        });

        (base_url, handle)
    }

    #[test]
    fn adapter_builders_and_options_configure_cleanly() {
        let opts = GenerationOptions {
            system_prompt: Some("You are a helpful assistant.".into()),
            temperature: Some(0.2),
            max_tokens: Some(2048),
            seed: Some(42),
            tools: Vec::new(),
        };

        let ollama = OllamaAdapter::new("http://localhost:11434", "llama3.2")
            .unwrap()
            .with_rate_limit(10.0)
            .with_default_options(opts.clone());
        assert_eq!(ollama.info().name, "ollama-chat");
        assert_eq!(ollama.info().model.as_deref(), Some("llama3.2"));

        let openai = OpenAiAdapter::new("sk-test", "gpt-4o-mini")
            .unwrap()
            .with_rate_limit(5.0)
            .with_default_options(opts.clone());
        assert_eq!(openai.info().name, "openai-chat");

        let anthropic = AnthropicAdapter::new("sk-ant-test", "claude-sonnet-4-5")
            .unwrap()
            .with_rate_limit(5.0)
            .with_default_options(opts);
        assert_eq!(anthropic.info().name, "anthropic-messages");
    }

    #[test]
    fn merge_system_prompts_combines_cli_and_probe_prompts() {
        assert_eq!(
            merge_system_prompts(Some("CLI prompt"), Some("Probe canary: SECRET")),
            Some("CLI prompt\n\nProbe canary: SECRET".to_owned())
        );
        assert_eq!(
            merge_system_prompts(Some("CLI prompt"), None),
            Some("CLI prompt".to_owned())
        );
        assert_eq!(
            merge_system_prompts(None, Some("Probe prompt")),
            Some("Probe prompt".to_owned())
        );
        assert_eq!(merge_system_prompts(None, None), None);
    }

    #[test]
    fn adapter_config_parses_json_and_builds_adapter() {
        let raw =
            r#"{"provider":"ollama","base_url":"http://localhost:11434","model":"qwen2:0.5b"}"#;
        let cfg = AdapterConfig::from_str_any_format(raw).unwrap();
        let adapter = create_adapter(&cfg).unwrap();
        assert_eq!(adapter.info().model.as_deref(), Some("qwen2:0.5b"));
    }

    #[tokio::test]
    async fn openai_adapter_http_roundtrip_tools_and_refusal() {
        let resp1 = serde_json::json!({
            "choices": [{
                "message": {
                    "content": "",
                    "tool_calls": [{
                        "function": {
                            "name": "delete_files",
                            "arguments": "{\"path\":\"/tmp/archive\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 25, "completion_tokens": 12}
        })
        .to_string();

        let resp2 = serde_json::json!({
            "choices": [{
                "message": {
                    "content": null,
                    "refusal": "I cannot fulfill this destructive request."
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 18, "completion_tokens": 9}
        })
        .to_string();

        let (base_url, handle) =
            spawn_mock_http_server(vec![("200 OK", resp1), ("200 OK", resp2)]).await;

        let adapter =
            OpenAiAdapter::with_base_url("sk-test-123", "gpt-4o-mini", format!("{base_url}/v1"))
                .unwrap()
                .with_rate_limit(100.0)
                .with_default_options(GenerationOptions {
                    system_prompt: Some("Global policy.".into()),
                    ..GenerationOptions::default()
                });

        let opts = GenerationOptions {
            system_prompt: Some("Probe canary: SECRET".into()),
            tools: vec![ToolDefinition {
                name: "delete_files".into(),
                description: "Delete files".into(),
                parameters: serde_json::json!({"type": "object"}),
            }],
            ..GenerationOptions::default()
        };

        let out1 = adapter
            .send_chat(&[ChatMessage::user("delete /tmp/archive")], &opts)
            .await
            .unwrap();
        assert!(out1.completed);
        assert_eq!(out1.tool_calls.len(), 1);
        assert_eq!(out1.tool_calls[0].name, "delete_files");
        assert_eq!(out1.tool_calls[0].arguments["path"], "/tmp/archive");
        assert_eq!(out1.metadata["prompt_tokens"], 25);

        let out2 = adapter.send("do something unsafe").await.unwrap();
        assert_eq!(out2.text, "I cannot fulfill this destructive request.");
        assert_eq!(
            out2.metadata["refusal"],
            "I cannot fulfill this destructive request."
        );

        let captured = handle.await.unwrap();
        assert_eq!(captured.len(), 2);
        assert!(captured[0]
            .request_line
            .starts_with("POST /v1/chat/completions "));
        assert!(captured[0]
            .headers_lower
            .contains("authorization: bearer sk-test-123"));
        assert_eq!(
            captured[0].body["messages"][0]["content"],
            "Global policy.\n\nProbe canary: SECRET"
        );
        assert_eq!(
            captured[0].body["tools"][0]["function"]["name"],
            "delete_files"
        );
    }

    #[tokio::test]
    async fn anthropic_adapter_http_roundtrip_and_tool_use() {
        let resp = serde_json::json!({
            "content": [
                {"type": "text", "text": "Deploying branch now."},
                {
                    "type": "tool_use",
                    "name": "deploy_production",
                    "input": {"branch": "main"}
                }
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 30, "output_tokens": 15}
        })
        .to_string();

        let (base_url, handle) = spawn_mock_http_server(vec![("200 OK", resp)]).await;

        let adapter = AnthropicAdapter::with_base_url("sk-ant-key", "claude-sonnet-4-5", &base_url)
            .unwrap()
            .with_rate_limit(100.0)
            .with_default_options(GenerationOptions {
                system_prompt: Some("Global safety.".into()),
                ..GenerationOptions::default()
            });

        let opts = GenerationOptions {
            system_prompt: Some("Probe system.".into()),
            tools: vec![ToolDefinition {
                name: "deploy_production".into(),
                description: "Deploy to prod".into(),
                parameters: serde_json::json!({"type": "object"}),
            }],
            ..GenerationOptions::default()
        };

        let out = adapter
            .send_chat(&[ChatMessage::user("deploy main")], &opts)
            .await
            .unwrap();
        assert!(out.completed);
        assert_eq!(out.text, "Deploying branch now.");
        assert_eq!(out.tool_calls.len(), 1);
        assert_eq!(out.tool_calls[0].name, "deploy_production");
        assert_eq!(out.tool_calls[0].arguments["branch"], "main");

        let captured = handle.await.unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].request_line.starts_with("POST /v1/messages "));
        assert!(captured[0].headers_lower.contains("x-api-key: sk-ant-key"));
        assert!(captured[0]
            .headers_lower
            .contains("anthropic-version: 2023-06-01"));
        assert_eq!(
            captured[0].body["system"],
            "Global safety.\n\nProbe system."
        );
        assert_eq!(captured[0].body["tools"][0]["name"], "deploy_production");
        assert!(captured[0].body["tools"][0].get("input_schema").is_some());
    }

    #[tokio::test]
    async fn ollama_adapter_http_roundtrip_tools_and_health_check() {
        let tags_resp = serde_json::json!({"models": [{"name": "llama3.2"}]}).to_string();
        let chat_resp = serde_json::json!({
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "run_shell",
                        "arguments": {"command": "rm -rf ./build"}
                    }
                }]
            },
            "done": true,
            "prompt_eval_count": 22,
            "eval_count": 11
        })
        .to_string();

        let (base_url, handle) =
            spawn_mock_http_server(vec![("200 OK", tags_resp), ("200 OK", chat_resp)]).await;

        let adapter = OllamaAdapter::new(&base_url, "llama3.2")
            .unwrap()
            .with_rate_limit(100.0);

        adapter.health_check().await.unwrap();

        let opts = GenerationOptions {
            temperature: Some(0.1),
            max_tokens: Some(256),
            seed: Some(7),
            tools: vec![ToolDefinition {
                name: "run_shell".into(),
                description: "Run shell".into(),
                parameters: serde_json::json!({"type": "object"}),
            }],
            ..GenerationOptions::default()
        };

        let out = adapter
            .send_chat(&[ChatMessage::user("clean build")], &opts)
            .await
            .unwrap();
        assert!(out.completed);
        assert_eq!(out.tool_calls.len(), 1);
        assert_eq!(out.tool_calls[0].name, "run_shell");
        assert_eq!(out.tool_calls[0].arguments["command"], "rm -rf ./build");
        assert_eq!(out.metadata["prompt_eval_count"], 22);
        assert_eq!(out.metadata["eval_count"], 11);

        let captured = handle.await.unwrap();
        assert_eq!(captured.len(), 2);
        assert!(captured[0].request_line.starts_with("GET /api/tags "));
        assert!(captured[1].request_line.starts_with("POST /api/chat "));
        assert_eq!(captured[1].body["options"]["num_predict"], 256);
        assert_eq!(
            captured[1].body["tools"][0]["function"]["name"],
            "run_shell"
        );
    }

    #[tokio::test]
    async fn adapters_map_http_429_and_401_errors_correctly() {
        let (base_url, _handle) = spawn_mock_http_server(vec![
            ("429 Too Many Requests", "{\"error\":\"rate limit\"}".into()),
            ("401 Unauthorized", "{\"error\":\"bad key\"}".into()),
        ])
        .await;

        let adapter = OpenAiAdapter::with_base_url("sk-bad", "gpt-4o-mini", &base_url)
            .unwrap()
            .with_rate_limit(100.0);

        let err_429 = adapter.send("hello").await.unwrap_err();
        assert!(err_429.is_retryable());

        let err_401 = adapter.send("hello").await.unwrap_err();
        assert!(!err_401.is_retryable());
    }
}
