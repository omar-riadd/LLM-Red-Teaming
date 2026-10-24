// crates/redteamer-adapters/src/ollama.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, Role, TargetAdapter, ToolCall,
    ToolDefinition,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

/// Adapter for Ollama's native `/api/chat` endpoint — supports system prompts,
/// multi-turn conversation history, tool calling, and generation options (`temperature`,
/// `num_predict`, `seed`).
pub struct OllamaAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    default_options: GenerationOptions,
    limiter: Mutex<RateLimiter>,
}

impl OllamaAdapter {
    /// Points the adapter at an Ollama server (default port 11434).
    ///
    /// # Errors
    /// Fails if the HTTP client cannot be constructed.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let client =
            crate::build_http_client_with_timeout(&base_url, std::time::Duration::from_secs(300))?;

        let model = model.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "ollama-chat",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model),
            },
            base_url,
            default_options: GenerationOptions::default(),
            // Local inference is free; only guard against accidental
            // request storms against the dev box.
            limiter: Mutex::new(RateLimiter::new(64.0, 64.0)),
        })
    }

    /// Configures a custom sustained requests-per-second rate limit.
    #[must_use]
    pub fn with_rate_limit(self, rps: f64) -> Self {
        let rps = rps.max(0.1);
        Self {
            limiter: Mutex::new(RateLimiter::new(rps.max(1.0), rps)),
            ..self
        }
    }

    /// Sets default generation options (system prompt, temperature, max_tokens, seed)
    /// used when per-call options do not override them.
    #[must_use]
    pub fn with_default_options(mut self, opts: GenerationOptions) -> Self {
        self.default_options = opts;
        self
    }
}

#[derive(Debug, Serialize)]
struct OllamaChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaModelOptions>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OllamaToolIn<'a>>,
}

#[derive(Debug, Serialize)]
struct OllamaToolIn<'a> {
    #[serde(rename = "type")]
    tool_type: &'static str,
    function: &'a ToolDefinition,
}

#[derive(Debug, Serialize)]
struct OllamaModelOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    #[serde(default)]
    message: Option<OllamaMessageOut>,
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    eval_count: Option<u64>,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OllamaMessageOut {
    #[serde(default)]
    content: String,
    #[serde(default)]
    tool_calls: Vec<OllamaToolCallOut>,
}

#[derive(Debug, Deserialize)]
struct OllamaToolCallOut {
    function: OllamaFunctionCallOut,
}

#[derive(Debug, Deserialize)]
struct OllamaFunctionCallOut {
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

#[async_trait]
impl TargetAdapter for OllamaAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let mut wire_messages = Vec::with_capacity(messages.len() + 1);
        let sys_prompt = crate::merge_system_prompts(
            self.default_options.system_prompt.as_deref(),
            opts.system_prompt.as_deref(),
        );
        if let Some(sp) = sys_prompt {
            if !messages.first().is_some_and(|m| m.role == Role::System) {
                wire_messages.push(ChatMessage::system(sp));
            }
        }
        wire_messages.extend_from_slice(messages);

        let temperature = opts.temperature.or(self.default_options.temperature);
        let num_predict = opts.max_tokens.or(self.default_options.max_tokens);
        let seed = opts.seed.or(self.default_options.seed);
        let options = if temperature.is_some() || num_predict.is_some() || seed.is_some() {
            Some(OllamaModelOptions {
                temperature,
                num_predict,
                seed,
            })
        } else {
            None
        };

        let active_tools = if !opts.tools.is_empty() {
            &opts.tools
        } else {
            &self.default_options.tools
        };
        let tools: Vec<OllamaToolIn<'_>> = active_tools
            .iter()
            .map(|function| OllamaToolIn {
                tool_type: "function",
                function,
            })
            .collect();

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let body = OllamaChatRequest {
            model: self.info.model.as_deref().unwrap_or_default(),
            messages: wire_messages,
            stream: false,
            options,
            tools,
        };

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("request to {url} failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        let status = response.status();
        let payload = response.text().await.map_err(|e| RedTeamerError::Adapter {
            adapter: self.info.name,
            message: format!("failed to read response body: {e}"),
            source: Some(Box::new(e)),
        })?;

        if !status.is_success() {
            return Err(RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!(
                    "HTTP {status}: {}",
                    payload.chars().take(512).collect::<String>()
                ),
                source: None,
            });
        }

        let parsed: OllamaChatResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed chat payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        let mut tool_calls = Vec::new();
        let text = match parsed.message {
            Some(m) => {
                tool_calls = m
                    .tool_calls
                    .into_iter()
                    .map(|tc| ToolCall {
                        name: tc.function.name,
                        arguments: tc.function.arguments,
                    })
                    .collect();
                m.content
            }
            None => parsed.response.unwrap_or_default(),
        };

        Ok(AdapterResponse {
            completed: parsed.done,
            text,
            tool_calls,
            metadata: serde_json::json!({
                "prompt_eval_count": parsed.prompt_eval_count,
                "eval_count": parsed.eval_count,
            }),
        })
    }

    async fn health_check(&self) -> Result<()> {
        // Cheap liveness probe: list installed models.
        let url = format!("{}/api/tags", self.base_url.trim_end_matches('/'));
        self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("health check failed: {e}"),
                source: Some(Box::new(e)),
            })?
            .error_for_status()
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("target unhealthy: {e}"),
                source: Some(Box::new(e)),
            })?;
        Ok(())
    }
}
