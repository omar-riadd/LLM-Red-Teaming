// crates/redteamer-adapters/src/openai_compatible.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, Role, TargetAdapter, ToolCall,
    ToolDefinition,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_OPENROUTER_URL: &str = "https://openrouter.ai/api/v1";
const DEFAULT_VLLM_URL: &str = "http://localhost:8000/v1";

/// Generic target adapter for OpenAI-compatible inference servers
/// (vLLM, OpenRouter, TGI, LocalAI, Ollama OpenAI compatibility layer, etc.).
pub struct OpenAiCompatibleAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    api_key: Option<String>,
    headers: HashMap<String, String>,
    default_options: GenerationOptions,
    limiter: Mutex<RateLimiter>,
}

impl OpenAiCompatibleAdapter {
    /// Builds a generic OpenAI-compatible adapter targeting `model` at `base_url`.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Adapter`] if the HTTP client fails to construct.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));
        if crate::is_loopback_url(&base_url) {
            builder = builder.no_proxy();
        }
        let client = builder.build().map_err(|e| RedTeamerError::Adapter {
            adapter: "openai-compatible",
            message: format!("failed to build HTTP client: {e}"),
            source: Some(Box::new(e)),
        })?;

        let model = model.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "openai-compatible",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model),
            },
            base_url,
            api_key: None,
            headers: HashMap::new(),
            default_options: GenerationOptions::default(),
            limiter: Mutex::new(RateLimiter::default()),
        })
    }

    /// Sets the API authentication key (sent as `Authorization: Bearer <key>`).
    #[must_use]
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Inserts a custom HTTP header into all dispatched requests.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Preset constructor for OpenRouter (`https://openrouter.ai/api/v1`).
    ///
    /// Automatically injects `HTTP-Referer` and `X-Title` attribution headers.
    ///
    /// # Errors
    /// See [`OpenAiCompatibleAdapter::new`].
    pub fn for_openrouter(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        let adapter = Self::new(DEFAULT_OPENROUTER_URL, model)?
            .with_api_key(api_key)
            .with_header("HTTP-Referer", "https://github.com/redteamer/llm-redteamer")
            .with_header("X-Title", "llm-redteamer");
        Ok(adapter)
    }

    /// Preset constructor for local/hosted vLLM servers.
    ///
    /// # Errors
    /// See [`OpenAiCompatibleAdapter::new`].
    pub fn for_vllm(base_url: Option<&str>, model: impl Into<String>) -> Result<Self> {
        let url = base_url.unwrap_or(DEFAULT_VLLM_URL);
        Self::new(url, model)
    }

    /// Configures a custom sustained requests-per-second rate limit.
    #[must_use]
    pub fn with_rate_limit(self, rps: f64) -> Self {
        let rps = rps.max(0.1);
        Self {
            limiter: Mutex::new(RateLimiter::new((rps * 2.0).max(5.0), rps)),
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

    async fn complete(&self, body: &CompatChatRequest) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut request = self.client.post(&url);

        if let Some(ref key) = self.api_key {
            if !key.trim().is_empty() && key != "none" {
                request = request.bearer_auth(key);
            }
        }

        for (k, v) in &self.headers {
            request = request.header(k, v);
        }

        let response = request
            .json(body)
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
                message: format!("HTTP {status}: {}", truncate(&payload, 512)),
                source: None,
            });
        }

        let parsed: CompatChatResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed completion payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        let choice = parsed.choices.first();
        let refusal = choice.and_then(|c| c.message.refusal.clone());
        let text = choice
            .and_then(|c| c.message.content.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| refusal.clone())
            .unwrap_or_default();

        let tool_calls = choice
            .map(|c| {
                c.message
                    .tool_calls
                    .iter()
                    .map(|tc| ToolCall {
                        name: tc.function.name.clone(),
                        arguments: serde_json::from_str(&tc.function.arguments).unwrap_or_else(
                            |_| serde_json::Value::String(tc.function.arguments.clone()),
                        ),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut metadata = parsed
            .usage
            .map(|u| serde_json::to_value(u).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(ref_str) = refusal {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert("refusal".to_owned(), serde_json::Value::String(ref_str));
            }
        }

        Ok(AdapterResponse {
            text,
            tool_calls,
            completed: choice
                .is_some_and(|c| matches!(c.finish_reason.as_deref(), Some("stop" | "tool_calls"))),
            metadata,
        })
    }
}

#[async_trait]
impl TargetAdapter for OpenAiCompatibleAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
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

        let active_tools = if !opts.tools.is_empty() {
            &opts.tools
        } else {
            &self.default_options.tools
        };
        let tools: Vec<CompatToolIn> = active_tools
            .iter()
            .cloned()
            .map(|function| CompatToolIn {
                tool_type: "function",
                function,
            })
            .collect();

        let req = CompatChatRequest {
            model: self.info.model.clone().unwrap_or_default(),
            messages: wire_messages,
            temperature: opts.temperature.or(self.default_options.temperature),
            max_tokens: opts.max_tokens.or(self.default_options.max_tokens),
            seed: opts.seed.or(self.default_options.seed),
            tools,
        };
        self.complete(&req).await
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CompatChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<CompatToolIn>,
}

#[derive(Debug, Serialize)]
struct CompatToolIn {
    #[serde(rename = "type")]
    tool_type: &'static str,
    function: ToolDefinition,
}

#[derive(Debug, Deserialize)]
struct CompatChatResponse {
    choices: Vec<CompatChoice>,
    #[serde(default)]
    usage: Option<CompatUsage>,
}

#[derive(Debug, Deserialize)]
struct CompatChoice {
    message: CompatChatMessageOut,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompatChatMessageOut {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
    #[serde(default)]
    tool_calls: Vec<CompatToolCallOut>,
}

#[derive(Debug, Deserialize)]
struct CompatToolCallOut {
    function: CompatFunctionCallOut,
}

#[derive(Debug, Deserialize)]
struct CompatFunctionCallOut {
    name: String,
    #[serde(default)]
    arguments: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompatUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}
