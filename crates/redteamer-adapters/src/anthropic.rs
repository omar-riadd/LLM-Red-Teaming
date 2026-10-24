// crates/redteamer-adapters/src/anthropic.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, Role, TargetAdapter,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Adapter for Anthropic's Messages API.
pub struct AnthropicAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    api_key: String,
    max_tokens: u32,
    default_options: GenerationOptions,
    limiter: Mutex<RateLimiter>,
}

impl AnthropicAdapter {
    /// Builds an adapter targeting `model` (e.g. `"claude-sonnet-4-5"`).
    ///
    /// # Errors
    /// Fails if the HTTP client cannot be constructed.
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Self::with_base_url(api_key, model, DEFAULT_BASE_URL)
    }

    /// Same as [`AnthropicAdapter::new`] with a custom gateway URL.
    ///
    /// # Errors
    /// See [`AnthropicAdapter::new`].
    pub fn with_base_url(
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| RedTeamerError::Adapter {
                adapter: "anthropic-messages",
                message: format!("failed to build HTTP client: {e}"),
                source: Some(Box::new(e)),
            })?;

        let model = model.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "anthropic-messages",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model),
            },
            base_url: base_url.into(),
            api_key: api_key.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
            default_options: GenerationOptions::default(),
            limiter: Mutex::new(RateLimiter::default()),
        })
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
        if let Some(mt) = opts.max_tokens {
            self.max_tokens = mt;
        }
        self.default_options = opts;
        self
    }
}

#[derive(Debug, Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    messages: Vec<MessageIn<'a>>,
}

#[derive(Debug, Serialize)]
struct MessageIn<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Debug, Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type", default)]
    block_type: String,
    #[serde(default)]
    text: Option<String>,
}

#[async_trait]
impl TargetAdapter for AnthropicAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let mut system_parts: Vec<&str> = Vec::new();
        if let Some(sp) = opts
            .system_prompt
            .as_deref()
            .or(self.default_options.system_prompt.as_deref())
        {
            system_parts.push(sp);
        }
        for m in messages.iter().filter(|m| m.role == Role::System) {
            system_parts.push(&m.content);
        }
        let system = (!system_parts.is_empty()).then(|| system_parts.join("\n\n"));

        let wire_messages: Vec<MessageIn<'_>> = messages
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| MessageIn {
                role: m.role.as_str(),
                content: &m.content,
            })
            .collect();

        let max_tokens = opts
            .max_tokens
            .or(self.default_options.max_tokens)
            .unwrap_or(self.max_tokens);
        let temperature = opts.temperature.or(self.default_options.temperature);

        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let body = MessagesRequest {
            model: self.info.model.as_deref().unwrap_or_default(),
            max_tokens,
            system,
            temperature,
            messages: wire_messages,
        };

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
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

        let parsed: MessagesResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed messages payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        // Concatenate all text blocks; ignore tool_use / thinking blocks.
        let text = parsed
            .content
            .iter()
            .filter(|b| b.block_type == "text")
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("");

        Ok(AdapterResponse {
            completed: parsed.stop_reason.as_deref() == Some("end_turn"),
            text,
            metadata: serde_json::json!({
                "stop_reason": parsed.stop_reason,
                "usage": parsed.usage,
            }),
        })
    }
}

