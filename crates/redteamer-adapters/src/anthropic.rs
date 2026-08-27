// crates/redteamer-adapters/src/anthropic.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{AdapterInfo, AdapterResponse, TargetAdapter};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Adapter for Anthropic's Messages API.
pub struct AnthropicAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    api_key: String,
    max_tokens: u32,
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
                model: Some(model.clone()),
            },
            base_url: base_url.into(),
            api_key: api_key.into(),
            max_tokens: 1024,
            limiter: Mutex::new(RateLimiter::default()),
        })
    }
}

#[derive(Debug, Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
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

    async fn send(&self, prompt: &str) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let body = MessagesRequest {
            model: self.info.model.as_deref().unwrap_or_default(),
            max_tokens: self.max_tokens,
            messages: vec![MessageIn {
                role: "user",
                content: prompt,
            }],
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
                message: format!("HTTP {status}: {}", payload.chars().take(512).collect::<String>()),
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
            metadata: serde_json::json!({ "stop_reason": parsed.stop_reason }),
        })
    }
}
