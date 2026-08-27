// crates/redteamer-adapters/src/openai.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{AdapterInfo, AdapterResponse, TargetAdapter};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";

/// Adapter for OpenAI-compatible chat-completion APIs
/// (OpenAI, Azure-style gateways, vLLM, Ollama's compat layer, ...).
pub struct OpenAiAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    api_key: String,
    /// Shared limiter; the adapter is `Send + Sync` and may be fanned out
    /// across probes, so mutation goes through an async `Mutex`.
    limiter: Mutex<RateLimiter>,
}

impl OpenAiAdapter {
    /// Builds an adapter targeting `model` with the given API key.
    ///
    /// # Errors
    /// Fails if the underlying HTTP client cannot be constructed (e.g.
    /// invalid TLS backend configuration).
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Self::with_base_url(api_key, model, DEFAULT_BASE_URL)
    }

    /// Same as [`OpenAiAdapter::new`] but pointing at a custom
    /// OpenAI-compatible endpoint.
    ///
    /// # Errors
    /// See [`OpenAiAdapter::new`].
    pub fn with_base_url(
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| RedTeamerError::Adapter {
                adapter: "openai-chat",
                message: format!("failed to build HTTP client: {e}"),
                source: Some(Box::new(e)),
            })?;

        let model = model.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "openai-chat",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model.clone()),
            },
            base_url: base_url.into(),
            api_key: api_key.into(),
            limiter: Mutex::new(RateLimiter::default()),
        })
    }

    async fn complete(&self, body: &ChatRequest) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
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

        let parsed: ChatResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed completion payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        let choice = parsed.choices.first();
        let text = choice.and_then(|c| c.message.content.clone()).unwrap_or_default();

        Ok(AdapterResponse {
            text,
            completed: choice.is_some_and(|c| c.finish_reason.as_deref() == Some("stop")),
            metadata: parsed.usage.map(|u| serde_json::to_value(u).unwrap_or_default()).unwrap_or_default(),
        })
    }
}

#[async_trait]
impl TargetAdapter for OpenAiAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send(&self, prompt: &str) -> Result<AdapterResponse> {
        self.complete(&ChatRequest::single_prompt(self.info.model.as_deref().unwrap_or_default(), prompt))
            .await
    }
}

// ---------------------------------------------------------------------------
// Wire types (subset of the chat-completion schema)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
}

impl ChatRequest {
    fn single_prompt(model: &str, prompt: &str) -> Self {
        Self {
            model: model.to_owned(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: prompt.into(),
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ChatMessageOut,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatMessageOut {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Usage {
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
