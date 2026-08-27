// crates/redteamer-adapters/src/ollama.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{AdapterInfo, AdapterResponse, TargetAdapter};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

/// Adapter for Ollama's native `/api/generate` endpoint — the standard
/// local target for integration tests and the docker-compose environment.
pub struct OllamaAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    limiter: Mutex<RateLimiter>,
}

impl OllamaAdapter {
    /// Points the adapter at an Ollama server (default port 11434).
    ///
    /// # Errors
    /// Fails if the HTTP client cannot be constructed.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| RedTeamerError::Adapter {
                adapter: "ollama-generate",
                message: format!("failed to build HTTP client: {e}"),
                source: Some(Box::new(e)),
            })?;

        let model = model.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "ollama-generate",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model.clone()),
            },
            base_url: base_url.into(),
            // Local inference is free; only guard against accidental
            // request storms against the dev box.
            limiter: Mutex::new(RateLimiter::new(64.0, 64.0)),
        })
    }
}

#[derive(Debug, Serialize)]
struct GenerateRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct GenerateResponse {
    #[serde(default)]
    response: String,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    eval_count: Option<u64>,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
}

#[async_trait]
impl TargetAdapter for OllamaAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send(&self, prompt: &str) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let url = format!("{}/api/generate", self.base_url.trim_end_matches('/'));
        let body = GenerateRequest {
            model: self.info.model.as_deref().unwrap_or_default(),
            prompt,
            stream: false,
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
                message: format!("HTTP {status}: {}", payload.chars().take(512).collect::<String>()),
                source: None,
            });
        }

        let parsed: GenerateResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed generate payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        Ok(AdapterResponse {
            completed: parsed.done,
            text: parsed.response,
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
