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
pub fn create_adapter(config: &AdapterConfig) -> Result<Box<dyn redteamer_core::traits::TargetAdapter>> {
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
            Some(url) => Box::new(AnthropicAdapter::with_base_url(api_key, model, url.clone())?),
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
