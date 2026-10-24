// crates/redteamer-core/src/error.rs

use thiserror::Error;

/// Unified error type for the entire `llm-redteamer` framework.
///
/// All fallible operations across adapters, probes, detectors, and
/// reporters funnel through this enum so callers can `?`-propagate
/// without per-crate error plumbing.
#[derive(Debug, Error)]
pub enum RedTeamerError {
    /// A target adapter failed to communicate with the LLM backend.
    #[error("adapter '{adapter}' failed: {message}")]
    Adapter {
        adapter: &'static str,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// A probe could not be executed (e.g., malformed attack corpus).
    #[error("probe failed: {0}")]
    Probe(String),

    /// A detector crashed or produced an unusable result.
    #[error("detector failed: {0}")]
    Detector(String),

    /// Report serialization or export failure.
    #[error("report export failed: {0}")]
    Report(String),

    /// Requested functionality is not implemented by the plugin.
    #[error("operation not supported: {0}")]
    Unsupported(String),

    /// Invalid or out-of-domain configuration supplied by the caller.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Serialization / deserialization failures (serde-backed formats).
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Anything else; escape hatch accepting any boxed `Send + Sync` error.
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl RedTeamerError {
    /// Returns `true` if this error represents a transient transport or HTTP failure
    /// (HTTP 408, 429, 500, 502, 503, 504, timeout, or connection reset) that should
    /// be retried with backoff.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Adapter { message, .. } => {
                let msg = message.to_lowercase();
                msg.contains("http 408")
                    || msg.contains("http 429")
                    || msg.contains("http 500")
                    || msg.contains("http 502")
                    || msg.contains("http 503")
                    || msg.contains("http 504")
                    || msg.contains("timed out")
                    || msg.contains("timeout")
                    || msg.contains("connection reset")
                    || msg.contains("connection refused")
                    || msg.contains("temporarily unavailable")
                    || msg.contains("rate limit")
            }
            _ => false,
        }
    }
}

/// Convenience alias used throughout the framework.
pub type Result<T, E = RedTeamerError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_identifies_transient_http_and_timeout_errors() {
        let rate_limited = RedTeamerError::Adapter {
            adapter: "openai-chat",
            message: "HTTP 429 Too Many Requests: rate limit exceeded".into(),
            source: None,
        };
        assert!(rate_limited.is_retryable());

        let gateway_err = RedTeamerError::Adapter {
            adapter: "anthropic-messages",
            message: "HTTP 503 Service Unavailable".into(),
            source: None,
        };
        assert!(gateway_err.is_retryable());

        let timeout_err = RedTeamerError::Adapter {
            adapter: "ollama-chat",
            message: "request timed out".into(),
            source: None,
        };
        assert!(timeout_err.is_retryable());

        let auth_err = RedTeamerError::Adapter {
            adapter: "openai-chat",
            message: "HTTP 401 Unauthorized".into(),
            source: None,
        };
        assert!(!auth_err.is_retryable());

        let config_err = RedTeamerError::InvalidConfig("bad config".into());
        assert!(!config_err.is_retryable());
    }
}

