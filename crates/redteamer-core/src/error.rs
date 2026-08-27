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

/// Convenience alias used throughout the framework.
pub type Result<T, E = RedTeamerError> = std::result::Result<T, E>;
