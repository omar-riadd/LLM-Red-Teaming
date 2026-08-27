// crates/redteamer-core/src/traits/adapter.rs

use crate::error::Result;
use crate::types::AttackRecord;

/// Metadata describing a target adapter.
#[derive(Debug, Clone, PartialEq)]
pub struct AdapterInfo {
    /// Unique adapter name, e.g. `"openai-chat"`.
    pub name: &'static str,
    /// Adapter version (semver string).
    pub version: &'static str,
    /// Model identifier the adapter targets, if pinned.
    pub model: Option<String>,
}

/// Transport-level response from a target.
#[derive(Debug, Clone, PartialEq)]
pub struct AdapterResponse {
    /// Raw text returned by the target.
    pub text: String,
    /// Whether the target reported finishing normally (`true`) or was
    /// truncated / aborted (`false`).
    pub completed: bool,
    /// Free-form provider metadata (usage stats, finish reason, ...).
    pub metadata: serde_json::Value,
}

/// A `TargetAdapter` abstracts communication with an LLM backend
/// (HTTP API, local inference server, gRPC endpoint, ...).
///
/// Implementations must be cheap to share across tasks: wrap them in
/// `Arc` and rely on interior mutability / connection pooling for state.
#[async_trait::async_trait]
pub trait TargetAdapter: Send + Sync {
    /// Static metadata about this adapter.
    fn info(&self) -> &AdapterInfo;

    /// Sends a single prompt to the target and awaits its completion.
    ///
    /// Implementations should be idempotent with respect to retries at
    /// the transport layer but MUST NOT silently retry on their own —
    /// the orchestrator owns retry policy.
    ///
    /// # Errors
    /// Returns [`crate::error::RedTeamerError::Adapter`] for transport,
    /// authentication, or rate-limit failures.
    async fn send(&self, prompt: &str) -> Result<AdapterResponse>;

    /// Sends a multi-turn conversation (used by escalation probes).
    ///
    /// The default implementation is unavailable; adapters that support
    /// conversations should override this. The default returns
    /// [`crate::error::RedTeamerError::Unsupported`].
    async fn send_conversation(&self, turns: &[String]) -> Result<AdapterResponse> {
        let _ = turns;
        Err(crate::error::RedTeamerError::Unsupported(
            "adapter does not support multi-turn conversations".into(),
        ))
    }

    /// Health-check hook invoked before a campaign starts.
    ///
    /// Default: send a benign ping prompt and require a non-empty reply.
    async fn health_check(&self) -> Result<()> {
        let response = self.send("ping").await?;
        if response.text.is_empty() {
            return Err(crate::error::RedTeamerError::Adapter {
                adapter: self.info().name,
                message: "health check returned empty response".into(),
                source: None,
            });
        }
        Ok(())
    }

    /// Attach transport-level context to an attack record before it is
    /// persisted (latency, token usage, etc.). Default: no-op.
    fn enrich_record(&self, record: &mut AttackRecord) {
        let _ = record;
    }
}
