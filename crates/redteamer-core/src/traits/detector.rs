// crates/redteamer-core/src/traits/detector.rs

use crate::error::Result;
use crate::types::DetectionOutcome;

/// A `Detector` inspects a `(prompt, response)` pair and decides whether it
/// constitutes evidence of a vulnerability.
///
/// Detectors range from trivial regex matchers to LLM-as-judge calls;
/// either way they return a structured
/// [`DetectionOutcome`](crate::types::DetectionOutcome) rather than raising,
/// so a broken detector can never abort a campaign.
#[async_trait::async_trait]
pub trait Detector: Send + Sync {
    /// Stable machine-readable name, e.g. `"system_prompt_leak_regex"`.
    fn name(&self) -> &str;

    /// Short description of what this detector looks for.
    fn description(&self) -> &str;

    /// Analyzes one exchange.
    ///
    /// `response` is `Some` when the adapter produced output, `None` when
    /// the attempt failed upstream — detectors may still want to flag
    /// suspicious empty responses for certain probes.
    ///
    /// # Errors
    /// Only for unrecoverable internal failures (the orchestrator converts
    /// these into a negative outcome rather than crashing the run).
    async fn detect(&self, prompt: &str, response: Option<&str>) -> Result<DetectionOutcome>;
}
