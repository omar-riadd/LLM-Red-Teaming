// crates/redteamer-core/src/traits/detector.rs

use crate::error::Result;
use crate::types::{DetectionOutcome, OwaspCategory};
use serde::{Deserialize, Serialize};

/// Owned evaluation context passed to [`Detector::detect`].
///
/// Owns all strings so it can be shared into `tokio::spawn` / `JoinSet` tasks
/// via `Arc<DetectContext>` without lifetime constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectContext {
    /// The attack prompt sent to the target.
    pub prompt: String,
    /// The raw response returned by the target, if any.
    pub response: Option<String>,
    /// Optional canary token injected into the target's system prompt.
    pub canary: Option<String>,
    /// Primary OWASP category being probed.
    pub category: OwaspCategory,
    /// Human-readable description of what the probe is testing.
    pub probe_goal: String,
}

impl DetectContext {
    /// Creates a basic detection context from a prompt and optional response.
    #[must_use]
    pub fn new(prompt: impl Into<String>, response: Option<impl Into<String>>) -> Self {
        Self {
            prompt: prompt.into(),
            response: response.map(Into::into),
            canary: None,
            category: OwaspCategory::PromptInjection,
            probe_goal: String::new(),
        }
    }

    #[must_use]
    pub fn with_canary(mut self, canary: Option<String>) -> Self {
        self.canary = canary;
        self
    }

    #[must_use]
    pub fn with_category(mut self, category: OwaspCategory) -> Self {
        self.category = category;
        self
    }

    #[must_use]
    pub fn with_probe_goal(mut self, probe_goal: impl Into<String>) -> Self {
        self.probe_goal = probe_goal.into();
        self
    }
}

/// A `Detector` inspects a [`DetectContext`] and decides whether it
/// constitutes evidence of a vulnerability or an explicit refusal.
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

    /// Analyzes one exchange given `ctx`.
    ///
    /// `ctx.response` is `Some` when the adapter produced output, `None` when
    /// the attempt failed upstream.
    ///
    /// # Errors
    /// Only for unrecoverable internal failures (the orchestrator converts
    /// these into a negative outcome rather than crashing the run).
    async fn detect(&self, ctx: &DetectContext) -> Result<DetectionOutcome>;
}

