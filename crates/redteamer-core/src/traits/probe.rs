// crates/redteamer-core/src/traits/probe.rs

use crate::error::Result;
use crate::traits::detector::Detector;
use crate::types::{AttackRecord, OwaspCategory};
use std::sync::Arc;
use uuid::Uuid;

/// A `Probe` is an executable attack strategy: it generates payloads from a
/// seed corpus, applies mutations, dispatches them through a
/// [`TargetAdapter`](crate::traits::adapter::TargetAdapter), and records
/// evidence as [`AttackRecord`]s.
///
/// Probes are pure orchestration: they never decide vulnerability — that is
/// delegated to [`Detector`](crate::traits::detector::Detector) plugins.
///
/// Because probes may run thousands of attempts, implementations should be
/// cancellation-safe (cooperative via `tokio` task cancellation) and avoid
/// holding locks across `.await` points.
#[async_trait::async_trait]
pub trait Probe: Send + Sync {
    /// Stable machine-readable name, e.g. `"direct_prompt_injection"`.
    fn name(&self) -> &str;

    /// Human-readable description shown in reports.
    fn description(&self) -> &str;

    /// The OWASP categories this probe covers.
    fn category(&self) -> Vec<OwaspCategory>;

    /// Executes the probe against `target`.
    ///
    /// `session_id` ties all emitted records to one campaign; `concurrency`
    /// hints how many attempts may be in flight simultaneously (the probe
    /// may cap this lower based on its own rate-limit needs).
    ///
    /// # Errors
    /// Returns only *fatal* errors (e.g., cannot read seed corpus).
    /// Per-attempt failures belong inside the emitted
    /// [`AttackRecord`]s with `Verdict::Error`.
    async fn run(
        &self,
        session_id: Uuid,
        target: Arc<dyn crate::traits::adapter::TargetAdapter>,
        concurrency: usize,
        detectors: Arc<[Arc<dyn Detector>]>,
    ) -> Result<Vec<AttackRecord>>;
}
