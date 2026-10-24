// crates/redteamer-detectors/src/pipeline.rs

use redteamer_core::error::Result;
use redteamer_core::traits::detector::{DetectContext, Detector};
use redteamer_core::types::{DetectionOutcome, DetectorPolarity};
use std::sync::Arc;

/// Composes several detectors and evaluates a single [`DetectContext`]
/// exchange against all of them concurrently.
///
/// Each detector runs in its own tokio task via [`JoinSet`]; a panicking
/// detector degrades to a negative outcome instead of aborting the scan,
/// preserving the "broken detector never kills a campaign" invariant.
#[derive(Clone, Default)]
pub struct DetectorPipeline {
    detectors: Vec<Arc<dyn Detector>>,
}

impl std::fmt::Debug for DetectorPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait objects are not Debug; report only the composition shape.
        f.debug_struct("DetectorPipeline")
            .field("detectors", &self.detectors.len())
            .finish()
    }
}

impl DetectorPipeline {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Builds a pipeline from an iterator of shared detectors.
    #[must_use]
    pub fn from_detectors(detectors: impl IntoIterator<Item = Arc<dyn Detector>>) -> Self {
        Self {
            detectors: detectors.into_iter().collect(),
        }
    }

    /// Registers one more detector.
    pub fn push(&mut self, detector: Arc<dyn Detector>) {
        self.detectors.push(detector);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Runs every registered detector concurrently over `ctx`.
    ///
    /// Returns one [`DetectionOutcome`] per detector, in *registration
    /// order* (not completion order) so downstream consumers see stable
    /// output across runs.
    ///
    /// # Errors
    /// Never fails structurally; individual detector failures are encoded
    /// as non-matching outcomes with `confidence: 0.0`.
    pub async fn run(&self, ctx: &DetectContext) -> Result<Vec<DetectionOutcome>> {
        let mut tasks = tokio::task::JoinSet::new();
        let shared_ctx = Arc::new(ctx.clone());

        for (index, detector) in self.detectors.iter().enumerate() {
            let detector = Arc::clone(detector);
            let ctx_clone = Arc::clone(&shared_ctx);
            let name = detector.name().to_owned();

            tasks.spawn(async move {
                (index, name, detector.detect(&ctx_clone).await)
            });
        }

        let mut indexed = Vec::with_capacity(tasks.len());
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, _, Ok(outcome))) => indexed.push((index, outcome)),
                Ok((_, name, Err(err))) => indexed.push((
                    usize::MAX,
                    DetectionOutcome {
                        detector_name: name,
                        matched: false,
                        polarity: DetectorPolarity::Vulnerable,
                        confidence: 0.0,
                        rationale: Some(format!("detector error: {err}")),
                    },
                )),
                // Panicked task.
                Err(join_err) => indexed.push((
                    usize::MAX,
                    DetectionOutcome {
                        detector_name: "<unknown>".into(),
                        matched: false,
                        polarity: DetectorPolarity::Vulnerable,
                        confidence: 0.0,
                        rationale: Some(format!("task failure: {join_err}")),
                    },
                )),
            }
        }

        indexed.sort_by_key(|(index, _)| *index);
        Ok(indexed.into_iter().map(|(_, outcome)| outcome).collect())
    }
}

