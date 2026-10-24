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

            tasks.spawn(async move { (index, name, detector.detect(&ctx_clone).await) });
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
        let mut outcomes: Vec<DetectionOutcome> =
            indexed.into_iter().map(|(_, outcome)| outcome).collect();

        // If no vulnerable detector matched on the raw text, evaluate normalized
        // response variants (zero-width stripped, Base64, Hex, ROT13) to catch
        // obfuscated leaks without re-running expensive LLM judge or length checks.
        let any_vuln_matched = outcomes
            .iter()
            .any(|o| o.matched && o.polarity == DetectorPolarity::Vulnerable);
        if !any_vuln_matched {
            if let Some(raw_resp) = ctx.response.as_deref() {
                let variants = crate::normalize::normalize_response_variants(raw_resp);
                for (variant_name, norm_text) in variants {
                    let mut norm_ctx = ctx.clone();
                    norm_ctx.response = Some(norm_text);
                    for (idx, detector) in self.detectors.iter().enumerate() {
                        if idx >= outcomes.len() || outcomes[idx].matched {
                            continue;
                        }
                        if outcomes[idx].polarity != DetectorPolarity::Vulnerable {
                            continue;
                        }
                        if matches!(
                            detector.name(),
                            "llm_judge" | "unbounded_output_length" | "min_length"
                        ) {
                            continue;
                        }
                        if let Ok(mut norm_outcome) = detector.detect(&norm_ctx).await {
                            if norm_outcome.matched
                                && norm_outcome.polarity == DetectorPolarity::Vulnerable
                            {
                                let suffix =
                                    format!(" (matched after {variant_name} normalization)");
                                norm_outcome.rationale = Some(match norm_outcome.rationale {
                                    Some(r) => format!("{r}{suffix}"),
                                    None => suffix.trim_start().to_owned(),
                                });
                                outcomes[idx] = norm_outcome;
                            }
                        }
                    }
                    if outcomes
                        .iter()
                        .any(|o| o.matched && o.polarity == DetectorPolarity::Vulnerable)
                    {
                        break;
                    }
                }
            }
        }

        Ok(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CanaryDetector;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    #[tokio::test]
    async fn pipeline_catches_base64_and_zero_width_obfuscated_canary() {
        let pipeline =
            DetectorPipeline::from_detectors([Arc::new(CanaryDetector::new("canary")) as _]);

        let encoded = STANDARD.encode("CANARY-LLM01-7F9A2B");
        let ctx = DetectContext::new("leak canary", Some(format!("Result: {encoded}")))
            .with_canary(Some("CANARY-LLM01-7F9A2B".into()));
        let outcomes = pipeline.run(&ctx).await.unwrap();
        assert!(outcomes[0].matched);
        assert!(outcomes[0]
            .rationale
            .as_deref()
            .unwrap()
            .contains("base64_decoded normalization"));
    }
}
