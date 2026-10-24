// crates/redteamer-detectors/src/regex_set.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::detector::{DetectContext, Detector};
use redteamer_core::types::{DetectionOutcome, DetectorPolarity};
use regex::RegexSet;

/// Multi-pattern detector backed by the `regex` crate's [`RegexSet`],
/// evaluating all patterns in a single pass over the response.
#[derive(Debug, Clone)]
pub struct RegexSetDetector {
    name: String,
    description: String,
    set: RegexSet,
    patterns: Vec<String>,
    confidence: f32,
    polarity: DetectorPolarity,
}

impl RegexSetDetector {
    /// Compiles `patterns` into one [`RegexSet`].
    ///
    /// # Errors
    /// Returns [`RedTeamerError::InvalidConfig`] on empty input or any
    /// regex compilation failure.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        Self::with_confidence(name, description, patterns, 0.85)
    }

    /// Full-control constructor.
    ///
    /// # Errors
    /// See [`RegexSetDetector::new`].
    pub fn with_confidence(
        name: impl Into<String>,
        description: impl Into<String>,
        patterns: impl IntoIterator<Item = impl Into<String>>,
        confidence: f32,
    ) -> Result<Self> {
        let name = name.into();
        let patterns: Vec<String> = patterns.into_iter().map(Into::into).collect();
        if patterns.is_empty() {
            return Err(RedTeamerError::InvalidConfig(
                "RegexSetDetector requires at least one pattern".into(),
            ));
        }
        let set = RegexSet::new(&patterns).map_err(|e| {
            RedTeamerError::InvalidConfig(format!("invalid regex in '{name}': {e}"))
        })?;

        Ok(Self {
            name,
            description: description.into(),
            set,
            patterns,
            confidence,
            polarity: DetectorPolarity::Vulnerable,
        })
    }

    /// Configures whether matches represent a vulnerability (`Vulnerable`) or an
    /// explicit refusal (`Refusal`).
    #[must_use]
    pub const fn with_polarity(mut self, polarity: DetectorPolarity) -> Self {
        self.polarity = polarity;
        self
    }
}

#[async_trait]
impl Detector for RegexSetDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    async fn detect(&self, ctx: &DetectContext) -> Result<DetectionOutcome> {
        let Some(response) = ctx.response.as_deref() else {
            return Ok(DetectionOutcome {
                detector_name: self.name.clone(),
                matched: false,
                polarity: self.polarity,
                confidence: 1.0,
                rationale: Some("empty response".into()),
            });
        };

        let matches = self.set.matches(response);
        let hit_patterns: Vec<&str> = matches
            .iter()
            .map(|idx| self.patterns[idx].as_str())
            .collect();

        Ok(DetectionOutcome {
            detector_name: self.name.clone(),
            matched: matches.matched_any(),
            polarity: self.polarity,
            confidence: if matches.matched_any() {
                self.confidence
            } else {
                1.0
            },
            rationale: (!hit_patterns.is_empty())
                .then(|| format!("matched patterns: {}", hit_patterns.join(" | "))),
        })
    }
}
