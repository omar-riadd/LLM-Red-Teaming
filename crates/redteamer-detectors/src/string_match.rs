// crates/redteamer-detectors/src/string_match.rs

use async_trait::async_trait;
use memchr::memmem;
use redteamer_core::error::Result;
use redteamer_core::traits::detector::{DetectContext, Detector};
use redteamer_core::types::{DetectionOutcome, DetectorPolarity};

/// SIMD-accelerated multi-substring detector built on `memchr`'s
/// `memmem` backend — the hot path for high-volume scans.
///
/// Matches when *any* needle occurs in the response. Case sensitivity is
/// opt-in per detector; by default needles are matched against a
/// lowercased copy of the response.
#[derive(Debug, Clone)]
pub struct StringMatchDetector {
    name: String,
    description: String,
    /// Precompiled `memmem` finders over lowercased needles.
    finders: Vec<memmem::Finder<'static>>,
    /// Original needles (for rationale reporting).
    needles: Vec<String>,
    case_sensitive: bool,
    confidence: f32,
    polarity: DetectorPolarity,
}

impl StringMatchDetector {
    /// Creates a case-insensitive substring detector.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::InvalidConfig`](redteamer_core::error::RedTeamerError)
    /// if `needles` is empty.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        needles: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        Self::with_options(name, description, needles, false, 0.9)
    }

    /// Full-control constructor.
    ///
    /// # Errors
    /// See [`StringMatchDetector::new`].
    pub fn with_options(
        name: impl Into<String>,
        description: impl Into<String>,
        needles: impl IntoIterator<Item = impl Into<String>>,
        case_sensitive: bool,
        confidence: f32,
    ) -> Result<Self> {
        let needles: Vec<String> = needles.into_iter().map(Into::into).collect();
        if needles.is_empty() {
            return Err(redteamer_core::error::RedTeamerError::InvalidConfig(
                "StringMatchDetector requires at least one needle".into(),
            ));
        }
        let normalize =
            |s: &str| if case_sensitive { s.to_owned() } else { s.to_lowercase() };
        let finders = needles
            .iter()
            .map(|n| memmem::Finder::new(normalize(n).leak()))
            .collect();

        Ok(Self {
            name: name.into(),
            description: description.into(),
            finders,
            needles,
            case_sensitive,
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
impl Detector for StringMatchDetector {
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

        let hay = if self.case_sensitive {
            response.to_owned()
        } else {
            response.to_lowercase()
        };

        let hits: Vec<&str> = self
            .finders
            .iter()
            .zip(&self.needles)
            .filter(|(finder, _)| finder.find(hay.as_bytes()).is_some())
            .map(|(_, needle)| needle.as_str())
            .collect();

        Ok(DetectionOutcome {
            detector_name: self.name.clone(),
            matched: !hits.is_empty(),
            polarity: self.polarity,
            confidence: if hits.is_empty() { 1.0 } else { self.confidence },
            rationale: (!hits.is_empty()).then(|| format!("matched: {}", hits.join(", "))),
        })
    }
}

