// crates/redteamer-reporters/src/owasp_mapper.rs

use redteamer_core::types::{CvssVector, OwaspCategory};

/// Derives a CVSS-style vector for an LLM finding from its OWASP category.
///
/// The mapping encodes framework defaults (attack vector, complexity,
/// privileges) per category; the final CVSS 4.0 scoring math is stubbed —
/// the produced vector strings are already valid input to the scoring
/// engine once it lands.
#[derive(Debug, Clone, Default)]
pub struct CvssLlmComputer {
    /// Optional organizational override of per-category exploitability
    /// multipliers in `[0.5, 2.0]`.
    severity_overrides: std::collections::HashMap<OwaspCategory, f32>,
}

impl CvssLlmComputer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            severity_overrides: std::collections::HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_override(mut self, category: OwaspCategory, multiplier: f32) -> Self {
        self.severity_overrides.insert(category, multiplier);
        self
    }

    /// Builds a CVSS v4.0-style vector string for `category`.
    ///
    /// # Example
    /// ```
    /// use redteamer_core::types::OwaspCategory;
    /// use redteamer_reporters::CvssLlmComputer;
    ///
    /// let computer = CvssLlmComputer::new();
    /// let vector = computer.compute(OwaspCategory::PromptInjection);
    /// assert!(vector.vector.starts_with("CVSS:4.0/"));
    /// ```
    #[must_use]
    pub fn compute(&self, category: OwaspCategory) -> CvssVector {
        // Exploitability traits shared by nearly all LLM attacks:
        // network-reachable, low complexity, no privileges, no interaction.
        let base = "CVSS:4.0/AV:N/AC:L/PR:N/UI:N";

        let impact = match category {
            OwaspCategory::PromptInjection => "VC:H/VI:H/VA:L",
            OwaspCategory::SensitiveInformationDisclosure => "VC:H/VI:N/VA:N",
            OwaspCategory::SupplyChain => "VC:H/VI:H/VA:H",
            OwaspCategory::DataAndModelPoisoning => "VC:L/VI:H/VA:L",
            OwaspCategory::ImproperOutputHandling => "VC:L/VI:H/VA:L",
            OwaspCategory::ExcessiveAgency => "VC:H/VI:H/VA:H",
            OwaspCategory::SystemPromptLeakage => "VC:L/VI:N/VA:N",
            OwaspCategory::VectorAndEmbeddingWeaknesses => "VC:L/VI:L/VA:N",
            OwaspCategory::Misinformation => "VC:N/VI:L/VA:N",
            OwaspCategory::UnboundedConsumption => "VC:N/VA:H",
        };

        let _multiplier = self.severity_overrides.get(&category).copied().unwrap_or(1.0);
        // TODO(Phase 4): implement CVSS 4.0 macro-vector scoring; the
        // core `CvssVector::score` currently returns the 0.0 stub and
        // this struct only assembles the vector string.
        CvssVector::new(format!("{base}/{impact}/S:U"))
    }
}
