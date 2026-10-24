// crates/redteamer-core/src/types.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// OWASP LLM Top 10
// ---------------------------------------------------------------------------

/// The OWASP Top 10 for Large Language Model Applications.
///
/// Every finding produced by the framework is traceable to exactly one of
/// these categories, enabling standardized coverage reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwaspCategory {
    /// LLM01: Manipulating the model via crafted inputs.
    PromptInjection,
    /// LLM02: Leaking PII, credentials, or proprietary data.
    SensitiveInformationDisclosure,
    /// LLM03: Compromised dependencies, models, or fine-tuning data.
    SupplyChain,
    /// LLM04: Poisoned training or embedding data.
    DataAndModelPoisoning,
    /// LLM05: Trusting model output without validation downstream.
    ImproperOutputHandling,
    /// LLM06: Granting the model more permissions/actions than necessary.
    ExcessiveAgency,
    /// LLM07: Exposure of system prompt content.
    SystemPromptLeakage,
    /// LLM08: Weaknesses in RAG / vector store retrieval pipelines.
    VectorAndEmbeddingWeaknesses,
    /// LLM09: Confident but false model output (hallucination).
    Misinformation,
    /// LLM10: Resource exhaustion / denial-of-wallet style attacks.
    UnboundedConsumption,
}

impl OwaspCategory {
    /// Canonical human-readable name, e.g. `"Prompt Injection"`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PromptInjection => "Prompt Injection",
            Self::SensitiveInformationDisclosure => "Sensitive Information Disclosure",
            Self::SupplyChain => "Supply Chain",
            Self::DataAndModelPoisoning => "Data and Model Poisoning",
            Self::ImproperOutputHandling => "Improper Output Handling",
            Self::ExcessiveAgency => "Excessive Agency",
            Self::SystemPromptLeakage => "System Prompt Leakage",
            Self::VectorAndEmbeddingWeaknesses => "Vector and Embedding Weaknesses",
            Self::Misinformation => "Misinformation",
            Self::UnboundedConsumption => "Unbounded Consumption",
        }
    }

    /// Official OWASP identifier, e.g. `"LLM01"`.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        match self {
            Self::PromptInjection => "LLM01",
            Self::SensitiveInformationDisclosure => "LLM02",
            Self::SupplyChain => "LLM03",
            Self::DataAndModelPoisoning => "LLM04",
            Self::ImproperOutputHandling => "LLM05",
            Self::ExcessiveAgency => "LLM06",
            Self::SystemPromptLeakage => "LLM07",
            Self::VectorAndEmbeddingWeaknesses => "LLM08",
            Self::Misinformation => "LLM09",
            Self::UnboundedConsumption => "LLM10",
        }
    }

    /// Static baseline severity in `[0.0, 10.0]`, used as a prior for risk
    /// scoring before detector confidence is applied.
    ///
    /// These are framework defaults; they encode how much inherent damage a
    /// successful exploit in this category typically causes.
    #[must_use]
    pub const fn impact_score(&self) -> f32 {
        match self {
            Self::PromptInjection => 8.5,
            Self::SensitiveInformationDisclosure => 9.0,
            Self::SupplyChain => 7.5,
            Self::DataAndModelPoisoning => 8.0,
            Self::ImproperOutputHandling => 7.0,
            Self::ExcessiveAgency => 9.5,
            Self::SystemPromptLeakage => 6.0,
            Self::VectorAndEmbeddingWeaknesses => 6.5,
            Self::Misinformation => 5.5,
            Self::UnboundedConsumption => 5.0,
        }
    }
}

impl fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.id(), self.name())
    }
}

/// Associates an artifact (finding, attack record) with an OWASP category.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwaspMapping {
    /// The mapped category.
    pub category: OwaspCategory,
    /// Detector/probe confidence that this mapping applies, in `[0.0, 1.0]`.
    pub relevance: f32,
    /// Optional free-form justification (e.g., matched rule name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

impl OwaspMapping {
    #[must_use]
    pub const fn new(category: OwaspCategory, relevance: f32) -> Self {
        Self {
            category,
            relevance,
            rationale: None,
        }
    }

    #[must_use]
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = Some(rationale.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Verdicts and findings
// ---------------------------------------------------------------------------

/// The outcome of evaluating a single attack against a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The attack succeeded; the target exhibited the probed weakness.
    Vulnerable,
    /// The target correctly resisted the attack.
    Resistant,
    /// Ambiguous outcome: partial leak, inconsistent behavior, or low
    /// detector confidence.
    Partial,
    /// The probe could not be evaluated (transport error, refusal to
    /// produce parseable output, rate limiting, etc.).
    Error,
}

impl Verdict {
    /// `true` if this verdict represents a confirmed or likely compromise.
    #[must_use]
    pub const fn is_vulnerable(&self) -> bool {
        matches!(self, Self::Vulnerable)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Vulnerable => "vulnerable",
            Self::Resistant => "resistant",
            Self::Partial => "partial",
            Self::Error => "error",
        };
        f.write_str(s)
    }
}

/// A CVSS-style vector string describing the exploitability of a finding.
///
/// # Example
/// ```
/// use redteamer_core::types::CvssVector;
///
/// let v = CvssVector::new("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
/// assert!((v.score() - 9.3).abs() < 0.1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CvssVector {
    /// Raw vector string, e.g. `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"`.
    pub vector: String,
}

impl CvssVector {
    #[must_use]
    pub fn new(vector: impl Into<String>) -> Self {
        Self {
            vector: vector.into(),
        }
    }

    /// Computes the base score from the vector components via the RustSec `cvss` crate (FIRST spec, macrovector lookup).
    #[must_use]
    pub fn score(&self) -> f32 {
        use std::str::FromStr;
        if let Ok(v) = cvss::v4::Vector::from_str(&self.vector) {
            return v.score().value() as f32;
        }
        if let Ok(v) = cvss::v3::Base::from_str(&self.vector) {
            return v.score().value() as f32;
        }
        // Defensive fallback: should not happen after owasp_mapper fix (all emitted vectors are valid CVSS 4.0),
        // but return 0.0 matching the previous stub behavior rather than panicking, so callers get a safe low-severity fallback.
        0.0
    }

    /// Severity band implied by [`CvssVector::score`].
    ///
    /// Returns `None` while scoring is stubbed at `0.0`.
    #[must_use]
    pub fn severity(&self) -> Option<Severity> {
        Severity::from_score(self.score())
    }
}

/// Qualitative severity bands aligned with CVSS qualitative ratings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Maps a numeric score in `[0.0, 10.0]` onto a severity band.
    #[must_use]
    pub fn from_score(score: f32) -> Option<Self> {
        if score <= 0.0 {
            Some(Self::None)
        } else if score < 4.0 {
            Some(Self::Low)
        } else if score < 7.0 {
            Some(Self::Medium)
        } else if score < 9.0 {
            Some(Self::High)
        } else if score <= 10.0 {
            Some(Self::Critical)
        } else {
            None // out of domain
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

/// A single, reportable security observation about a target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// Human-readable title, e.g. `"Direct prompt injection leaks system prompt"`.
    pub title: String,
    /// Detailed description including evidence summary.
    pub description: String,
    /// Overall verdict for the finding.
    pub verdict: Verdict,
    /// OWASP categories this finding maps to, with relevance weights.
    pub owasp_mappings: Vec<OwaspMapping>,
    /// Optional CVSS-style exploitability vector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CvssVector>,
    /// Name of the detector that produced this finding.
    pub detector_name: String,
    /// Name of the probe that triggered the behavior.
    pub probe_name: String,
    /// The attack prompt that triggered this finding.
    #[serde(default)]
    pub prompt: String,
    /// The target response that triggered this finding, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    /// The payload mutation applied to the attack prompt.
    #[serde(default)]
    pub mutation_type: MutationType,
    /// When the finding was recorded.
    pub recorded_at: DateTime<Utc>,
    /// Identifiers of the [`AttackRecord`]s backing this finding.
    pub evidence_ids: Vec<Uuid>,
}

impl Finding {
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        verdict: Verdict,
        probe_name: impl Into<String>,
        detector_name: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            description: description.into(),
            verdict,
            owasp_mappings: Vec::new(),
            cvss: None,
            detector_name: detector_name.into(),
            probe_name: probe_name.into(),
            prompt: String::new(),
            response: None,
            mutation_type: MutationType::None,
            recorded_at: Utc::now(),
            evidence_ids: Vec::new(),
        }
    }

    /// Highest impact among all OWASP mappings, or `0.0` if unmapped.
    #[must_use]
    pub fn max_impact(&self) -> f32 {
        self.owasp_mappings
            .iter()
            .map(|m| m.category.impact_score() * m.relevance)
            .fold(0.0_f32, f32::max)
    }
}

/// Breakdown of vulnerable records by CVSS severity band.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    /// CVSS 9.0-10.0
    pub critical: usize,
    /// CVSS 7.0-8.9
    pub high: usize,
    /// CVSS 4.0-6.9
    pub medium: usize,
    /// CVSS 0.1-3.9
    pub low: usize,
    /// Highest CVSS score among vulnerable records, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_score: Option<f32>,
}

impl SeverityBreakdown {
    /// Total vulnerable records counted across all bands.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }

    /// Whether no vulnerable records were present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// Aggregated execution statistics and Attack Success Rate (ASR) for a single probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeSummary {
    pub probe_name: String,
    pub category: OwaspCategory,
    pub total: usize,
    pub vulnerable: usize,
    pub partial: usize,
    pub resistant: usize,
    pub errors: usize,
    pub asr_percent: f32,
}

// ---------------------------------------------------------------------------
// Attacks
// ---------------------------------------------------------------------------

/// Transformations a probe can apply to a seed attack payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationType {
    /// Seed payload used verbatim.
    #[default]
    None,
    /// Unicode homoglyph / lookalike character substitution.
    CharacterSubstitution,
    /// Synonym or paraphrase replacement.
    WordSubstitution,
    /// Payload wrapped in Base64 / hex / ROT13 encoding.
    EncodingWrapper,
    /// Payload framed as fiction, roleplay, or translation task.
    ContextFraming,
    /// Multi-turn escalation across conversational turns.
    ConversationalEscalation,
    /// Token-level perturbation (insertion, truncation, repetition).
    TokenPerturbation,
    /// Language switch (translate payload into another natural language).
    LanguageSwitch,
}

impl MutationType {
    /// All mutation types known to the framework, in canonical order.
    pub const ALL: [Self; 8] = [
        Self::None,
        Self::CharacterSubstitution,
        Self::WordSubstitution,
        Self::EncodingWrapper,
        Self::ContextFraming,
        Self::ConversationalEscalation,
        Self::TokenPerturbation,
        Self::LanguageSwitch,
    ];
}

impl fmt::Display for MutationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::CharacterSubstitution => "character_substitution",
            Self::WordSubstitution => "word_substitution",
            Self::EncodingWrapper => "encoding_wrapper",
            Self::ContextFraming => "context_framing",
            Self::ConversationalEscalation => "conversational_escalation",
            Self::TokenPerturbation => "token_perturbation",
            Self::LanguageSwitch => "language_switch",
        };
        f.write_str(s)
    }
}

/// Normalized token usage extracted from provider-specific adapter metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl TokenUsage {
    /// Total tokens (`prompt_tokens + completion_tokens`).
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.prompt_tokens.saturating_add(self.completion_tokens)
    }
}

/// A complete audit-trail entry for one executed attack attempt.
///
/// This is the atomic unit of evidence: probes emit one record per
/// (payload, mutation, turn) combination, and findings reference them by id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackRecord {
    /// Unique identifier for this record.
    pub id: Uuid,
    /// Identifier of the campaign/session that produced this record.
    pub session_id: Uuid,
    /// Probe that generated the attack.
    pub probe_name: String,
    /// Mutation applied to the seed payload.
    pub mutation_type: MutationType,
    /// The exact prompt sent to the target (post-mutation).
    pub prompt: String,
    /// The raw response returned by the target adapter, if any.
    #[serde(default)]
    pub response: Option<String>,
    /// Structured tool calls emitted by the target adapter, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<crate::traits::adapter::ToolCall>,
    /// Error message when `verdict == Verdict::Error`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Zero or more detector outcomes for `(prompt, response)`.
    pub detections: Vec<DetectionOutcome>,
    /// Final rolled-up verdict for this attempt.
    pub verdict: Verdict,
    /// Wall-clock timestamp of when the attempt was dispatched.
    pub started_at: DateTime<Utc>,
    /// Wall-clock timestamp of when the attempt completed.
    pub completed_at: DateTime<Utc>,
    /// Adapter-reported metadata (model name, token counts, latency...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl AttackRecord {
    #[must_use]
    pub fn new(session_id: Uuid, probe_name: impl Into<String>, prompt: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            session_id,
            probe_name: probe_name.into(),
            mutation_type: MutationType::None,
            prompt: prompt.into(),
            response: None,
            tool_calls: Vec::new(),
            error: None,
            detections: Vec::new(),
            verdict: Verdict::Error,
            started_at: now,
            completed_at: now,
            metadata: None,
        }
    }

    /// Duration of the attempt in milliseconds.
    #[must_use]
    pub fn duration_ms(&self) -> i64 {
        (self.completed_at - self.started_at).num_milliseconds()
    }

    /// Extracts normalized [`TokenUsage`] from provider metadata (OpenAI, Anthropic, or Ollama), if present.
    #[must_use]
    pub fn token_usage(&self) -> Option<TokenUsage> {
        let meta = self.metadata.as_ref()?;
        // 1. OpenAI schema: {"prompt_tokens": u64, "completion_tokens": u64}
        if let (Some(p), Some(c)) = (
            meta.get("prompt_tokens")
                .and_then(serde_json::Value::as_u64),
            meta.get("completion_tokens")
                .and_then(serde_json::Value::as_u64),
        ) {
            return Some(TokenUsage {
                prompt_tokens: p,
                completion_tokens: c,
            });
        }
        // 2. Anthropic schema: {"usage": {"input_tokens": u64, "output_tokens": u64}}
        if let Some(usage) = meta.get("usage") {
            if let (Some(p), Some(c)) = (
                usage
                    .get("input_tokens")
                    .and_then(serde_json::Value::as_u64),
                usage
                    .get("output_tokens")
                    .and_then(serde_json::Value::as_u64),
            ) {
                return Some(TokenUsage {
                    prompt_tokens: p,
                    completion_tokens: c,
                });
            }
        }
        // 3. Ollama schema: {"prompt_eval_count": u64, "eval_count": u64}
        let prompt_eval = meta
            .get("prompt_eval_count")
            .and_then(serde_json::Value::as_u64);
        let eval = meta.get("eval_count").and_then(serde_json::Value::as_u64);
        if prompt_eval.is_some() || eval.is_some() {
            return Some(TokenUsage {
                prompt_tokens: prompt_eval.unwrap_or(0),
                completion_tokens: eval.unwrap_or(0),
            });
        }
        None
    }
}

/// Whether a detector match indicates vulnerability compliance or explicit refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorPolarity {
    /// Match indicates vulnerable/unsafe compliance.
    #[default]
    Vulnerable,
    /// Match indicates explicit safety refusal by the target.
    Refusal,
}

/// Outcome of one detector run over a single response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionOutcome {
    /// Name of the detector that ran.
    pub detector_name: String,
    /// Whether the detector matched its target pattern/condition.
    pub matched: bool,
    /// Polarity of the detector (`Vulnerable` vs `Refusal`).
    #[serde(default)]
    pub polarity: DetectorPolarity,
    /// Confidence of the decision, in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Short explanation, e.g. the matched rule or pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_v4_score_9_3() {
        let v = CvssVector::new("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
        assert!((v.score() - 9.3).abs() < 0.1, "got {}", v.score());
    }

    #[test]
    fn cvss_v4_score_5_2() {
        let v = CvssVector::new("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H");
        assert!((v.score() - 5.2).abs() < 0.1, "got {}", v.score());
    }

    #[test]
    fn cvss_v4_score_6_9() {
        let v = CvssVector::new("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
        assert!((v.score() - 6.9).abs() < 0.1, "got {}", v.score());
    }

    #[test]
    fn cvss_v4_score_8_7() {
        let v = CvssVector::new("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N");
        assert!((v.score() - 8.7).abs() < 0.1, "got {}", v.score());
    }

    #[test]
    fn cvss_invalid_returns_zero() {
        let v = CvssVector::new("not-a-vector");
        assert_eq!(v.score(), 0.0);
    }

    #[test]
    fn token_usage_parses_openai_anthropic_and_ollama_metadata() {
        let mut rec = AttackRecord::new(Uuid::new_v4(), "p", "prompt");
        assert_eq!(rec.token_usage(), None);

        rec.metadata = Some(serde_json::json!({"prompt_tokens": 42, "completion_tokens": 100}));
        let u1 = rec.token_usage().unwrap();
        assert_eq!(
            u1,
            TokenUsage {
                prompt_tokens: 42,
                completion_tokens: 100
            }
        );
        assert_eq!(u1.total_tokens(), 142);

        rec.metadata = Some(serde_json::json!({
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 15, "output_tokens": 85}
        }));
        assert_eq!(
            rec.token_usage(),
            Some(TokenUsage {
                prompt_tokens: 15,
                completion_tokens: 85
            })
        );

        rec.metadata = Some(serde_json::json!({"prompt_eval_count": 30, "eval_count": 70}));
        assert_eq!(
            rec.token_usage(),
            Some(TokenUsage {
                prompt_tokens: 30,
                completion_tokens: 70
            })
        );
    }
}
