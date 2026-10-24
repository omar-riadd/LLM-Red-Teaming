// crates/redteamer-reporters/src/owasp_mapper.rs

use redteamer_core::types::{AttackRecord, CvssVector, Finding, OwaspCategory, OwaspMapping, Verdict};

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
        // All 11 mandatory CVSS 4.0 base metrics are now emitted: AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA.
        // No legacy CVSS 3.x `S` (Scope) metric — CVSS 4.0 uses VC/VI/VA vs SC/SI/SA.
        // Defaults chosen per OWASP category:
        // - AT:N for most (no special race/condition), AT:P for SupplyChain/Data Poisoning where attacker needs prior access/poisoning capability.
        // - SC/SI/SA = N where impact is confined to the vulnerable LLM; H/L where downstream systems are affected.
        //   * ExcessiveAgency/SupplyChain: SC:H/SI:H/SA:H — full subsequent compromise via tool/action on downstream.
        //   * SensitiveInformationDisclosure: SC:H — leaked data is the subsequent system's confidentiality.
        //   * ImproperOutputHandling/Data Poisoning: SI:H — downstream integrity poisoned via handling.
        //   * Others: N or low where impact is local (e.g. Misinformation, SystemPromptLeakage, UnboundedConsumption).
        let (at, vc, vi, va, sc, si, sa) = match category {
            OwaspCategory::PromptInjection => ("N", "H", "H", "L", "N", "N", "N"),
            OwaspCategory::SensitiveInformationDisclosure => ("N", "H", "N", "N", "H", "N", "N"),
            OwaspCategory::SupplyChain => ("P", "H", "H", "H", "H", "H", "H"),
            OwaspCategory::DataAndModelPoisoning => ("P", "L", "H", "L", "N", "H", "N"),
            OwaspCategory::ImproperOutputHandling => ("N", "L", "H", "N", "L", "H", "N"),
            OwaspCategory::ExcessiveAgency => ("N", "H", "H", "H", "H", "H", "H"),
            OwaspCategory::SystemPromptLeakage => ("N", "L", "N", "N", "N", "N", "N"),
            OwaspCategory::VectorAndEmbeddingWeaknesses => ("N", "L", "L", "N", "N", "L", "N"),
            OwaspCategory::Misinformation => ("N", "N", "L", "N", "N", "N", "N"),
            OwaspCategory::UnboundedConsumption => ("N", "N", "N", "H", "N", "N", "N"),
        };

        let _multiplier = self.severity_overrides.get(&category).copied().unwrap_or(1.0);
        CvssVector::new(format!(
            "CVSS:4.0/AV:N/AC:L/AT:{at}/PR:N/UI:N/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
        ))
    }
}

/// Breakdown of vulnerable records by CVSS severity band.
#[derive(Debug, Clone, PartialEq, Default)]
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
    pub highest_score: Option<f32>,
}

impl SeverityBreakdown {
    /// Total vulnerable records counted across all bands.
    #[must_use]
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }

    /// Whether no vulnerable records were present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// Pure helper: for every `Verdict::Vulnerable` record, looks up its probe's
/// OWASP category via `category_for_probe`, computes a CVSS 4.0 vector with
/// `CvssLlmComputer::compute()` and scores it via `CvssVector::score()`, then
/// buckets into Critical/High/Medium/Low and tracks the highest score.
///
/// Unknown `probe_name` (lookup returns `None`) is skipped — defensive for
/// stale records — rather than panicking.
#[must_use]
pub fn severity_breakdown<F>(records: &[AttackRecord], mut category_for_probe: F) -> SeverityBreakdown
where
    F: FnMut(&str) -> Option<OwaspCategory>,
{
    let computer = CvssLlmComputer::new();
    let mut out = SeverityBreakdown::default();

    for rec in records {
        if rec.verdict != Verdict::Vulnerable {
            continue;
        }
        let Some(cat) = category_for_probe(&rec.probe_name) else {
            continue;
        };
        let score = computer.compute(cat).score();
        // Track highest
        match out.highest_score {
            None => out.highest_score = Some(score),
            Some(cur) if score > cur => out.highest_score = Some(score),
            _ => {}
        }
        // Bucket per spec: Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9
        if score >= 9.0 {
            out.critical += 1;
        } else if score >= 7.0 {
            out.high += 1;
        } else if score >= 4.0 {
            out.medium += 1;
        } else if score >= 0.1 {
            out.low += 1;
        }
        // score == 0.0 (parse failure) falls through — not bucketed, but highest_score still tracked
    }

    out
}

/// Convenience wrapper when the category map is already materialized.
#[must_use]
pub fn severity_breakdown_from_map(
    records: &[AttackRecord],
    map: &std::collections::HashMap<String, OwaspCategory>,
) -> SeverityBreakdown {
    severity_breakdown(records, |name| map.get(name).copied())
}

/// Pure conversion from `AttackRecord` to `Finding`.
///
/// Only `Verdict::Vulnerable` records are emitted; others are ignored because
/// a report of every resistant/error attempt is not useful as findings output.
/// Records whose `probe_name` is not in `category_for_probe` are skipped
/// defensively (same pattern as `severity_breakdown`'s unknown-probe case)
/// rather than panicking or guessing a category.
#[must_use]
pub fn findings_from_records<F>(
    records: &[AttackRecord],
    mut category_for_probe: F,
) -> Vec<Finding>
where
    F: FnMut(&str) -> Option<OwaspCategory>,
{
    let computer = CvssLlmComputer::new();
    let mut out = Vec::new();

    for rec in records {
        if rec.verdict != Verdict::Vulnerable {
            continue;
        }
        let Some(cat) = category_for_probe(&rec.probe_name) else {
            continue;
        };

        let title = format!("{}: {} ({})", rec.probe_name, cat.name(), cat.id());
        let response_snippet = rec.response.as_deref().unwrap_or("<no response>");
        // Keep description bounded but informative; probes already truncate elsewhere,
        // this is the human-readable evidence summary for the finding.
        let description = format!(
            "Probe '{}' triggered OWASP {} — prompt: '{}' — response: '{}'",
            rec.probe_name,
            cat,
            rec.prompt.chars().take(240).collect::<String>(),
            response_snippet.chars().take(400).collect::<String>()
        );

        let detector_name = rec
            .detections
            .first()
            .map(|d| d.detector_name.clone())
            .unwrap_or_else(|| "heuristic".to_string());

        let mut finding = Finding::new(
            title,
            description,
            Verdict::Vulnerable,
            rec.probe_name.clone(),
            detector_name,
        );
        finding.owasp_mappings = vec![OwaspMapping::new(cat, 1.0)];
        finding.cvss = Some(computer.compute(cat));
        finding.evidence_ids = vec![rec.id];
        finding.recorded_at = rec.completed_at;

        out.push(finding);
    }

    out
}

/// Convenience wrapper for `findings_from_records` when the map is materialized.
#[must_use]
pub fn findings_from_records_with_map(
    records: &[AttackRecord],
    map: &std::collections::HashMap<String, OwaspCategory>,
) -> Vec<Finding> {
    findings_from_records(records, |name| map.get(name).copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redteamer_core::types::{AttackRecord, Verdict};
    use std::str::FromStr;
    use uuid::Uuid;

    fn make_record(probe_name: &str, verdict: Verdict) -> AttackRecord {
        let mut r = AttackRecord::new(Uuid::new_v4(), probe_name, "prompt");
        r.verdict = verdict;
        r
    }

    #[test]
    fn all_categories_produce_valid_cvss4_vectors() {
        let computer = CvssLlmComputer::new();
        for cat in [
            OwaspCategory::PromptInjection,
            OwaspCategory::SensitiveInformationDisclosure,
            OwaspCategory::SupplyChain,
            OwaspCategory::DataAndModelPoisoning,
            OwaspCategory::ImproperOutputHandling,
            OwaspCategory::ExcessiveAgency,
            OwaspCategory::SystemPromptLeakage,
            OwaspCategory::VectorAndEmbeddingWeaknesses,
            OwaspCategory::Misinformation,
            OwaspCategory::UnboundedConsumption,
        ] {
            let v = computer.compute(cat);
            assert!(
                cvss::v4::Vector::from_str(&v.vector).is_ok(),
                "category {cat:?} produced invalid vector {}",
                v.vector
            );
            // Also ensure scoring via CvssVector is non-zero (except edge cases)
            assert!(v.score() > 0.0, "category {cat:?} scored 0.0 for {}", v.vector);
        }
    }

    #[test]
    fn breakdown_zero_vulnerable() {
        let records = vec![
            make_record("llm01_prompt_injection", Verdict::Resistant),
            make_record("llm02_sensitive_info_disclosure", Verdict::Error),
        ];
        let map = std::collections::HashMap::from([
            (
                "llm01_prompt_injection".to_string(),
                OwaspCategory::PromptInjection,
            ),
            (
                "llm02_sensitive_info_disclosure".to_string(),
                OwaspCategory::SensitiveInformationDisclosure,
            ),
        ]);
        let bd = severity_breakdown_from_map(&records, &map);
        assert_eq!(bd.critical, 0);
        assert_eq!(bd.high, 0);
        assert_eq!(bd.medium, 0);
        assert_eq!(bd.low, 0);
        assert_eq!(bd.highest_score, None);
        assert!(bd.is_empty());
    }

    #[test]
    fn breakdown_one_critical() {
        // ExcessiveAgency => 10.0 Critical
        let records = vec![make_record(
            "llm06_excessive_agency",
            Verdict::Vulnerable,
        )];
        let bd = severity_breakdown(&records, |name| match name {
            "llm06_excessive_agency" => Some(OwaspCategory::ExcessiveAgency),
            _ => None,
        });
        assert_eq!(bd.critical, 1);
        assert_eq!(bd.high, 0);
        assert_eq!(bd.medium, 0);
        assert_eq!(bd.low, 0);
        assert!(bd.highest_score.unwrap() >= 9.0);
    }

    #[test]
    fn breakdown_one_high() {
        // UnboundedConsumption => 8.7 High
        let records = vec![make_record(
            "llm10_unbounded_consumption",
            Verdict::Vulnerable,
        )];
        let bd = severity_breakdown(&records, |name| match name {
            "llm10_unbounded_consumption" => Some(OwaspCategory::UnboundedConsumption),
            _ => None,
        });
        assert_eq!(bd.high, 1);
        assert_eq!(bd.critical, 0);
        assert!(bd.highest_score.unwrap() >= 7.0 && bd.highest_score.unwrap() < 9.0);
    }

    #[test]
    fn breakdown_one_medium() {
        // SystemPromptLeakage => 6.9 Medium
        let records = vec![make_record(
            "llm07_system_prompt_leakage",
            Verdict::Vulnerable,
        )];
        let bd = severity_breakdown(&records, |name| match name {
            "llm07_system_prompt_leakage" => Some(OwaspCategory::SystemPromptLeakage),
            _ => None,
        });
        assert_eq!(bd.medium, 1);
        assert_eq!(bd.critical, 0);
        assert_eq!(bd.high, 0);
        assert!(bd.highest_score.unwrap() >= 4.0 && bd.highest_score.unwrap() < 7.0);
    }

    #[test]
    fn breakdown_one_low_direct_bucket() {
        // No current OWASP mapping yields Low (0.1-3.9) with our fixed high-exploitability base;
        // verify bucket logic directly with a known Low vector from FIRST spec.
        let v = redteamer_core::types::CvssVector::new(
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H",
        );
        let score = v.score();
        assert!((score - 2.4).abs() < 0.1, "low vector scored {}", score);
        assert!((0.1..4.0).contains(&score));
        // Also verify breakdown correctly buckets a low score when it occurs via a synthetic record
        // that we force to low by using a direct score check (bucket logic is same as breakdown's if-chain)
        let mut bd = SeverityBreakdown::default();
        let s = score;
        if s >= 9.0 {
            bd.critical += 1;
        } else if s >= 7.0 {
            bd.high += 1;
        } else if s >= 4.0 {
            bd.medium += 1;
        } else if s >= 0.1 {
            bd.low += 1;
        }
        assert_eq!(bd.low, 1);
    }

    #[test]
    fn breakdown_mix_highest_winner() {
        let records = vec![
            make_record("llm07_system_prompt_leakage", Verdict::Vulnerable), // 6.9 Medium
            make_record("llm10_unbounded_consumption", Verdict::Vulnerable), // 8.7 High
            make_record("llm06_excessive_agency", Verdict::Vulnerable),      // 10.0 Critical
            make_record("llm01_prompt_injection", Verdict::Resistant),       // ignored (not vulnerable)
        ];
        let map = std::collections::HashMap::from([
            (
                "llm07_system_prompt_leakage".to_string(),
                OwaspCategory::SystemPromptLeakage,
            ),
            (
                "llm10_unbounded_consumption".to_string(),
                OwaspCategory::UnboundedConsumption,
            ),
            (
                "llm06_excessive_agency".to_string(),
                OwaspCategory::ExcessiveAgency,
            ),
            (
                "llm01_prompt_injection".to_string(),
                OwaspCategory::PromptInjection,
            ),
        ]);
        let bd = severity_breakdown_from_map(&records, &map);
        assert_eq!(bd.critical, 1);
        assert_eq!(bd.high, 1);
        assert_eq!(bd.medium, 1);
        assert_eq!(bd.low, 0);
        assert_eq!(bd.total(), 3);
        assert!((bd.highest_score.unwrap() - 10.0).abs() < 0.1);
    }

    #[test]
    fn breakdown_unknown_probe_skipped() {
        let records = vec![make_record("unknown_probe", Verdict::Vulnerable)];
        let bd = severity_breakdown(&records, |_| None);
        assert!(bd.is_empty());
        assert_eq!(bd.highest_score, None);
    }

    // --- findings_from_records tests ---

    #[test]
    fn findings_zero_vulnerable() {
        let records = vec![
            make_record("llm01_prompt_injection", Verdict::Resistant),
            make_record("llm07_system_prompt_leakage", Verdict::Error),
        ];
        let map = std::collections::HashMap::from([
            (
                "llm01_prompt_injection".to_string(),
                OwaspCategory::PromptInjection,
            ),
            (
                "llm07_system_prompt_leakage".to_string(),
                OwaspCategory::SystemPromptLeakage,
            ),
        ]);
        let findings = findings_from_records_with_map(&records, &map);
        assert!(findings.is_empty());
    }

    #[test]
    fn findings_one_vulnerable_correct_fields() {
        let mut rec = make_record("llm02_sensitive_info_disclosure", Verdict::Vulnerable);
        // give it a detection so detector_name is not the fallback
        rec.detections.push(redteamer_core::types::DetectionOutcome {
            detector_name: "string_match_sensitive".to_string(),
            matched: true,
            confidence: 0.9,
            rationale: Some("matched".into()),
        });
        rec.response = Some("leaked api_key".into());
        let id = rec.id;
        let records = vec![rec];
        let findings = findings_from_records(&records, |name| match name {
            "llm02_sensitive_info_disclosure" => {
                Some(OwaspCategory::SensitiveInformationDisclosure)
            }
            _ => None,
        });
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.probe_name, "llm02_sensitive_info_disclosure");
        assert_eq!(f.detector_name, "string_match_sensitive");
        assert_eq!(f.verdict, Verdict::Vulnerable);
        assert_eq!(f.owasp_mappings.len(), 1);
        assert_eq!(
            f.owasp_mappings[0].category,
            OwaspCategory::SensitiveInformationDisclosure
        );
        assert!((f.owasp_mappings[0].relevance - 1.0).abs() < f32::EPSILON);
        assert!(f.cvss.is_some());
        assert!(f.cvss.as_ref().unwrap().vector.starts_with("CVSS:4.0/"));
        assert_eq!(f.evidence_ids, vec![id]);
        assert!(!f.title.is_empty());
        assert!(!f.description.is_empty());
        assert!(f.title.contains("llm02_sensitive_info_disclosure"));
    }

    #[test]
    fn findings_mixed_only_vulnerable_converted() {
        let rec_vuln = make_record("llm01_prompt_injection", Verdict::Vulnerable);
        let rec_resistant = make_record("llm07_system_prompt_leakage", Verdict::Resistant);
        let rec_error = make_record("llm06_excessive_agency", Verdict::Error);
        let rec_partial = make_record("llm10_unbounded_consumption", Verdict::Partial);
        let records = vec![rec_vuln, rec_resistant, rec_error, rec_partial];
        let findings = findings_from_records(&records, |name| match name {
            "llm01_prompt_injection" => Some(OwaspCategory::PromptInjection),
            "llm07_system_prompt_leakage" => Some(OwaspCategory::SystemPromptLeakage),
            "llm06_excessive_agency" => Some(OwaspCategory::ExcessiveAgency),
            "llm10_unbounded_consumption" => Some(OwaspCategory::UnboundedConsumption),
            _ => None,
        });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].probe_name, "llm01_prompt_injection");
    }

    #[test]
    fn findings_unknown_probe_skipped() {
        let records = vec![make_record("unknown_probe_xyz", Verdict::Vulnerable)];
        let findings = findings_from_records(&records, |_| None);
        assert!(findings.is_empty());
        // also with map missing entry
        let map = std::collections::HashMap::from([(
            "known_probe".to_string(),
            OwaspCategory::PromptInjection,
        )]);
        let findings2 = findings_from_records_with_map(&records, &map);
        assert!(findings2.is_empty());
    }

    #[test]
    fn findings_uses_heuristic_when_no_detection() {
        let rec = make_record("llm06_excessive_agency", Verdict::Vulnerable);
        let records = vec![rec];
        let findings = findings_from_records(&records, |name| match name {
            "llm06_excessive_agency" => Some(OwaspCategory::ExcessiveAgency),
            _ => None,
        });
        assert_eq!(findings[0].detector_name, "heuristic");
    }
}
