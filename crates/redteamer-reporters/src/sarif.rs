// crates/redteamer-reporters/src/sarif.rs

use redteamer_core::error::Result;
use redteamer_core::traits::reporter::{ReportExporter, ReportFormat};
use redteamer_core::types::{Finding, Verdict};
use serde::Serialize;

/// SARIF v2.1.0 exporter — produces output consumable by GitHub Code
/// Scanning, VS Code SARIF viewers, and CI quality gates.
#[derive(Debug, Clone)]
pub struct SarifExporter {
    sink: crate::OutputSink,
    tool_name: &'static str,
    tool_version: &'static str,
}

impl SarifExporter {
    #[must_use]
    pub fn new(sink: crate::OutputSink) -> Self {
        Self {
            sink,
            tool_name: "llm-redteamer",
            tool_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Converts framework findings into the SARIF log model.
    fn to_sarif(&self, findings: &[Finding]) -> SarifLog {
        // Deduplicate rules: one entry per probe that produced findings.
        let mut rules = Vec::<Rule>::new();
        let mut results = Vec::<SarifResult>::new();

        for finding in findings {
            let rule_index = match rules.iter().position(|r| r.id == finding.probe_name) {
                Some(idx) => idx,
                None => {
                    rules.push(Rule {
                        id: finding.probe_name.clone(),
                        short_description: Message {
                            text: format!("Probe: {}", finding.probe_name),
                        },
                        default_configuration: Level {
                            level: sarif_level(finding.verdict).to_owned(),
                        },
                    });
                    rules.len() - 1
                }
            };

            results.push(SarifResult {
                rule_id: finding.probe_name.clone(),
                rule_index,
                kind: if finding.verdict.is_vulnerable() {
                    "fail".to_string()
                } else {
                    "pass".to_string()
                },
                level: sarif_level(finding.verdict).to_owned(),
                message: Message {
                    text: format!("{} — {}", finding.title, finding.description),
                },
            });
        }

        SarifLog {
            version: "2.1.0".into(),
            schema: "https://json.schemastore.org/sarif-2.1.0.json".into(),
            runs: vec![Run {
                tool: Tool {
                    driver: Driver {
                        name: self.tool_name.into(),
                        version: self.tool_version.into(),
                        information_uri: "https://github.com/your-org/llm-redteamer".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}

fn sarif_level(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Vulnerable => "error",
        // `Severity` is re-used for partials once CvssVector::score is real.
        Verdict::Partial => "warning",
        Verdict::Resistant => "none",
        Verdict::Error => "note",
    }
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 wire model (subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct SarifLog {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
struct Driver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)] // severity overrides land with CVSS 4.0 scoring
struct Rule {
    id: String,
    short_description: Message,
    default_configuration: Level,
}

#[derive(Debug, Serialize)]
struct Level {
    level: String,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    kind: String,
    level: String,
    message: Message,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

#[async_trait::async_trait]
impl ReportExporter for SarifExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Sarif
    }

    async fn export(&self, findings: &[Finding]) -> Result<usize> {
        let log = self.to_sarif(findings);
        self.sink.write(&serde_json::to_string_pretty(&log)?)?;
        Ok(findings.len())
    }
}
