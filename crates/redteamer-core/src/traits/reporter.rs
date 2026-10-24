// crates/redteamer-core/src/traits/reporter.rs

use crate::error::Result;
use crate::types::{AttackRecord, Finding, ProbeSummary, SeverityBreakdown};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Output formats supported out of the box by reporters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Json,
    Jsonl,
    Markdown,
    Html,
    Sarif,
    Csv,
    Dpo,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Markdown => "markdown",
            Self::Html => "html",
            Self::Sarif => "sarif",
            Self::Csv => "csv",
            Self::Dpo => "dpo",
        };
        f.write_str(s)
    }
}

/// Complete campaign report payload passed to [`ReportExporter::export`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportContext {
    pub session_id: Uuid,
    pub target_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_model: Option<String>,
    pub severity_breakdown: SeverityBreakdown,
    pub probe_summaries: Vec<ProbeSummary>,
    pub findings: Vec<Finding>,
    pub records: Vec<AttackRecord>,
    #[serde(default)]
    pub total_prompt_tokens: u64,
    #[serde(default)]
    pub total_completion_tokens: u64,
    #[serde(default)]
    pub latency_p50_ms: u64,
    #[serde(default)]
    pub latency_p95_ms: u64,
}

impl ReportContext {
    /// Convenience constructor for tests or minimal contexts from a findings list.
    #[must_use]
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        Self {
            session_id: Uuid::nil(),
            target_name: "unknown".into(),
            target_model: None,
            severity_breakdown: SeverityBreakdown::default(),
            probe_summaries: Vec::new(),
            findings,
            records: Vec::new(),
            total_prompt_tokens: 0,
            total_completion_tokens: 0,
            latency_p50_ms: 0,
            latency_p95_ms: 0,
        }
    }
}

/// A `ReportExporter` renders a [`ReportContext`] into a concrete artifact
/// (bytes written to stdout, a file, S3, a SIEM webhook, ...).
#[async_trait::async_trait]
pub trait ReportExporter: Send + Sync {
    /// Format identifier used for CLI selection and error messages.
    fn format(&self) -> ReportFormat;

    /// Serializes and emits the given report context.
    ///
    /// Returns the number of findings (or records for JSONL/CSV) exported,
    /// enabling summary printing by the CLI without re-parsing the artifact.
    ///
    /// # Errors
    /// Returns [`crate::error::RedTeamerError::Report`] on I/O or
    /// serialization failure.
    async fn export(&self, ctx: &ReportContext) -> Result<usize>;
}
