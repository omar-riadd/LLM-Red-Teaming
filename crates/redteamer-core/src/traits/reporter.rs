// crates/redteamer-core/src/traits/reporter.rs

use crate::error::Result;
use crate::types::Finding;
use std::fmt;

/// Output formats supported out of the box by reporters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    Json,
    Markdown,
    Html,
    Sarif,
    Csv,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Html => "html",
            Self::Sarif => "sarif",
            Self::Csv => "csv",
        };
        f.write_str(s)
    }
}

/// A `ReportExporter` renders aggregated findings into a concrete artifact
/// (bytes written to stdout, a file, S3, a SIEM webhook, ...).
#[async_trait::async_trait]
pub trait ReportExporter: Send + Sync {
    /// Format identifier used for CLI selection and error messages.
    fn format(&self) -> ReportFormat;

    /// Serializes and emits the given findings.
    ///
    /// Returns the number of findings exported, enabling summary printing
    /// by the CLI without re-parsing the artifact.
    ///
    /// # Errors
    /// Returns [`crate::error::RedTeamerError::Report`] on I/O or
    /// serialization failure.
    async fn export(&self, findings: &[Finding]) -> Result<usize>;
}
