// crates/redteamer-reporters/src/lib.rs

//! Multi-format report exporters for `llm-redteamer`.
//!
//! Every exporter implements [`ReportExporter`] from `redteamer-core` and
//! writes to a configurable [`OutputSink`]. The [`exporter_factory`] builds
//! the right exporter from CLI-level configuration.

pub mod html;
pub mod markdown;
pub mod owasp_mapper;
pub mod sarif;

use redteamer_core::error::RedTeamerError;
use redteamer_core::error::Result;
use redteamer_core::traits::reporter::{ReportExporter, ReportFormat};
use std::path::PathBuf;

pub use html::HtmlExporter;
pub use markdown::MarkdownExporter;
pub use owasp_mapper::CvssLlmComputer;
pub use sarif::SarifExporter;

/// Where an exporter writes its artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSink {
    /// Human-facing default: print to stdout.
    Stdout,
    /// Write to a file path.
    File(PathBuf),
}

impl OutputSink {
    /// Emits rendered bytes to this sink.
    ///
    /// # Errors
    /// File I/O failures surface as [`RedTeamerError::Report`].
    pub(crate) fn write(&self, contents: &str) -> Result<()> {
        match self {
            Self::Stdout => {
                use std::io::Write;
                let mut out = std::io::stdout().lock();
                out.write_all(contents.as_bytes())
                    .and_then(|()| out.write_all(b"\n"))
                    .map_err(|e| RedTeamerError::Report(format!("stdout write failed: {e}")))
            }
            Self::File(path) => std::fs::write(path, contents)
                .map_err(|e| RedTeamerError::Report(format!("write to {} failed: {e}", path.display()))),
        }
    }
}

/// Builds the exporter matching `format`.
///
/// # Errors
/// Returns [`RedTeamerError::Unsupported`] for formats that have no
/// exporter yet (currently `Csv`).
pub fn exporter_factory(format: ReportFormat, sink: OutputSink) -> Result<Box<dyn ReportExporter>> {
    match format {
        ReportFormat::Json => Ok(Box::new(JsonExporter { sink })),
        ReportFormat::Markdown => Ok(Box::new(MarkdownExporter::new(sink))),
        ReportFormat::Html => HtmlExporter::new(sink).map(|e| Box::new(e) as Box<dyn ReportExporter>),
        ReportFormat::Sarif => Ok(Box::new(SarifExporter::new(sink))),
        ReportFormat::Csv => Err(RedTeamerError::Unsupported(
            "CSV export is planned for a later phase".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// JSON exporter (trivial serde round-trip; kept here so every format has one home)
// ---------------------------------------------------------------------------

struct JsonExporter {
    sink: OutputSink,
}

#[async_trait::async_trait]
impl ReportExporter for JsonExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Json
    }

    async fn export(&self, findings: &[redteamer_core::types::Finding]) -> Result<usize> {
        self.sink.write(&serde_json::to_string_pretty(findings)?)?;
        Ok(findings.len())
    }
}
