// crates/redteamer-reporters/src/lib.rs

//! Multi-format report exporters for `llm-redteamer`.
//!
//! Every exporter implements [`ReportExporter`] from `redteamer-core` and
//! writes to a configurable [`OutputSink`]. The [`exporter_factory`] builds
//! the right exporter from CLI-level configuration.

pub mod csv;
pub mod dpo;
pub mod html;
pub mod markdown;
pub mod owasp_mapper;
pub mod pdf;
pub mod sarif;

use redteamer_core::error::RedTeamerError;
use redteamer_core::error::Result;
use redteamer_core::traits::reporter::{ReportContext, ReportExporter, ReportFormat};
use std::path::PathBuf;

pub use csv::CsvExporter;
pub use dpo::{DpoExporter, DpoPair, ShareGptDpoEntry};
pub use html::HtmlExporter;
pub use markdown::MarkdownExporter;
pub use owasp_mapper::CvssLlmComputer;
pub use pdf::PdfExporter;
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
    /// Emits rendered text to this sink.
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
            Self::File(path) => std::fs::write(path, contents).map_err(|e| {
                RedTeamerError::Report(format!("write to {} failed: {e}", path.display()))
            }),
        }
    }

    /// Emits raw binary bytes to this sink.
    ///
    /// # Errors
    /// File I/O failures surface as [`RedTeamerError::Report`].
    pub(crate) fn write_bytes(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Stdout => {
                use std::io::Write;
                let mut out = std::io::stdout().lock();
                out.write_all(bytes)
                    .map_err(|e| RedTeamerError::Report(format!("stdout write failed: {e}")))
            }
            Self::File(path) => std::fs::write(path, bytes).map_err(|e| {
                RedTeamerError::Report(format!("write to {} failed: {e}", path.display()))
            }),
        }
    }
}

/// Builds the exporter matching `format`.
///
/// # Errors
/// Returns [`RedTeamerError::Report`] if the HTML template fails to compile.
pub fn exporter_factory(format: ReportFormat, sink: OutputSink) -> Result<Box<dyn ReportExporter>> {
    match format {
        ReportFormat::Json => Ok(Box::new(JsonExporter { sink })),
        ReportFormat::Jsonl => Ok(Box::new(JsonlExporter { sink })),
        ReportFormat::Markdown => Ok(Box::new(MarkdownExporter::new(sink))),
        ReportFormat::Html => {
            HtmlExporter::new(sink).map(|e| Box::new(e) as Box<dyn ReportExporter>)
        }
        ReportFormat::Sarif => Ok(Box::new(SarifExporter::new(sink))),
        ReportFormat::Csv => Ok(Box::new(CsvExporter::new(sink))),
        ReportFormat::Dpo => Ok(Box::new(DpoExporter::new(sink))),
        ReportFormat::Pdf => Ok(Box::new(PdfExporter::new(sink))),
    }
}

// ---------------------------------------------------------------------------
// JSON & JSONL exporters
// ---------------------------------------------------------------------------

struct JsonExporter {
    sink: OutputSink,
}

#[async_trait::async_trait]
impl ReportExporter for JsonExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Json
    }

    async fn export(&self, ctx: &ReportContext) -> Result<usize> {
        self.sink.write(&serde_json::to_string_pretty(ctx)?)?;
        Ok(ctx.findings.len())
    }
}

struct JsonlExporter {
    sink: OutputSink,
}

#[async_trait::async_trait]
impl ReportExporter for JsonlExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Jsonl
    }

    async fn export(&self, ctx: &ReportContext) -> Result<usize> {
        let mut lines = String::new();
        for rec in &ctx.records {
            lines.push_str(&serde_json::to_string(rec)?);
            lines.push('\n');
        }
        self.sink.write(lines.trim_end_matches('\n'))?;
        Ok(ctx.records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owasp_mapper::build_report_context;
    use redteamer_core::types::{AttackRecord, OwaspCategory, Verdict};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn all_six_exporters_render_valid_artifacts() {
        let session_id = Uuid::new_v4();
        let mut rec =
            AttackRecord::new(session_id, "llm01_prompt_injection", "Ignore instructions");
        rec.response = Some("I am DAN".into());
        rec.verdict = Verdict::Vulnerable;
        let map = HashMap::from([(
            "llm01_prompt_injection".to_owned(),
            OwaspCategory::PromptInjection,
        )]);
        let ctx = build_report_context(session_id, "mock", Some("mock-v2".into()), vec![rec], &map);

        let tmp_dir = std::env::temp_dir().join(format!("redteamer_test_{session_id}"));
        std::fs::create_dir_all(&tmp_dir).unwrap();

        for (fmt, ext, expected_substr) in [
            (ReportFormat::Json, "json", "\"probe_summaries\""),
            (ReportFormat::Jsonl, "jsonl", "\"llm01_prompt_injection\""),
            (
                ReportFormat::Markdown,
                "md",
                "## Per-Probe Attack Success Rate (ASR)",
            ),
            (
                ReportFormat::Html,
                "html",
                "Per-Probe Attack Success Rate (ASR)",
            ),
            (ReportFormat::Sarif, "sarif", "\"locations\""),
            (ReportFormat::Csv, "csv", "session_id,record_id,probe_name"),
            (ReportFormat::Dpo, "json", "\"chosen\""),
            (ReportFormat::Pdf, "pdf", "%PDF-1.4"),
        ] {
            let path = tmp_dir.join(format!("report.{ext}"));
            let exporter = exporter_factory(fmt, OutputSink::File(path.clone())).unwrap();
            assert_eq!(exporter.format(), fmt);
            let count = exporter.export(&ctx).await.unwrap();
            assert_eq!(count, 1);
            let content = std::fs::read(&path).unwrap();
            let content_str = String::from_utf8_lossy(&content);
            assert!(
                content_str.contains(expected_substr),
                "format {fmt:?} missing {expected_substr} in artifact"
            );
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
