// crates/redteamer-reporters/src/html.rs

use handlebars::Handlebars;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::reporter::{ReportExporter, ReportFormat};
use redteamer_core::types::Finding;
use serde_json::json;
use uuid::Uuid;

const TEMPLATE_NAME: &str = "report";
const TEMPLATE_SOURCE: &str = include_str!("templates/report.html.hbs");

/// Renders findings into a standalone HTML document via Handlebars.
#[derive(Debug)]
pub struct HtmlExporter {
    registry: Handlebars<'static>,
    sink: crate::OutputSink,
}

impl HtmlExporter {
    /// Creates an exporter with the embedded default template registered.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Report`] if the embedded template fails
    /// to compile (a build-time programming error surfaced at runtime).
    pub fn new(sink: crate::OutputSink) -> Result<Self> {
        let mut registry = Handlebars::new();
        registry
            .register_template_string(TEMPLATE_NAME, TEMPLATE_SOURCE)
            .map_err(|e| RedTeamerError::Report(format!("html template error: {e}")))?;
        Ok(Self { registry, sink })
    }

    fn render_payload(&self, findings: &[Finding], session_id: Uuid) -> serde_json::Value {
        json!({
            "session_id": session_id.to_string(),
            "generated_at": chrono::Utc::now().to_rfc2822(),
            "summary": {
                "total": findings.len(),
                "vulnerable_count": findings.iter()
                    .filter(|f| f.verdict.is_vulnerable())
                    .count(),
            },
            "findings": findings.iter().map(|f| json!({
                "title": f.title,
                "verdict": f.verdict.to_string(),
                "probe_name": f.probe_name,
                "detector_name": f.detector_name,
                "owasp_summary": f.owasp_mappings.iter()
                    .map(|m| m.category.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            })).collect::<Vec<_>>(),
        })
    }
}

#[async_trait::async_trait]
impl ReportExporter for HtmlExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Html
    }

    async fn export(&self, findings: &[Finding]) -> Result<usize> {
        // TODO(Week 4): thread the real scan session id through the
        // ReportExporter signature instead of synthesizing nil here.
        let payload = self.render_payload(findings, Uuid::nil());
        let rendered = self
            .registry
            .render(TEMPLATE_NAME, &payload)
            .map_err(|e| RedTeamerError::Report(format!("html render error: {e}")))?;
        self.sink.write(&rendered)?;
        Ok(findings.len())
    }
}
