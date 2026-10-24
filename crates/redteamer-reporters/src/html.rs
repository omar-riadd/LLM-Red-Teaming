// crates/redteamer-reporters/src/html.rs

use handlebars::Handlebars;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::reporter::{ReportContext, ReportExporter, ReportFormat};
use serde_json::json;

const TEMPLATE_NAME: &str = "report";
const TEMPLATE_SOURCE: &str = include_str!("templates/report.html.hbs");

/// Renders a standalone HTML report via Handlebars.
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

    fn render_payload(&self, ctx: &ReportContext) -> serde_json::Value {
        let total_findings = ctx.findings.len();
        let circumference = 251.3274_f64; // 2 * PI * 40
        let mut donut_segments = Vec::new();

        if total_findings == 0 {
            donut_segments.push(json!({
                "label": "Resistant",
                "color": "#10b981",
                "count": 0,
                "dasharray": format!("{circumference:.2} 0"),
                "dashoffset": 0.0,
            }));
        } else {
            let n = total_findings as f64;
            let mut offset = 0.0_f64;
            let categories = [
                ("Critical", "#dc2626", ctx.severity_breakdown.critical),
                ("High", "#ea580c", ctx.severity_breakdown.high),
                ("Medium", "#d97706", ctx.severity_breakdown.medium),
                ("Low", "#2563eb", ctx.severity_breakdown.low),
            ];

            for (label, color, count) in categories {
                if count > 0 {
                    let len = (count as f64 / n) * circumference;
                    donut_segments.push(json!({
                        "label": label,
                        "color": color,
                        "count": count,
                        "dasharray": format!("{:.2} {:.2}", len, circumference - len),
                        "dashoffset": -offset,
                    }));
                    offset += len;
                }
            }
        }

        json!({
            "session_id": ctx.session_id.to_string(),
            "target_name": ctx.target_name,
            "target_model": ctx.target_model.as_deref().unwrap_or("default"),
            "generated_at": chrono::Utc::now().to_rfc2822(),
            "donut_segments": donut_segments,
            "summary": {
                "total_records": ctx.records.len(),
                "total_findings": ctx.findings.len(),
                "critical": ctx.severity_breakdown.critical,
                "high": ctx.severity_breakdown.high,
                "medium": ctx.severity_breakdown.medium,
                "low": ctx.severity_breakdown.low,
                "highest_score": ctx.severity_breakdown.highest_score.map_or_else(|| "0.0".into(), |s| format!("{s:.1}")),
                "total_prompt_tokens": ctx.total_prompt_tokens,
                "total_completion_tokens": ctx.total_completion_tokens,
                "latency_p50_ms": ctx.latency_p50_ms,
                "latency_p95_ms": ctx.latency_p95_ms,
            },
            "probe_summaries": ctx.probe_summaries.iter().map(|s| json!({
                "probe_name": s.probe_name,
                "category": s.category.to_string(),
                "total": s.total,
                "vulnerable": s.vulnerable,
                "partial": s.partial,
                "resistant": s.resistant,
                "errors": s.errors,
                "asr_percent": format!("{:.1}%", s.asr_percent),
            })).collect::<Vec<_>>(),
            "findings": ctx.findings.iter().map(|f| {
                let (cvss_score, cvss_band, cvss_vec) = f.cvss.as_ref().map_or_else(
                    || ("0.0".to_owned(), "None".to_owned(), String::new()),
                    |c| {
                        (
                            format!("{:.1}", c.score()),
                            c.severity().map_or_else(|| "None".to_owned(), |s| s.to_string()),
                            c.vector.clone(),
                        )
                    },
                );
                json!({
                    "title": f.title,
                    "verdict": f.verdict.to_string(),
                    "probe_name": f.probe_name,
                    "detector_name": f.detector_name,
                    "mutation_type": f.mutation_type.to_string(),
                    "cvss_score": cvss_score,
                    "cvss_band": cvss_band,
                    "cvss_vector": cvss_vec,
                    "prompt": f.prompt,
                    "response": f.response.as_deref().unwrap_or(""),
                    "owasp_summary": f.owasp_mappings.iter()
                        .map(|m| m.category.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

#[async_trait::async_trait]
impl ReportExporter for HtmlExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Html
    }

    async fn export(&self, ctx: &ReportContext) -> Result<usize> {
        let payload = self.render_payload(ctx);
        let rendered = self
            .registry
            .render(TEMPLATE_NAME, &payload)
            .map_err(|e| RedTeamerError::Report(format!("html render error: {e}")))?;
        self.sink.write(&rendered)?;
        Ok(ctx.findings.len())
    }
}
