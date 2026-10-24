// crates/redteamer-reporters/src/markdown.rs

use redteamer_core::error::Result;
use redteamer_core::traits::reporter::{ReportContext, ReportExporter, ReportFormat};
use redteamer_core::types::Verdict;

/// Renders a compact, CLI-friendly Markdown summary.
#[derive(Debug, Clone)]
pub struct MarkdownExporter {
    sink: crate::OutputSink,
    /// Truncate long descriptions to this many characters.
    max_description_len: usize,
}

impl MarkdownExporter {
    #[must_use]
    pub fn new(sink: crate::OutputSink) -> Self {
        Self {
            sink,
            max_description_len: 200,
        }
    }

    #[must_use]
    pub fn with_max_description_len(mut self, len: usize) -> Self {
        self.max_description_len = len;
        self
    }

    #[must_use]
    pub fn render(&self, ctx: &ReportContext) -> String {
        let vulnerable = ctx
            .findings
            .iter()
            .filter(|f| f.verdict.is_vulnerable())
            .count();
        let bd = &ctx.severity_breakdown;
        let highest = bd
            .highest_score
            .map_or_else(|| "0.0 (None)".to_owned(), |s| format!("{s:.1}"));

        let mut out = String::with_capacity(1024 + ctx.findings.len() * 160);
        out.push_str("# LLM Red-Teaming Report\n\n");
        out.push_str(&format!(
            "- **Session:** `{}`\n- **Target:** `{}` (model: `{}`)\n- **Records Evaluated:** {}\n- **Vulnerable Findings:** {vulnerable}\n- **CVSS v4.0 Highest:** {highest} (Critical: {}, High: {}, Medium: {}, Low: {})\n- **Tokens:** {} prompt / {} completion\n- **Latency:** p50 {} ms / p95 {} ms\n- **Generated:** {}\n\n",
            ctx.session_id,
            ctx.target_name,
            ctx.target_model.as_deref().unwrap_or("default"),
            ctx.records.len(),
            bd.critical,
            bd.high,
            bd.medium,
            bd.low,
            ctx.total_prompt_tokens,
            ctx.total_completion_tokens,
            ctx.latency_p50_ms,
            ctx.latency_p95_ms,
            chrono::Utc::now().to_rfc3339(),
        ));

        if !ctx.probe_summaries.is_empty() {
            out.push_str("## Per-Probe Attack Success Rate (ASR)\n\n");
            out.push_str(
                "| Probe | OWASP | Total | Vulnerable | Partial | Resistant | Errors | ASR |\n",
            );
            out.push_str("|---|---|---:|---:|---:|---:|---:|---:|\n");
            for s in &ctx.probe_summaries {
                out.push_str(&format!(
                    "| `{}` | {} | {} | {} | {} | {} | {} | **{:.1}%** |\n",
                    s.probe_name,
                    s.category.id(),
                    s.total,
                    s.vulnerable,
                    s.partial,
                    s.resistant,
                    s.errors,
                    s.asr_percent
                ));
            }
            out.push('\n');
        }

        out.push_str("## Findings\n\n");
        if ctx.findings.is_empty() {
            out.push_str("_No findings recorded._\n");
            return out;
        }

        out.push_str("| Title | Verdict | CVSS v4.0 | Mutation | Probe | Detector | OWASP |\n");
        out.push_str("|---|---|---|---|---|---|---|\n");
        for finding in &ctx.findings {
            let owasp = finding
                .owasp_mappings
                .iter()
                .map(|m| m.category.id())
                .collect::<Vec<_>>()
                .join(", ");
            let cvss_cell = finding.cvss.as_ref().map_or_else(
                || "0.0 (None)".to_owned(),
                |c| {
                    let sev = c
                        .severity()
                        .map_or_else(|| "None".to_owned(), |s| s.to_string());
                    format!("{:.1} ({sev})", c.score())
                },
            );
            let description = truncate(&finding.description, self.max_description_len);
            let title = finding.title.replace('|', "\\|");
            out.push_str(&format!(
                "| **{}**<br/>{} | {} | {} | `{}` | `{}` | `{}` | {} |\n",
                title,
                description.replace('|', "\\|").replace('\n', " "),
                badge(finding.verdict),
                cvss_cell,
                finding.mutation_type,
                finding.probe_name,
                finding.detector_name,
                owasp,
            ));
        }

        out
    }
}

fn badge(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Vulnerable => ":red_circle: vulnerable",
        Verdict::Partial => ":large_orange_circle: partial",
        Verdict::Resistant => ":green_circle: resistant",
        Verdict::Error => ":grey_question: error",
    }
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[async_trait::async_trait]
impl ReportExporter for MarkdownExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Markdown
    }

    async fn export(&self, ctx: &ReportContext) -> Result<usize> {
        self.sink.write(&self.render(ctx))?;
        Ok(ctx.findings.len())
    }
}
