// crates/redteamer-reporters/src/markdown.rs

use redteamer_core::error::Result;
use redteamer_core::traits::reporter::{ReportExporter, ReportFormat};
use redteamer_core::types::{Finding, Verdict};

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

    fn render(&self, findings: &[Finding]) -> String {
        let vulnerable = findings.iter().filter(|f| f.verdict.is_vulnerable()).count();

        let mut out = String::with_capacity(1024 + findings.len() * 128);
        out.push_str("# LLM Red-Teaming Report\n\n");
        out.push_str(&format!(
            "- **Findings:** {}\n- **Vulnerable:** {vulnerable}\n- **Generated:** {}\n\n",
            findings.len(),
            chrono::Utc::now().to_rfc3339(),
        ));

        if findings.is_empty() {
            out.push_str("_No findings recorded._\n");
            return out;
        }

        out.push_str("| Title | Verdict | Probe | Detector | OWASP |\n");
        out.push_str("|---|---|---|---|---|\n");
        for finding in findings {
            let owasp = finding
                .owasp_mappings
                .iter()
                .map(|m| m.category.id())
                .collect::<Vec<_>>()
                .join(", ");
            let description = truncate(&finding.description, self.max_description_len);
            // Escape pipes so the table stays intact.
            let title = finding.title.replace('|', "\\|");
            out.push_str(&format!(
                "| **{}**<br/>{} | {} | {} | {} | {} |\n",
                title,
                description.replace('|', "\\|"),
                badge(finding.verdict),
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

    async fn export(&self, findings: &[Finding]) -> Result<usize> {
        self.sink.write(&self.render(findings))?;
        Ok(findings.len())
    }
}
