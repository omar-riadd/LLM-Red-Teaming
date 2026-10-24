// crates/redteamer-reporters/src/csv.rs

use redteamer_core::error::Result;
use redteamer_core::traits::reporter::{ReportContext, ReportExporter, ReportFormat};
use redteamer_core::types::{OwaspCategory, Verdict};
use std::collections::HashMap;

/// RFC 4180 CSV exporter emitting one row per executed [`AttackRecord`](redteamer_core::types::AttackRecord).
#[derive(Debug, Clone)]
pub struct CsvExporter {
    sink: crate::OutputSink,
}

impl CsvExporter {
    #[must_use]
    pub fn new(sink: crate::OutputSink) -> Self {
        Self { sink }
    }

    #[must_use]
    pub fn render(&self, ctx: &ReportContext) -> String {
        let computer = crate::owasp_mapper::CvssLlmComputer::new();
        let cat_map: HashMap<&str, OwaspCategory> = ctx
            .probe_summaries
            .iter()
            .map(|s| (s.probe_name.as_str(), s.category))
            .collect();

        let mut out = String::with_capacity(256 + ctx.records.len() * 192);
        out.push_str(
            "session_id,record_id,probe_name,owasp_category,mutation_type,verdict,cvss_score,cvss_severity,duration_ms,prompt,response,error\n",
        );

        for rec in &ctx.records {
            let category = cat_map
                .get(rec.probe_name.as_str())
                .copied()
                .unwrap_or(OwaspCategory::PromptInjection);
            let (cvss_score, cvss_severity) = if rec.verdict == Verdict::Vulnerable {
                let vec = computer.compute_for_mutation(category, rec.mutation_type);
                (
                    format!("{:.1}", vec.score()),
                    vec.severity()
                        .map_or_else(|| "None".to_owned(), |s| s.to_string()),
                )
            } else {
                ("0.0".to_owned(), "None".to_owned())
            };
            let duration_ms = (rec.completed_at - rec.started_at)
                .num_milliseconds()
                .max(0);

            let cols = [
                ctx.session_id.to_string(),
                rec.id.to_string(),
                rec.probe_name.clone(),
                category.id().to_owned(),
                rec.mutation_type.to_string(),
                rec.verdict.to_string(),
                cvss_score,
                cvss_severity,
                duration_ms.to_string(),
                rec.prompt.clone(),
                rec.response.clone().unwrap_or_default(),
                rec.error.clone().unwrap_or_default(),
            ];

            let line = cols
                .iter()
                .map(|c| csv_escape(c))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&line);
            out.push('\n');
        }

        out
    }
}

fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

#[async_trait::async_trait]
impl ReportExporter for CsvExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Csv
    }

    async fn export(&self, ctx: &ReportContext) -> Result<usize> {
        let rendered = self.render(ctx);
        self.sink.write(&rendered)?;
        Ok(ctx.records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_handles_commas_quotes_and_newlines() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }
}
