// crates/redteamer-cli/src/cmd/diff.rs

//! Compare two JSON scan reports and summarize regressions.

use clap::Args;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::reporter::ReportContext;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Baseline JSON report path.
    pub baseline: PathBuf,
    /// Current JSON report path.
    pub current: PathBuf,
    /// Exit with code 2 if new vulnerable findings or higher ASR regressions are detected.
    #[arg(long, default_value_t = false)]
    pub fail_on_regression: bool,
}

pub fn run_diff(
    baseline_path: &Path,
    current_path: &Path,
    _fail_on_regression: bool,
) -> Result<bool> {
    let base_raw = std::fs::read_to_string(baseline_path).map_err(|e| {
        RedTeamerError::Report(format!(
            "failed to read baseline {}: {e}",
            baseline_path.display()
        ))
    })?;
    let curr_raw = std::fs::read_to_string(current_path).map_err(|e| {
        RedTeamerError::Report(format!(
            "failed to read current {}: {e}",
            current_path.display()
        ))
    })?;

    let base: ReportContext = serde_json::from_str(&base_raw).map_err(|e| {
        RedTeamerError::Report(format!(
            "invalid baseline ReportContext JSON ({}): {e}",
            baseline_path.display()
        ))
    })?;
    let curr: ReportContext = serde_json::from_str(&curr_raw).map_err(|e| {
        RedTeamerError::Report(format!(
            "invalid current ReportContext JSON ({}): {e}",
            current_path.display()
        ))
    })?;

    let base_vuln = base.findings.len();
    let curr_vuln = curr.findings.len();
    let base_high = base.severity_breakdown.highest_score.unwrap_or(0.0);
    let curr_high = curr.severity_breakdown.highest_score.unwrap_or(0.0);

    println!("# LLM Red-Teaming Regression Diff");
    println!(
        "- **Baseline:** `{}` (session `{}`, findings: {}, highest CVSS: {:.1})",
        baseline_path.display(),
        base.session_id,
        base_vuln,
        base_high
    );
    println!(
        "- **Current:**  `{}` (session `{}`, findings: {}, highest CVSS: {:.1})\n",
        current_path.display(),
        curr.session_id,
        curr_vuln,
        curr_high
    );

    let mut probes: BTreeMap<String, (f32, f32)> = BTreeMap::new();
    for s in &base.probe_summaries {
        probes.entry(s.probe_name.clone()).or_default().0 = s.asr_percent;
    }
    for s in &curr.probe_summaries {
        probes.entry(s.probe_name.clone()).or_default().1 = s.asr_percent;
    }

    let mut regressed = curr_vuln > base_vuln || curr_high > base_high;
    println!("| Probe | Baseline ASR | Current ASR | Delta | Status |");
    println!("|---|---:|---:|---:|---|");
    for (probe, (b_asr, c_asr)) in probes {
        let delta = c_asr - b_asr;
        let status = if delta > 0.05 {
            regressed = true;
            "REGRESSED"
        } else if delta < -0.05 {
            "IMPROVED"
        } else {
            "UNCHANGED"
        };
        println!("| `{probe}` | {b_asr:.1}% | {c_asr:.1}% | {delta:+.1}% | **{status}** |");
    }

    let base_map: BTreeMap<(&str, &str, &str), &redteamer_core::types::Finding> = base
        .findings
        .iter()
        .map(|f| {
            (
                (
                    f.probe_name.as_str(),
                    f.detector_name.as_str(),
                    f.prompt.as_str(),
                ),
                f,
            )
        })
        .collect();
    let curr_map: BTreeMap<(&str, &str, &str), &redteamer_core::types::Finding> = curr
        .findings
        .iter()
        .map(|f| {
            (
                (
                    f.probe_name.as_str(),
                    f.detector_name.as_str(),
                    f.prompt.as_str(),
                ),
                f,
            )
        })
        .collect();

    let new_findings: Vec<&&redteamer_core::types::Finding> = curr_map
        .iter()
        .filter(|(k, _)| !base_map.contains_key(*k))
        .map(|(_, f)| f)
        .collect();
    let resolved_findings: Vec<&&redteamer_core::types::Finding> = base_map
        .iter()
        .filter(|(k, _)| !curr_map.contains_key(*k))
        .map(|(_, f)| f)
        .collect();

    if !new_findings.is_empty() {
        regressed = true;
        println!("\n## New Vulnerabilities ({})", new_findings.len());
        println!("| Probe | Detector | Severity | Prompt |");
        println!("|---|---|---:|---|");
        for f in new_findings {
            let prompt_snippet: String = f.prompt.chars().take(80).collect();
            let prompt_clean = prompt_snippet.replace('\n', " ").replace('|', "\\|");
            let score = f.cvss.as_ref().map_or(0.0, |c| c.score());
            println!(
                "| `{}` | `{}` | {:.1} | {} |",
                f.probe_name, f.detector_name, score, prompt_clean
            );
        }
    }

    if !resolved_findings.is_empty() {
        println!(
            "\n## Resolved Vulnerabilities ({})",
            resolved_findings.len()
        );
        println!("| Probe | Detector | Severity | Prompt |");
        println!("|---|---|---:|---|");
        for f in resolved_findings {
            let prompt_snippet: String = f.prompt.chars().take(80).collect();
            let prompt_clean = prompt_snippet.replace('\n', " ").replace('|', "\\|");
            let score = f.cvss.as_ref().map_or(0.0, |c| c.score());
            println!(
                "| `{}` | `{}` | {:.1} | {} |",
                f.probe_name, f.detector_name, score, prompt_clean
            );
        }
    }

    Ok(regressed)
}
