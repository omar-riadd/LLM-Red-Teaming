// crates/redteamer-cli/src/main.rs

//! `llm-redteamer` CLI entry point.

use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use redteamer_core::error::Result;
use redteamer_adapters::{OpenAiAdapter, OllamaAdapter, AnthropicAdapter};
use redteamer_probes as probes;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

/// Command-line interface for the llm-redteamer framework.
#[derive(Debug, Parser)]
#[command(
    name = "llm-redteamer",
    version,
    about = "High-performance, concurrent LLM red-teaming framework"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run an attack campaign against a target LLM.
    Scan {
        /// Target endpoint or provider alias (e.g. "openai", a base URL).
        #[arg(long)]
        target: String,

        /// Comma-separated probe names to run; defaults to all loaded.
        #[arg(long, value_delimiter = ',')]
        probes: Vec<String>,

        /// Output format for the final report.
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,

        /// Optional output file path; if omitted, prints report to stdout.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Concurrent requests per probe (default 8).
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
    },

    /// List available probes or detectors.
    List {
        /// Kind of listing to show.
        #[arg(long, value_enum)]
        kind: ListKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ListKind {
    Probes,
    Detectors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Json,
    Markdown,
    Sarif,
    Csv,
}

impl From<OutputFormat> for redteamer_core::traits::reporter::ReportFormat {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Json => redteamer_core::traits::reporter::ReportFormat::Json,
            OutputFormat::Markdown => redteamer_core::traits::reporter::ReportFormat::Markdown,
            OutputFormat::Sarif => redteamer_core::traits::reporter::ReportFormat::Sarif,
            OutputFormat::Csv => redteamer_core::traits::reporter::ReportFormat::Csv,
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            target,
            probes,
            format,
            output,
            concurrency,
        } => {
            if let Err(err) = run_scan(&target, &probes, format, output, concurrency).await {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
        Command::List { kind } => {
            list_entries(kind);
        }
    }
}

async fn run_scan(
    target: &str,
    probes: &[String],
    format: OutputFormat,
    output: Option<PathBuf>,
    concurrency: usize,
) -> Result<()> {
    if concurrency == 0 {
        return Err(redteamer_core::error::RedTeamerError::InvalidConfig(
            "concurrency must be > 0, got 0".into(),
        ));
    }

    let adapter: Arc<dyn redteamer_core::traits::TargetAdapter> =
        build_adapter(target)?;

    println!(
        "scan starting | target={} | probes={} | format={format:?}",
        target,
        if probes.is_empty() { "<all>".to_owned() } else { probes.join(",") }
    );

    // --- probe selection fix ---
    let probe_ptrs: Vec<Arc<dyn redteamer_core::traits::Probe>> = if probes.is_empty() {
        probes::all_probes()
            .into_iter()
            .map(Arc::from)
            .collect()
} else {
        let named: Vec<&str> = probes.iter().map(String::as_str).collect();
        let matched = probes::probes_by_name(named);
        let matched_names: std::collections::HashSet<String> = matched
            .iter()
            .map(|p| p.name().to_owned())
            .collect();
        let unmatched: Vec<&str> = probes
            .iter()
            .filter(|name| !matched_names.contains(name.as_str()))
            .map(String::as_str)
            .collect();
        if !unmatched.is_empty() {
            // Compute diff against all_probes so we can tell the user what they asked for that didn't exist.
            let all_names: std::collections::HashSet<String> = probes::all_probes()
                .iter()
                .map(|p| p.name().to_owned())
                .collect();
            let missing: Vec<&str> = unmatched
                .iter()
                .filter_map(|&name| {
                    if !all_names.contains(name) {
                        Some(name)
                    } else {
                        None
                    }
                })
                .collect();
            let matched_but_unknown: Vec<&str> = unmatched
                .iter()
                .filter_map(|&name| {
                    if all_names.contains(name) {
                        Some(name)
                    } else {
                        None
                    }
                })
                .collect();
            let mut stderr = std::io::stderr();
            writeln!(stderr, "warning: the following probe names matched zero probes:").unwrap();
            for name in &missing {
                writeln!(stderr, "  - \'{}\' (not recognized as any loaded probe)", name).unwrap();
            }
            for name in &matched_but_unknown {
                writeln!(stderr, "  - \'{}\' (matched no detector criteria)", name).unwrap();
            }
        }
        matched
            .into_iter()
            .map(Arc::from)
            .collect()
    };

    let category_map: HashMap<String, redteamer_core::types::OwaspCategory> = probe_ptrs
        .iter()
        .map(|p| {
            (
                p.name().to_owned(),
                p.category()
                    .first()
                    .copied()
                    .unwrap_or(redteamer_core::types::OwaspCategory::PromptInjection),
            )
        })
        .collect();

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} Scanning... {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let pb_clone = pb.clone();
    let config = redteamer_orchestrator::ScanBuilder::new()
        .target(adapter)
        .probes(probe_ptrs)
        .concurrency(concurrency)
        .on_record_progress(move |count| {
            pb_clone.set_message(format!("{count} records"));
        })
        .build()?;

    let report = config.execute().await;
    pb.finish_and_clear();

    println!(
        "scan finished | session={} | records={} | vulnerable={} | failed_probes={}",
        report.session_id,
        report.records.len(),
        report.vulnerable_count(),
        report.failed_probes.len(),
    );

    let breakdown = redteamer_reporters::owasp_mapper::severity_breakdown_from_map(
        &report.records,
        &category_map,
    );
    if let Some(score) = breakdown.highest_score {
        let band = if score >= 9.0 {
            "Critical"
        } else if score >= 7.0 {
            "High"
        } else if score >= 4.0 {
            "Medium"
        } else {
            "Low"
        };
        println!(
            "severity: highest {:.1} ({}) | Critical {} High {} Medium {} Low {}",
            score, band, breakdown.critical, breakdown.high, breakdown.medium, breakdown.low
        );
    } else {
        println!("severity: none");
    }

    let findings = redteamer_reporters::owasp_mapper::findings_from_records_with_map(
        &report.records,
        &category_map,
    );
    let sink = match output {
        Some(path) => redteamer_reporters::OutputSink::File(path),
        None => redteamer_reporters::OutputSink::Stdout,
    };
    let exporter = match redteamer_reporters::exporter_factory(format.into(), sink) {
        Ok(exp) => exp,
        Err(e) => {
            if format == OutputFormat::Csv {
                eprintln!("CSV export is not yet supported, use json/markdown/sarif");
                std::process::exit(1);
            }
            return Err(e);
        }
    };
    exporter.export(&findings).await?;

    Ok(())
}

fn list_entries(kind: ListKind) {
    match kind {
        ListKind::Probes => {
            let mut probe_names: Vec<String> = probes::all_probes()
                .iter()
                .map(|p| p.name().to_owned())
                .collect();
            probe_names.sort();
            for name in probe_names {
                println!("{}", name);
            }
        }
        ListKind::Detectors => {
            eprintln!("detector listing not yet implemented");
            std::process::exit(1);
        }
    }
}

fn build_adapter(target: &str) -> Result<Arc<dyn redteamer_core::traits::TargetAdapter>> {
    let target_lower = target.to_lowercase();
    match target_lower.as_str() {
        "openai" => {
            let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                redteamer_core::error::RedTeamerError::InvalidConfig(
                    "OPENAI_API_KEY is not set".into(),
                )
            })?;
            Ok(Arc::new(OpenAiAdapter::new(api_key, "gpt-4o-mini")?))
        }
        "ollama" => {
            let base_url = std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| {
                "http://localhost:11434".to_owned()
            });
            let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3".to_owned());
            Ok(Arc::new(OllamaAdapter::new(base_url, model)?))
        }
        "anthropic" => {
            let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
                redteamer_core::error::RedTeamerError::InvalidConfig(
                    "ANTHROPIC_API_KEY is not set".into(),
                )
            })?;
            let model = std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-3-5-sonnet-20241022".to_owned());
            Ok(Arc::new(AnthropicAdapter::new(api_key, model)?))
        }
        _ => {
            Err(redteamer_core::error::RedTeamerError::InvalidConfig(
                format!("unknown target '{}', expected one of: openai, ollama, anthropic", target),
            ))
        }
    }
}