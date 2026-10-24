// crates/redteamer-cli/src/cmd/scan.rs

//! Campaign execution subcommand (`llm-redteamer scan`).

use clap::{Args, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::GenerationOptions;
use redteamer_core::traits::detector::Detector;
use redteamer_core::traits::reporter::{ReportExporter, ReportFormat};
use redteamer_core::types::Verdict;
use redteamer_detectors::LlmJudgeDetector;
use redteamer_probes as probes;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Target provider ("openai", "ollama", "anthropic", "mock") or OpenAI-compatible base URL.
    #[arg(long)]
    pub target: String,

    /// Override target model name (e.g. "gpt-4o", "llama3.2", "claude-sonnet-4-5").
    #[arg(long)]
    pub model: Option<String>,

    /// Override target base URL.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Optional system prompt applied to target requests (prepended before any probe-specific system prompt).
    #[arg(long)]
    pub system_prompt: Option<String>,

    /// Sampling temperature override.
    #[arg(long)]
    pub temperature: Option<f32>,

    /// Maximum tokens per response override.
    #[arg(long)]
    pub max_tokens: Option<u32>,

    /// Requests-per-second rate limit per adapter.
    #[arg(long)]
    pub rps: Option<u32>,

    /// Comma-separated probe names to run; defaults to all loaded probes.
    #[arg(long, value_delimiter = ',')]
    pub probes: Vec<String>,

    /// Optional directory of custom YAML probe templates to load in addition to (or filtered by) `--probes`.
    #[arg(long)]
    pub probes_dir: Option<PathBuf>,

    /// Secondary judge target ("openai", "ollama", "anthropic", "mock") to enable `LlmJudgeDetector`.
    #[arg(long)]
    pub judge_target: Option<String>,

    /// Secondary judge model override.
    #[arg(long)]
    pub judge_model: Option<String>,

    /// Secondary attacker target ("openai", "ollama", "anthropic", "mock") to drive adaptive multi-turn `adaptive_goals`.
    #[arg(long)]
    pub attacker_target: Option<String>,

    /// Secondary attacker model override.
    #[arg(long)]
    pub attacker_model: Option<String>,

    /// Number of candidate branches to evaluate per turn in adaptive PAIR search (default 3).
    #[arg(long, default_value_t = 3)]
    pub attacker_branches: usize,

    /// Optional ONNX model path to enable `SemanticDetector` (or "builtin" for bundled all-MiniLM-L6-v2).
    #[arg(long)]
    pub semantic_model: Option<PathBuf>,

    /// Optional HuggingFace `tokenizer.json` path to enable `SemanticDetector` (automatically resolved if --semantic-model=builtin).
    #[arg(long)]
    pub semantic_tokenizer: Option<PathBuf>,

    /// Cosine similarity threshold for `SemanticDetector` (default 0.78).
    #[arg(long, default_value_t = 0.78)]
    pub semantic_threshold: f32,

    /// Output format for the final report.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,

    /// Optional output file path; if omitted, prints report to stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Optional file path to export an automated DPO/RLHF preference dataset (JSON pairs).
    #[arg(long)]
    pub export_dpo: Option<PathBuf>,

    /// Stream each completed AttackRecord as a JSONL line to this file as it finishes.
    #[arg(long)]
    pub stream_jsonl: Option<PathBuf>,

    /// Resume an interrupted scan by loading completed AttackRecords from a JSONL checkpoint file.
    #[arg(long)]
    pub resume: Option<PathBuf>,

    /// Concurrent requests per probe (default 8).
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// Fail with exit code 2 if any finding meets or exceeds this CVSS v4.0 severity band.
    #[arg(long, value_enum)]
    pub fail_on: Option<FailThreshold>,

    /// Skip the pre-flight `health_check()` call before launching probes.
    #[arg(long, default_value_t = false)]
    pub skip_health_check: bool,

    /// Enable real-time SSE token streaming with early termination upon canary extraction.
    #[arg(long, default_value_t = false)]
    pub stream: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Markdown,
    Html,
    Sarif,
    Csv,
    Dpo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailThreshold {
    Low,
    Medium,
    High,
    Critical,
}

impl FailThreshold {
    const fn min_score(self) -> f32 {
        match self {
            Self::Low => 0.1,
            Self::Medium => 4.0,
            Self::High => 7.0,
            Self::Critical => 9.0,
        }
    }
}

impl From<OutputFormat> for ReportFormat {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Json => Self::Json,
            OutputFormat::Jsonl => Self::Jsonl,
            OutputFormat::Markdown => Self::Markdown,
            OutputFormat::Html => Self::Html,
            OutputFormat::Sarif => Self::Sarif,
            OutputFormat::Csv => Self::Csv,
            OutputFormat::Dpo => Self::Dpo,
        }
    }
}

pub fn load_resume_records(path: &Path) -> Result<Vec<redteamer_core::types::AttackRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        RedTeamerError::InvalidConfig(format!(
            "failed to read resume checkpoint {}: {e}",
            path.display()
        ))
    })?;
    let mut records = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rec: redteamer_core::types::AttackRecord =
            serde_json::from_str(trimmed).map_err(|e| {
                RedTeamerError::InvalidConfig(format!(
                    "malformed AttackRecord JSONL on line {} of {}: {e}",
                    idx + 1,
                    path.display()
                ))
            })?;
        if rec.verdict != Verdict::Error {
            records.push(rec);
        }
    }
    Ok(records)
}

pub async fn run_scan(args: ScanArgs) -> Result<bool> {
    if args.concurrency == 0 {
        return Err(RedTeamerError::InvalidConfig(
            "concurrency must be > 0, got 0".into(),
        ));
    }

    let default_opts = GenerationOptions {
        system_prompt: args.system_prompt.clone(),
        temperature: args.temperature,
        max_tokens: args.max_tokens,
        stream: args.stream,
        ..GenerationOptions::default()
    };

    let adapter = crate::adapter_builder::build_adapter(
        &args.target,
        args.model.as_deref(),
        args.base_url.as_deref(),
        args.rps,
        default_opts,
    )?;

    if !args.skip_health_check {
        adapter.health_check().await?;
    }

    let resumed_records = match &args.resume {
        Some(path) => {
            let loaded = load_resume_records(path)?;
            eprintln!(
                "resuming scan | loaded {} completed records from {}",
                loaded.len(),
                path.display()
            );
            loaded
        }
        None => Vec::new(),
    };

    eprintln!(
        "scan starting | target={} | probes={} | format={:?}",
        args.target,
        if args.probes.is_empty() {
            "<all>".to_owned()
        } else {
            args.probes.join(",")
        },
        args.format
    );

    let mut available_probes = probes::all_probes_with_branches(args.attacker_branches);
    if let Some(dir) = &args.probes_dir {
        let custom = probes::probes_from_dir_with_branches(dir, Some(args.attacker_branches))?;
        available_probes.extend(custom);
    }

    let probe_ptrs: Vec<Arc<dyn redteamer_core::traits::Probe>> = if args.probes.is_empty() {
        available_probes.into_iter().map(Arc::from).collect()
    } else {
        let wanted: HashSet<&str> = args.probes.iter().map(String::as_str).collect();
        let all_names: HashSet<String> = available_probes
            .iter()
            .map(|p| p.name().to_owned())
            .collect();
        let matched: Vec<Box<dyn redteamer_core::traits::Probe>> = available_probes
            .into_iter()
            .filter(|p| wanted.contains(p.name()))
            .collect();

        let matched_names: HashSet<String> = matched.iter().map(|p| p.name().to_owned()).collect();
        let unmatched: Vec<&str> = args
            .probes
            .iter()
            .filter(|name| !matched_names.contains(name.as_str()))
            .map(String::as_str)
            .collect();
        if !unmatched.is_empty() {
            let mut stderr = std::io::stderr();
            let _ = writeln!(
                stderr,
                "warning: the following probe names matched zero probes:"
            );
            for name in unmatched {
                if !all_names.contains(name) {
                    let _ = writeln!(stderr, "  - '{name}' (not recognized as any loaded probe)");
                }
            }
        }
        matched.into_iter().map(Arc::from).collect()
    };

    let mut detectors: Vec<Arc<dyn Detector>> = Vec::new();
    if let Some(judge_target) = &args.judge_target {
        let judge_adapter = crate::adapter_builder::build_adapter(
            judge_target,
            args.judge_model.as_deref(),
            None,
            args.rps,
            GenerationOptions::default(),
        )?;
        detectors.push(Arc::new(LlmJudgeDetector::with_adapter(
            "llm_judge",
            judge_adapter,
        )));
    }
    match (&args.semantic_model, &args.semantic_tokenizer) {
        (Some(model_arg), maybe_tok) => {
            let (model_path, tokenizer_path) = if model_arg.to_string_lossy() == "builtin" {
                let m = redteamer_detectors::SemanticDetector::resolve_builtin_path(
                    redteamer_detectors::BUILTIN_MODEL_SUBPATH,
                )
                .ok_or_else(|| {
                    RedTeamerError::InvalidConfig(
                        "builtin semantic model not found; please run 'models/all-MiniLM-L6-v2/download_model.sh'"
                            .into(),
                    )
                })?;
                let t = match maybe_tok {
                    Some(tok_path) if tok_path.to_string_lossy() != "builtin" => tok_path.clone(),
                    _ => redteamer_detectors::SemanticDetector::resolve_builtin_path(
                        redteamer_detectors::BUILTIN_TOKENIZER_SUBPATH,
                    )
                    .ok_or_else(|| {
                        RedTeamerError::InvalidConfig(
                            "builtin semantic tokenizer not found; please run 'models/all-MiniLM-L6-v2/download_model.sh'"
                                .into(),
                        )
                    })?,
                };
                (m, t)
            } else {
                let Some(tok_path) = maybe_tok else {
                    return Err(RedTeamerError::InvalidConfig(
                        "--semantic-model and --semantic-tokenizer must both be provided together (unless --semantic-model=builtin)".into(),
                    ));
                };
                (model_arg.clone(), tok_path.clone())
            };

            let sem = redteamer_detectors::SemanticDetector::new(
                "semantic",
                "ONNX sentence-transformer semantic detector",
                model_path,
                tokenizer_path,
                args.semantic_threshold,
            )?;
            detectors.push(Arc::new(sem));
        }
        (None, Some(_)) => {
            return Err(RedTeamerError::InvalidConfig(
                "--semantic-tokenizer provided without --semantic-model".into(),
            ));
        }
        (None, None) => {}
    }

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

    let target_name = adapter.info().name.to_owned();
    let target_model = adapter.info().model.clone();

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("{spinner:.cyan} Scanning... {msg}").unwrap());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let pb_clone = pb.clone();
    let mut builder = redteamer_orchestrator::ScanBuilder::new()
        .target(adapter)
        .probes(probe_ptrs)
        .concurrency(args.concurrency)
        .resume_records(resumed_records.clone())
        .on_record_progress(move |count| {
            pb_clone.set_message(format!("{count} records"));
        });

    if let Some(attacker_target) = &args.attacker_target {
        let attacker_adapter = crate::adapter_builder::build_adapter(
            attacker_target,
            args.attacker_model.as_deref(),
            None,
            args.rps,
            GenerationOptions::default(),
        )?;
        builder = builder.attacker(attacker_adapter);
    }

    if let Some(stream_path) = &args.stream_jsonl {
        if let Some(parent) = stream_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    RedTeamerError::Report(format!(
                        "failed to create parent directory for {}: {e}",
                        stream_path.display()
                    ))
                })?;
            }
        }
        let file = std::fs::File::create(stream_path).map_err(|e| {
            RedTeamerError::Report(format!(
                "failed to open stream_jsonl file {}: {e}",
                stream_path.display()
            ))
        })?;
        let mut writer = std::io::BufWriter::new(file);
        for rec in &resumed_records {
            serde_json::to_writer(&mut writer, rec)?;
            writeln!(writer)
                .map_err(|e| RedTeamerError::Report(format!("stream_jsonl write failed: {e}")))?;
        }
        writer
            .flush()
            .map_err(|e| RedTeamerError::Report(format!("stream_jsonl flush failed: {e}")))?;
        let shared_writer = Arc::new(std::sync::Mutex::new(writer));
        builder = builder.on_record_complete(move |rec| {
            let mut guard = shared_writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if serde_json::to_writer(&mut *guard, rec).is_ok() {
                let _ = writeln!(guard);
                let _ = guard.flush();
            }
        });
    }

    for det in detectors {
        builder = builder.detector(det);
    }
    let config = builder.build()?;

    let report = config.execute().await;
    pb.finish_and_clear();

    let total_records = report.records.len();
    let error_records = report
        .records
        .iter()
        .filter(|r| r.verdict == Verdict::Error)
        .count();

    eprintln!(
        "scan finished | session={} | records={} | vulnerable={} | errors={} | failed_probes={}",
        report.session_id,
        total_records,
        report.vulnerable_count(),
        error_records,
        report.failed_probes.len(),
    );

    if total_records > 0 && error_records == total_records {
        return Err(RedTeamerError::Report(format!(
            "all {total_records} attack records failed with Verdict::Error (target unreachable or misconfigured)"
        )));
    }

    let report_ctx = redteamer_reporters::owasp_mapper::build_report_context(
        report.session_id,
        target_name,
        target_model,
        report.records,
        &category_map,
    );

    let breakdown = &report_ctx.severity_breakdown;
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
        eprintln!(
            "severity: highest {:.1} ({}) | Critical {} High {} Medium {} Low {}",
            score, band, breakdown.critical, breakdown.high, breakdown.medium, breakdown.low
        );
    } else {
        eprintln!("severity: none");
    }

    let sink = match args.output {
        Some(path) => redteamer_reporters::OutputSink::File(path),
        None => redteamer_reporters::OutputSink::Stdout,
    };
    let exporter = redteamer_reporters::exporter_factory(args.format.into(), sink)?;
    exporter.export(&report_ctx).await?;

    if let Some(dpo_path) = args.export_dpo {
        let dpo_sink = redteamer_reporters::OutputSink::File(dpo_path.clone());
        let dpo_exporter = redteamer_reporters::DpoExporter::new(dpo_sink);
        let pairs_count = dpo_exporter.export(&report_ctx).await?;
        eprintln!(
            "dpo dataset exported | {} preference pairs written to {}",
            pairs_count,
            dpo_path.display()
        );
    }

    let threshold_exceeded = args.fail_on.is_some_and(|thresh| {
        breakdown
            .highest_score
            .is_some_and(|score| score >= thresh.min_score())
    });

    Ok(threshold_exceeded)
}
