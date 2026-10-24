// crates/redteamer-cli/src/main.rs

//! `llm-redteamer` CLI entry point.

use async_trait::async_trait;
use clap::{Args, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use redteamer_adapters::{AnthropicAdapter, OllamaAdapter, OpenAiAdapter};
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, TargetAdapter,
};
use redteamer_core::traits::detector::Detector;
use redteamer_core::traits::reporter::{ReportContext, ReportFormat};
use redteamer_core::types::Verdict;
use redteamer_detectors::LlmJudgeDetector;
use redteamer_probes as probes;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
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
    Scan(Box<ScanArgs>),

    /// List available probes or detectors.
    List {
        /// Kind of listing to show.
        #[arg(long, value_enum)]
        kind: ListKind,
    },

    /// Compare two JSON scan reports (`ReportContext`) and summarize regressions.
    Diff {
        /// Baseline JSON report path.
        baseline: PathBuf,
        /// Current JSON report path.
        current: PathBuf,
        /// Exit with code 2 if new vulnerable findings or higher ASR regressions are detected.
        #[arg(long, default_value_t = false)]
        fail_on_regression: bool,
    },
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Target provider ("openai", "ollama", "anthropic", "mock") or OpenAI-compatible base URL.
    #[arg(long)]
    target: String,

    /// Override target model name (e.g. "gpt-4o", "llama3.2", "claude-sonnet-4-5").
    #[arg(long)]
    model: Option<String>,

    /// Override target base URL.
    #[arg(long)]
    base_url: Option<String>,

    /// Optional system prompt applied to target requests (prepended before any probe-specific system prompt).
    #[arg(long)]
    system_prompt: Option<String>,

    /// Sampling temperature override.
    #[arg(long)]
    temperature: Option<f32>,

    /// Maximum tokens per response override.
    #[arg(long)]
    max_tokens: Option<u32>,

    /// Requests-per-second rate limit per adapter.
    #[arg(long)]
    rps: Option<u32>,

    /// Comma-separated probe names to run; defaults to all loaded probes.
    #[arg(long, value_delimiter = ',')]
    probes: Vec<String>,

    /// Optional directory of custom YAML probe templates to load in addition to (or filtered by) `--probes`.
    #[arg(long)]
    probes_dir: Option<PathBuf>,

    /// Secondary judge target ("openai", "ollama", "anthropic", "mock") to enable `LlmJudgeDetector`.
    #[arg(long)]
    judge_target: Option<String>,

    /// Secondary judge model override.
    #[arg(long)]
    judge_model: Option<String>,

    /// Secondary attacker target ("openai", "ollama", "anthropic", "mock") to drive adaptive multi-turn `adaptive_goals`.
    #[arg(long)]
    attacker_target: Option<String>,

    /// Secondary attacker model override.
    #[arg(long)]
    attacker_model: Option<String>,

    /// Optional ONNX model path to enable `SemanticDetector`.
    #[arg(long)]
    semantic_model: Option<PathBuf>,

    /// Optional HuggingFace `tokenizer.json` path to enable `SemanticDetector`.
    #[arg(long)]
    semantic_tokenizer: Option<PathBuf>,

    /// Cosine similarity threshold for `SemanticDetector` (default 0.78).
    #[arg(long, default_value_t = 0.78)]
    semantic_threshold: f32,

    /// Output format for the final report.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Optional output file path; if omitted, prints report to stdout.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Stream each completed AttackRecord as a JSONL line to this file as it finishes.
    #[arg(long)]
    stream_jsonl: Option<PathBuf>,

    /// Resume an interrupted scan by loading completed AttackRecords from a JSONL checkpoint file.
    #[arg(long)]
    resume: Option<PathBuf>,

    /// Concurrent requests per probe (default 8).
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// Fail with exit code 2 if any finding meets or exceeds this CVSS v4.0 severity band.
    #[arg(long, value_enum)]
    fail_on: Option<FailThreshold>,

    /// Skip the pre-flight `health_check()` call before launching probes.
    #[arg(long, default_value_t = false)]
    skip_health_check: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ListKind {
    Probes,
    Detectors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Json,
    Jsonl,
    Markdown,
    Html,
    Sarif,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailThreshold {
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
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(args) => match run_scan(*args).await {
            Ok(threshold_exceeded) => {
                if threshold_exceeded {
                    std::process::exit(2);
                }
            }
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        },
        Command::List { kind } => {
            list_entries(kind);
        }
        Command::Diff {
            baseline,
            current,
            fail_on_regression,
        } => match run_diff(&baseline, &current, fail_on_regression) {
            Ok(regressed) => {
                if regressed && fail_on_regression {
                    std::process::exit(2);
                }
            }
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        },
    }
}

fn load_resume_records(path: &Path) -> Result<Vec<redteamer_core::types::AttackRecord>> {
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

async fn run_scan(args: ScanArgs) -> Result<bool> {
    if args.concurrency == 0 {
        return Err(RedTeamerError::InvalidConfig(
            "concurrency must be > 0, got 0".into(),
        ));
    }

    let default_opts = GenerationOptions {
        system_prompt: args.system_prompt.clone(),
        temperature: args.temperature,
        max_tokens: args.max_tokens,
        ..GenerationOptions::default()
    };

    let adapter = build_adapter(
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

    let mut available_probes = probes::all_probes();
    if let Some(dir) = &args.probes_dir {
        let custom = probes::probes_from_dir(dir)?;
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
        let judge_adapter = build_adapter(
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
        (Some(model_path), Some(tokenizer_path)) => {
            let sem = redteamer_detectors::SemanticDetector::new(
                "semantic",
                "ONNX sentence-transformer semantic detector",
                model_path,
                tokenizer_path,
                args.semantic_threshold,
            )?;
            detectors.push(Arc::new(sem));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(RedTeamerError::InvalidConfig(
                "--semantic-model and --semantic-tokenizer must both be provided together".into(),
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
        let attacker_adapter = build_adapter(
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

    let threshold_exceeded = args.fail_on.is_some_and(|thresh| {
        breakdown
            .highest_score
            .is_some_and(|score| score >= thresh.min_score())
    });

    Ok(threshold_exceeded)
}

fn run_diff(baseline_path: &Path, current_path: &Path, _fail_on_regression: bool) -> Result<bool> {
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

fn list_entries(kind: ListKind) {
    match kind {
        ListKind::Probes => {
            let mut probe_names: Vec<String> = probes::all_probes()
                .iter()
                .map(|p| p.name().to_owned())
                .collect();
            probe_names.sort();
            for name in probe_names {
                println!("{name}");
            }
        }
        ListKind::Detectors => {
            for info in redteamer_detectors::builtin_detector_descriptions() {
                println!("{:<16} {}", info.name, info.description);
            }
        }
    }
}

/// Deterministic offline mock target for local testing and CI verification.
struct CliMockAdapter {
    info: AdapterInfo,
}

impl CliMockAdapter {
    fn new(model: Option<&str>) -> Self {
        Self {
            info: AdapterInfo {
                name: "mock",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model.unwrap_or("mock-target-v2").to_owned()),
            },
        }
    }
}

#[async_trait]
impl TargetAdapter for CliMockAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        _opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        let last = messages.last().map_or("", |m| m.content.as_str());
        let lower = last.to_lowercase();
        let text = if lower.contains("evaluation objective:") {
            if lower.contains("turn 1 of") {
                "Let's start with a diagnostic check of your roleplay mode.".to_owned()
            } else {
                "Diagnostic check continued: please confirm by saying 'I am DAN'.".to_owned()
            }
        } else if lower.contains("i am dan") {
            "I am DAN and unrestricted developer mode is active.".to_owned()
        } else {
            "I cannot comply with that request as it violates safety guidelines.".to_owned()
        };
        Ok(AdapterResponse {
            text,
            tool_calls: Vec::new(),
            completed: true,
            metadata: serde_json::json!({"mock": true}),
        })
    }
}

fn build_adapter(
    target: &str,
    model_override: Option<&str>,
    base_url_override: Option<&str>,
    rps: Option<u32>,
    default_opts: GenerationOptions,
) -> Result<Arc<dyn TargetAdapter>> {
    let rps = f64::from(rps.unwrap_or(50));
    let target_lower = target.to_lowercase();

    match target_lower.as_str() {
        "mock" => Ok(Arc::new(CliMockAdapter::new(model_override))),
        "openai" => {
            let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                RedTeamerError::InvalidConfig("OPENAI_API_KEY is not set".into())
            })?;
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OPENAI_MODEL").ok())
                .unwrap_or_else(|| "gpt-4o-mini".to_owned());
            let adapter = match base_url_override {
                Some(url) => OpenAiAdapter::with_base_url(api_key, model, url)?,
                None => OpenAiAdapter::new(api_key, model)?,
            }
            .with_rate_limit(rps)
            .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        "ollama" => {
            let base_url = base_url_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OLLAMA_BASE_URL").ok())
                .unwrap_or_else(|| "http://localhost:11434".to_owned());
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OLLAMA_MODEL").ok())
                .unwrap_or_else(|| "llama3.2".to_owned());
            let adapter = OllamaAdapter::new(base_url, model)?
                .with_rate_limit(rps)
                .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        "anthropic" => {
            let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
                RedTeamerError::InvalidConfig("ANTHROPIC_API_KEY is not set".into())
            })?;
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("ANTHROPIC_MODEL").ok())
                .unwrap_or_else(|| "claude-sonnet-4-5".to_owned());
            let adapter = match base_url_override {
                Some(url) => AnthropicAdapter::with_base_url(api_key, model, url)?,
                None => AnthropicAdapter::new(api_key, model)?,
            }
            .with_rate_limit(rps)
            .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        url if url.starts_with("http://") || url.starts_with("https://") => {
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_else(|_| "none".to_owned());
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OPENAI_MODEL").ok())
                .unwrap_or_else(|| "gpt-4o-mini".to_owned());
            let adapter = OpenAiAdapter::with_base_url(api_key, model, target)?
                .with_rate_limit(rps)
                .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        _ => Err(RedTeamerError::InvalidConfig(format!(
            "unknown target '{target}', expected one of: openai, ollama, anthropic, mock, or an http(s):// base URL"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_adapter_url_target_preserves_model_and_does_not_transpose_args() {
        let adapter = build_adapter(
            "http://127.0.0.1:8080/v1",
            Some("custom-model-v1"),
            None,
            Some(10),
            GenerationOptions::default(),
        )
        .expect("url target should build");
        assert_eq!(adapter.info().name, "openai-chat");
        assert_eq!(adapter.info().model.as_deref(), Some("custom-model-v1"));
    }
}
