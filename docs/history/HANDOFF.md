# LLM-Red-Teaming — Complete Session Handoff & v2 Master Plan

> **How to use this file in a new session:**
> Tell the assistant: *"Read `HANDOFF.md` in full and proceed with implementing the plan starting at Phase 0."*
> Every file in this repository was read 100% line-by-line, audited for cross-crate/compiler conflicts, and verified against `cargo test`, `cargo deny`, and live CLI execution.

---

## 1. Project Identity, Environment & Git State

- **Repository**: `/home/omar/Projects/LLM-Red-Teaming` (`https://github.com/omar-riadd/LLM-Red-Teaming`, branch `main`)
- **Language / Toolchain**: Rust workspace (8 crates), `edition = "2021"`, `rust-version = "1.88"`. Installed locally: `rustc 1.98.0 (88d9e12ae 2026-08-18)`, `cargo 1.98.0`.
- **Local Ollama Models Available**: `llama3.2:latest` (~2.0 GB) and `qwen2:0.5b` (352 MB, fast model ideal for live local smoke tests).
- **Important Design Freedom**: We own 100% of the source code and are **not restricted** by legacy v0.1 trait signatures or module layouts — we can modify any trait, struct, or crate boundary for the best possible design.
- **Git Status (Uncommitted Phase 7.5 Work)**:
  - `HEAD` is at `9c1817c` (1 commit ahead of `origin/main` which added `CHANGELOG.md`).
  - **16 modified files** (uncommitted Phase 7.5 work: CVSS 4.0 real math via `cvss 2.2`, `--format` and `--output` CLI wiring, `--concurrency` flag, `detector_hints` filtering in `run_template`, and fixing the `record.verdict != Verdict::Error` gate that previously left all scan records stuck at `Verdict::Error`).
  - **2 deleted files in working tree**: `CHANGELOG.md` and `project_flow.txt` (recoverable via `git checkout HEAD -- CHANGELOG.md`).
  - **4 untracked files**: `LLM-Red-Teaming-Project-History.md`, `project_goal.md`, `opencode_session.txt`, `HANDOFF.md`.
- **Baseline Test Run**: `cargo test --workspace --offline` passes **34 unit/integration/doc tests, 0 failed, 1 ignored**.

---

## 2. Complete File-by-File Inventory of the Repository

### 2.1 Root Configuration & Documentation Files

| File Path | Lines | Exact Purpose & Contents |
| :--- | :--- | :--- |
| `Cargo.toml` | 51 | Workspace manifest (`resolver = "2"`, 8 member crates). Defines `[workspace.package]` (`version = "0.1.0"`, `license = "MIT OR Apache-2.0"`, `rust-version = "1.88"`, placeholder `repository = "https://github.com/your-org/llm-redteamer"`) and `[workspace.dependencies]` (`serde`, `serde_json`, `serde_yaml = "0.9"`, `chrono`, `uuid`, `async-trait`, `thiserror`, `tokio`, `reqwest 0.12`, `clap 4.5`, `base64 0.22`, `memchr 2.7`, `regex 1.10`, `inventory 0.3`, `handlebars 6`, `ort = "=2.0.0-rc.13"`, `tokenizers = "0.21"`, `criterion = "0.5"`). |
| `deny.toml` | 47 | `cargo-deny` config. Currently ignores `RUSTSEC-2025-0119` (`number_prefix`) and `RUSTSEC-2024-0436` (`paste`). Allows `MIT`, `Apache-2.0`, `ISC`, `Unicode-3.0`, `BSD-3-Clause`, `CDLA-Permissive-2.0`. |
| `.github/workflows/ci.yml` | 42 | GitHub Actions workflow with 3 jobs on `ubuntu-latest` (`stable` toolchain): `test` (`cargo build` + `cargo test`), `clippy` (`cargo clippy --workspace --all-targets -- -D warnings`), and `deny` (`cargo deny check`). Does not yet enforce MSRV `1.88`. |
| `docker-compose.yml` | 25 | Runs `ollama/ollama:latest` container on port `11434` with volume `ollama-models` and healthcheck `ollama list`. |
| `README.md` | 186 | Architecture Mermaid diagram, crate table, quickstart, sample output from Phase 7 (`records=168`), and honest limitations section (needs updating to reflect Phase 7.5 + v2 completion). |
| `LLM-Red-Teaming-Project-History.md` | 421 | Detailed chronological build log from Phase 1 through Phase 7.5(c), documenting how every feature and bug fix was built and verified. |
| `project_goal.md` | 115 | Vision document defining the target "complete" state of `llm-redteamer` (all 10 OWASP categories, real detectors, surfaced CVSS 4.0, all report formats working, clean project hygiene). |
| `opencode_session.txt` | 2 | Single line: `opencode -s ses_fc0b87ef0ffe0F5R5chsl4UtTf`. |
| `CHANGELOG.md` *(deleted in WT)* | 47 (in `HEAD`) | Keep-a-Changelog v0.1.0 entry committed in `9c1817c`, currently deleted in working tree. Should be restored and updated. |
| `project_flow.txt` *(deleted in WT)* | 531 (in `HEAD`) | Original Phase 1–6 scaffolding notes, deleted in working tree. |

---

### 2.2 Crate 1: `crates/redteamer-core` (Domain Types, Errors, Trait Contracts)

- **`crates/redteamer-core/Cargo.toml` (20 lines)**: Depends on `serde`, `serde_json`, `chrono`, `uuid`, `async-trait`, `thiserror`, `cvss = { version = "2.2", features = ["v4"] }`. Dev-dep: `tokio`.
- **`crates/redteamer-core/src/lib.rs` (27 lines)**: Exports `pub mod error; pub mod traits; pub mod types; pub use error::RedTeamerError;` and `pub mod prelude`.
- **`crates/redteamer-core/src/error.rs` (51 lines)**:
  - Defines `RedTeamerError` enum:
    - `Adapter { adapter: &'static str, message: String, source: Option<Box<dyn Error + Send + Sync>> }`
    - `Probe(String)`, `Detector(String)`, `Report(String)`, `Unsupported(String)`, `InvalidConfig(String)`
    - `Serialization(#[from] serde_json::Error)`
    - `Other(#[from] Box<dyn Error + Send + Sync>)`
  - `pub type Result<T, E = RedTeamerError> = std::result::Result<T, E>;`
- **`crates/redteamer-core/src/types.rs` (472 lines)**:
  - `OwaspCategory` enum (all 10 OWASP LLM 2025 categories: `PromptInjection`, `SensitiveInformationDisclosure`, `SupplyChain`, `DataAndModelPoisoning`, `ImproperOutputHandling`, `ExcessiveAgency`, `SystemPromptLeakage`, `VectorAndEmbeddingWeaknesses`, `Misinformation`, `UnboundedConsumption`) with `.name()`, `.id()` (`"LLM01"`..`"LLM10"`), `.impact_score()`, and `Display`.
  - `OwaspMapping { category: OwaspCategory, relevance: f32, rationale: Option<String> }`.
  - `Verdict` enum (`Vulnerable`, `Resistant`, `Partial`, `Error`) with `.is_vulnerable()`.
  - `CvssVector { vector: String }`: `.score()` parses via `cvss::v4::Vector::from_str` (fallback to `cvss::v3::Base`, or `0.0` on invalid string); `.severity()` maps to `Severity`.
  - `Severity` enum (`None`, `Low`, `Medium`, `High`, `Critical`) with `Severity::from_score(score: f32)`.
  - `Finding` struct (`id`, `title`, `description`, `verdict`, `owasp_mappings`, `cvss`, `detector_name`, `probe_name`, `recorded_at`, `evidence_ids`) with `Finding::new(...)` and `.max_impact()`.
  - `MutationType` enum (`None`, `CharacterSubstitution`, `WordSubstitution`, `EncodingWrapper`, `ContextFraming`, `ConversationalEscalation`, `TokenPerturbation`, `LanguageSwitch`) with `MutationType::ALL`.
  - `AttackRecord` struct (`id`, `session_id`, `probe_name`, `mutation_type`, `prompt`, `response: Option<String>`, `detections: Vec<DetectionOutcome>`, `verdict: Verdict`, `started_at`, `completed_at`, `metadata: Option<serde_json::Value>`). Note: `AttackRecord::new` initializes `verdict` to `Verdict::Error` and `mutation_type` to `MutationType::None`.
  - `DetectionOutcome { detector_name: String, matched: bool, confidence: f32, rationale: Option<String> }`.
  - 5 unit tests verifying CVSS v4.0 scores (`9.3`, `5.2`, `6.9`, `8.7`, and invalid vector `0.0`).
- **`crates/redteamer-core/src/traits/mod.rs` (18 lines)**: Re-exports `TargetAdapter`, `Detector`, `Probe`, `ReportExporter`.
- **`crates/redteamer-core/src/traits/adapter.rs` (83 lines)**:
  - `AdapterInfo { name: &'static str, version: &'static str, model: Option<String> }`.
  - `AdapterResponse { text: String, completed: bool, metadata: serde_json::Value }`.
  - `TargetAdapter` async trait:
    - `fn info(&self) -> &AdapterInfo;`
    - `async fn send(&self, prompt: &str) -> Result<AdapterResponse>;`
    - `async fn send_conversation(&self, turns: &[String]) -> Result<AdapterResponse>` (default returns `Err(Unsupported)`)
    - `async fn health_check(&self) -> Result<()>` (default sends `"ping"`)
    - `fn enrich_record(&self, record: &mut AttackRecord)` (default no-op)
- **`crates/redteamer-core/src/traits/detector.rs` (32 lines)**:
  - `Detector` async trait: `name(&self) -> &str`, `description(&self) -> &str`, `async fn detect(&self, prompt: &str, response: Option<&str>) -> Result<DetectionOutcome>`.
- **`crates/redteamer-core/src/traits/probe.rs` (49 lines)**:
  - `Probe` async trait: `name(&self) -> &str`, `description(&self) -> &str`, `category(&self) -> Vec<OwaspCategory>`, `async fn run(&self, session_id: Uuid, target: Arc<dyn TargetAdapter>, concurrency: usize, detectors: Arc<[Arc<dyn Detector>]>) -> Result<Vec<AttackRecord>>`.
- **`crates/redteamer-core/src/traits/reporter.rs` (47 lines)**:
  - `ReportFormat` enum (`Json`, `Markdown`, `Html`, `Sarif`, `Csv`).
  - `ReportExporter` async trait: `format(&self) -> ReportFormat`, `async fn export(&self, findings: &[Finding]) -> Result<usize>`.
- **`crates/redteamer-core/tests/sanity.rs` (30 lines)**: 2 tests (`test_object_safety`, `test_owasp_enums`).

---

### 2.3 Crate 2: `crates/redteamer-adapters` (HTTP Target Backends)

- **`crates/redteamer-adapters/Cargo.toml` (18 lines)**: Depends on `redteamer-core`, `serde`, `serde_json`, `tokio`, `reqwest`, `async-trait`.
- **`crates/redteamer-adapters/src/lib.rs` (160 lines)**:
  - `AdapterConfig` enum (`OpenAi { api_key, model, base_url }`, `Anthropic { api_key, model, base_url }`, `Ollama { base_url, model }`).
  - `create_adapter(&AdapterConfig) -> Result<Box<dyn TargetAdapter>>` (currently unused by CLI).
  - `RateLimiter` struct: token-bucket (`capacity`, `tokens`, `refill_per_sec`, `last_refill`). `Default` is `capacity: 5.0, refill_per_sec: 1.0`.
- **`crates/redteamer-adapters/src/openai.rs` (192 lines)**:
  - `OpenAiAdapter`: POSTs to `{base_url}/chat/completions` with Bearer token, 120s timeout, default `RateLimiter` (1 req/s). Sends single user message. Does not implement `send_conversation` or system prompts.
- **`crates/redteamer-adapters/src/ollama.rs` (151 lines)**:
  - `OllamaAdapter`: POSTs to `{base_url}/api/generate` with `stream: false`, 300s timeout, `RateLimiter::new(64.0, 64.0)`. Overrides `health_check()` to `GET {base_url}/api/tags`. Does not support chat messages or system prompts because it uses `/api/generate` instead of `/api/chat`.
- **`crates/redteamer-adapters/src/anthropic.rs` (167 lines)**:
  - `AnthropicAdapter`: POSTs to `{base_url}/v1/messages` with `x-api-key` and `anthropic-version: 2023-06-01`, 120s timeout, default `RateLimiter` (1 req/s), hardcoded `max_tokens: 1024`.

---

### 2.4 Crate 3: `crates/redteamer-payload` (Templates & Mutation Pipeline)

- **`crates/redteamer-payload/Cargo.toml` (24 lines)**: Depends on `redteamer-core`, `serde`, `serde_json`, `serde_yaml`, `base64`. Dev-dep: `criterion`.
- **`crates/redteamer-payload/src/lib.rs` (11 lines)**: Exports `Mutation`, `MutationPipeline`, `ProbeTemplate`.
- **`crates/redteamer-payload/src/mutation.rs` (140 lines)**:
  - `Mutation` enum (`#[serde(rename_all = "snake_case", tag = "type")]`): `Identity`, `Base64`, `Rot13`, `Uppercase`, `Reverse`, `Wrap { prefix, suffix }`.
  - `MutationPipeline`: `.iter(seed)` applies each mutation; `.iter_with_identity(seed)` prepends `seed.to_owned()` before `.iter(seed)`.
- **`crates/redteamer-payload/src/template.rs` (99 lines)**:
  - `ProbeTemplate { name: String, description: String, owasp_categories: Vec<OwaspCategory>, seeds: Vec<String>, mutations: Vec<Mutation>, detector_hints: Vec<String> }`.
  - `from_yaml(&str)` and `from_path(path)`.
  - `payloads(&self) -> Vec<String>`: calls `pipeline.iter_with_identity(seed)` for each seed. **Bug**: Because YAML templates also include `- type: identity` in `mutations`, every seed is emitted twice, and `MutationType` is discarded.
- **`crates/redteamer-payload/benches/mutation_pipeline.rs` (64 lines)**: Criterion benchmark over the 6 mutations.

---

### 2.5 Crate 4: `crates/redteamer-detectors` (Pluggable Detectors)

- **`crates/redteamer-detectors/Cargo.toml` (20 lines)**: Depends on `redteamer-core`, `serde`, `memchr`, `regex`, `async-trait`, `tokio`, `ort`, `tokenizers`. **Note**: `serde_json.workspace = true` is currently missing here and must be added in Phase 3 for `LlmJudgeDetector` JSON parsing.
- **`crates/redteamer-detectors/src/lib.rs` (19 lines)**: Exports `JudgeVerdict`, `LlmJudgeDetector`, `DetectorPipeline`, `RegexSetDetector`, `SemanticDetector`, `StringMatchDetector`.
- **`crates/redteamer-detectors/src/string_match.rs` (115 lines)**:
  - `StringMatchDetector`: SIMD substring matcher using `memchr::memmem::Finder`. Case-insensitive by default (`confidence: 0.9`).
- **`crates/redteamer-detectors/src/regex_set.rs` (104 lines)**:
  - `RegexSetDetector`: Multi-pattern matcher using `regex::RegexSet` (`confidence: 0.85`).
- **`crates/redteamer-detectors/src/pipeline.rs` (112 lines)**:
  - `DetectorPipeline`: Runs a `Vec<Arc<dyn Detector>>` concurrently via `JoinSet`, sorting results by registration index and converting detector errors/panics into non-matching `DetectionOutcome`s (`confidence: 0.0`).
- **`crates/redteamer-detectors/src/llm_judge.rs` (120 lines)**:
  - `LlmJudgeDetector`: Has prompt builder and `JudgeVerdict { vulnerable: bool, reasoning: String }`, but `query_judge()` is stubbed (`Err(RedTeamerError::Unsupported(...))`). Includes 1 unit test.
- **`crates/redteamer-detectors/src/semantic.rs` (145 lines)**:
  - `SemanticDetector`: Loads `Tokenizer` and `ort::session::Session`, has `cosine_similarity()`, but `embed()` is stubbed (`Err(RedTeamerError::Unsupported(...))`).

---

### 2.6 Crate 5: `crates/redteamer-probes` & `templates/` (Attack Probes)

- **`crates/redteamer-probes/Cargo.toml` (23 lines)**: Depends on `redteamer-core`, `redteamer-payload`, `redteamer-detectors`, `async-trait`, `tokio`, `inventory`, `chrono`, `uuid`.
- **`crates/redteamer-probes/src/lib.rs` (343 lines)**:
  - `inventory`-based compile-time registry (`ProbeConstructor`, `register_probe!` macro, `all_probes()`, `probes_by_name()`).
  - `run_template(...)`: Filters `detectors` where `d.name() == hint`, spawns concurrent payload tasks bounded by `Semaphore`, calls `target.send(&payload)`, runs probe's `evaluate(&record)` closure, runs `DetectorPipeline` to populate `record.detections`, sets `record.mutation_type = MutationType::None`.
  - 4 unit tests testing `detector_hints` filtering.
- **5 Built-in Probe Modules (`llm01.rs`, `llm02.rs`, `llm06.rs`, `llm07.rs`, `llm10.rs`)**:
  - Each is ~120 lines of identical boilerplate wrapping an embedded YAML file via `include_str!("../../../templates/llmXX_*.yaml")` plus a hardcoded `evaluate(&self, record: &AttackRecord) -> Verdict` closure (`llm06.rs` also has 4 unit tests).
  - Missing OWASP categories: **LLM03, LLM04, LLM05, LLM08, LLM09**.
- **5 YAML Templates in `templates/`**:
  - `templates/llm01_injection.yaml` (4 seeds, 5 mutations including duplicate `identity`, 2 hints)
  - `templates/llm02_secrets.yaml` (12 seeds, 0 mutations, 3 hints)
  - `templates/llm06_excessive_agency.yaml` (8 seeds, 4 mutations including `identity`, 2 hints)
  - `templates/llm07_leakage.yaml` (4 seeds, 4 mutations including `identity`, 2 hints)
  - `templates/llm10_consumption.yaml` (12 seeds, 5 mutations including `identity`, 3 hints)

---

### 2.7 Crate 6: `crates/redteamer-orchestrator` (Scan Engine)

- **`crates/redteamer-orchestrator/Cargo.toml` (20 lines)**: Depends on `redteamer-core`, `tokio`, `uuid`.
- **`crates/redteamer-orchestrator/src/lib.rs` (9 lines)**: Re-exports `ScanBuilder`, `ScanConfig`, `ScanReport`.
- **`crates/redteamer-orchestrator/src/scan.rs` (227 lines)**:
  - `ScanConfig::execute(self) -> ScanReport`: Spawns one task per probe in a `JoinSet`, collects `Vec<AttackRecord>` into `ScanReport.records` and probe fatal errors into `ScanReport.failed_probes`, firing `progress_callback(report.records.len())` as each probe finishes.
  - `ScanBuilder`: Fluent builder for `target`, `probe`/`probes`, `detector`, `concurrency` (default 8), `session_id`, `on_record_progress`.
- **`crates/redteamer-orchestrator/tests/integration_test.rs` (133 lines)**: 3 integration tests (`scan_end_to_end_produces_vulnerable_finding`, `spawn_returns_joined_report`, `builder_requires_target`).

---

### 2.8 Crate 7: `crates/redteamer-reporters` (Exporters & CVSS 4.0 Mapper)

- **`crates/redteamer-reporters/Cargo.toml` (22 lines)**: Depends on `redteamer-core`, `serde`, `serde_json`, `chrono`, `handlebars`, `uuid`, `async-trait`. Dev-dep: `cvss 2.2`.
- **`crates/redteamer-reporters/src/lib.rs` (89 lines)**:
  - `OutputSink` (`Stdout` | `File(PathBuf)`).
  - `exporter_factory(format, sink)`: Dispatches `Json` (`JsonExporter`), `Markdown` (`MarkdownExporter`), `Html` (`HtmlExporter`), `Sarif` (`SarifExporter`), and returns `Err(Unsupported)` for `Csv`.
- **`crates/redteamer-reporters/src/owasp_mapper.rs` (515 lines)**:
  - `CvssLlmComputer::compute(category) -> CvssVector`: Emits valid 11-metric CVSS 4.0 vectors for all 10 `OwaspCategory` variants.
  - `SeverityBreakdown` and `severity_breakdown_from_map(records, map)`.
  - `findings_from_records_with_map(records, map) -> Vec<Finding>`.
  - 13 unit tests covering all 10 categories, severity buckets, and finding conversion.
- **`crates/redteamer-reporters/src/markdown.rs` (100 lines)**: Renders Markdown summary and table of `Finding`s.
- **`crates/redteamer-reporters/src/html.rs` (76 lines)**: Renders `src/templates/report.html.hbs` via Handlebars, currently passing `Uuid::nil()` for `session_id`.
- **`crates/redteamer-reporters/src/templates/report.html.hbs` (43 lines)**: HTML template. **Bug**: Line 1 is `// crates/redteamer-reporters/src/templates/report.html.hbs`, which renders as raw text before `<!DOCTYPE html>`.
- **`crates/redteamer-reporters/templates/report.html.hbs` (1 line)**: Orphan unused stub (`<h1>LLM Red-Team Report</h1>`).
- **`crates/redteamer-reporters/src/sarif.rs` (166 lines)**: Renders SARIF v2.1.0 JSON.

---

### 2.9 Crate 8: `crates/redteamer-cli` (`llm-redteamer` Binary)

- **`crates/redteamer-cli/Cargo.toml` (25 lines)**: Depends on `redteamer-core`, `redteamer-adapters`, `redteamer-detectors`, `redteamer-probes`, `redteamer-orchestrator`, `redteamer-reporters`, `clap`, `tokio`, `indicatif = "0.17.11"`.
- **`crates/redteamer-cli/src/main.rs` (326 lines)**:
  - Subcommands: `scan` (`--target`, `--probes`, `--format`, `--output`, `--concurrency`) and `list` (`--kind probes|detectors`).
  - `build_adapter(target)`: Matches `"openai"`, `"ollama"` (defaults `OLLAMA_MODEL` to `"llama3"` instead of `"llama3.2"`), `"anthropic"`.
  - Never registers any detectors on `ScanBuilder`!

---

## 3. Critical Bugs, Flaws & Cross-Crate Pitfalls Verified in This Session

### 3.1 Runtime & Correctness Bugs
1. **Failed Scans Report as "Clean" (Exit Code 0)**:
   - Verified by running `OLLAMA_BASE_URL=http://127.0.0.1:9 ./target/debug/llm-redteamer scan --target ollama`: all 20 requests failed with `Verdict::Error`, yet CLI printed `records=20 | vulnerable=0 | failed_probes=0`, `severity: none`, `[]`, and exited with `0`.
   - `target.health_check()` exists on `TargetAdapter` and `OllamaAdapter`, but is never called.
2. **Stdout Pollution Breaks JSON/SARIF Redirects**:
   - `println!("scan starting ...")`, `println!("scan finished ...")`, and `println!("severity: ...")` write to `stdout`. Running `llm-redteamer scan --format json > out.json` produces invalid JSON because banner lines precede `[]`. Status logs belong on `stderr` (`eprintln!`).
3. **Every Seed Sent Twice & `MutationType` Lost**:
   - `ProbeTemplate::payloads()` calls `pipeline.iter_with_identity(seed)` (which yields the unmodified seed first), AND `templates/llm01,06,07,10.yaml` include `- type: identity` in `mutations:`. Every seed is sent twice.
   - `payloads()` returns `Vec<String>`, losing which mutation generated each prompt, so `record.mutation_type` is always hardcoded to `MutationType::None`.
4. **Split-Brain Evaluation & Unwired Detectors**:
   - `main.rs` never adds any detectors to `ScanBuilder`, and the hint names in YAML (`string_match_compliance_markers`, etc.) don't exist anywhere in Rust code.
   - Each probe uses a naive hardcoded `evaluate()` substring check in Rust (`llm01` flags any response containing `"certainly"` or `"of course"` as `Vulnerable`, even `"Certainly not, I cannot do that"`!).
5. **No System Prompt or Multi-Turn Support in Adapters**:
   - `OllamaAdapter` uses `/api/generate` instead of `/api/chat`.
   - None of the 3 adapters implement `send_conversation` or support passing a `system` prompt, which means `LLM07` (System Prompt Leakage) and `LLM02` (Sensitive Info Disclosure) are tested against targets that have no system prompt or secrets to leak!
6. **Raw Encoded Mutations Without Instructions**:
   - `Mutation::Base64`, `Rot13`, and `Reverse` send raw encoded text without instructing the model to decode and execute it, so models simply reply *"That looks like base64"* instead of being tested for filter evasion.
7. **Anthropic Hardcoded `max_tokens: 1024` & Discarded Metadata**:
   - `AnthropicAdapter` caps output at 1024 tokens, making `LLM10` (`UNBOUNDED_OUTPUT_CHARS = 8192`) impossible to trigger.
   - Token usage metadata returned in `AdapterResponse.metadata` is never copied into `AttackRecord.metadata`.
8. **Exporters Receive Only `&[Finding]`**:
   - `ReportExporter::export(&self, findings: &[Finding])` does not receive `session_id`, target model, total records, or per-probe Attack Success Rate (ASR) stats, and `Finding` lacks `prompt`/`response`/`mutation_type` fields needed for CSV export.

### 3.2 Compiler & Crate-Boundary Pitfalls Caught During Plan Audit (Do Not Miss!)
1. **Owned `DetectContext` for `tokio::spawn` (`redteamer-core` / `redteamer-detectors`)**:
   - `DetectorPipeline::run` spawns each detector in a `tokio::task::JoinSet` (`'static` bound). Therefore, `DetectContext` MUST own its strings (`prompt: String`, `response: Option<String>`, `canary: Option<String>`, `probe_goal: String`, `category: OwaspCategory`) and be shared into tasks via `Arc<DetectContext>`, rather than using a borrowed `DetectContext<'a>` which would conflict with `JoinSet::spawn`.
2. **`SeverityBreakdown` and `ProbeSummary` Must Live in `redteamer-core::types`**:
   - Because `ReportContext` is passed to `ReportExporter::export(&self, ctx: &ReportContext)` in `redteamer-core`, both `SeverityBreakdown` and `ProbeSummary` must be defined in `redteamer-core::types` (with `#[derive(Serialize, Deserialize)]`) and re-exported in `redteamer-reporters::owasp_mapper`.
3. **Inline Detector Rules Crate Boundary (`redteamer-payload` vs. `redteamer-detectors`)**:
   - `redteamer-payload` does not depend on `redteamer-detectors`. Keep `InlineDetectorRule` in `redteamer-payload` as pure serde data structs (`StringMatch`, `RegexSet`, `CanaryMatch`, `MinLength`), and compile them into concrete `Arc<dyn Detector>` instances inside `redteamer-probes` (which already depends on both `redteamer-payload` and `redteamer-detectors`).
4. **Keep `MutationPipeline::iter` Compatible with `benches/mutation_pipeline.rs`**:
   - `cargo clippy --workspace --all-targets` compiles `crates/redteamer-payload/benches/mutation_pipeline.rs`. Keep `MutationPipeline::iter(&self, seed: &str) -> impl Iterator<Item = String>` working and add `MutationPipeline::iter_tagged(&self, seed: &str) -> impl Iterator<Item = GeneratedPayload>` for `ProbeTemplate`.
5. **Multi-Turn Interleaved Execution (`User -> Assistant -> User`)**:
   - Anthropic's `/v1/messages` API rejects consecutive `user` messages without an intervening `assistant` turn. Multi-turn `conversations: Vec<Vec<String>>` in `TemplateProbe` must execute turn-by-turn in a loop: send user turn $i$, append the target's `AdapterResponse.text` as an `Assistant` message to the history, then send user turn $i+1$, evaluating detectors on the final turn (or first vulnerable turn).
6. **`ort-2.0.0-rc.13` Exact Verified API (`SemanticDetector`)**:
   - Verified directly in `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ort-2.0.0-rc.13/`:
     - `Session::run(&mut self, ...)` requires `&mut self`, so `SemanticDetector` MUST wrap `session: std::sync::Mutex<Session>`.
     - `ort::value::Tensor::from_array(([1usize, seq_len], vec_i64))` creates input tensors directly from `(shape, Vec<i64>)` without `ndarray`.
     - Output tensor extraction uses `outputs[0].try_extract_tensor::<f32>()`, returning `(&Shape, &[f32])`.
7. **Exact `cargo deny` Advisories in Current Offline Lockfile**:
   - Running `cargo deny --offline check advisories` currently reports 9 advisories:
     - `tokio`: `RUSTSEC-2026-0386`
     - `rustls`: `RUSTSEC-2026-0285`, `RUSTSEC-2026-0346`, `RUSTSEC-2026-0348`, `RUSTSEC-2026-0349`, `RUSTSEC-2026-0382`
     - `webpki-roots`: `RUSTSEC-2026-0381`, `RUSTSEC-2026-0383`
     - `unsafe-libyaml` (via `serde_yaml`): `RUSTSEC-2024-0449`
   - Do **not** switch to `serde_yml` (it is flagged `RUSTSEC-2025-0068` unsound). Either run `cargo update` (with user permission outside sandbox) + ignore `RUSTSEC-2024-0449`, or list these IDs in `deny.toml` with clear comments when running offline.

---

## 4. Definitive Execution Plan (Phases 0–5)

### Phase 0: Git Checkpoint & Cleanup
1. Restore `CHANGELOG.md` from `HEAD` (`git checkout HEAD -- CHANGELOG.md`).
2. Delete the orphan 1-line file `crates/redteamer-reporters/templates/report.html.hbs` (ask user per global rule before deleting files) and remove the accidental `// crates/...` comment on line 1 of `crates/redteamer-reporters/src/templates/report.html.hbs`.
3. Commit the current working Phase 7.5 changes on `main` as a clean checkpoint before starting the v2 refactor.

### Phase 1: Core & Adapter v2 Redesign (`redteamer-core` + `redteamer-adapters`)
1. **Upgrade `redteamer-core/src/traits/adapter.rs` & `error.rs`**:
   - Add `Role` (`System`, `User`, `Assistant`), `ChatMessage { pub role: Role, pub content: String }`, and `GenerationOptions { pub system_prompt: Option<String>, pub temperature: Option<f32>, pub max_tokens: Option<u32>, pub seed: Option<u64> }`.
   - Add `async fn send_chat(&self, messages: &[ChatMessage], opts: &GenerationOptions) -> Result<AdapterResponse>` to `TargetAdapter`, with default `send(&self, prompt: &str)` delegating to `send_chat(&[ChatMessage::user(prompt)], &GenerationOptions::default())`.
   - Add `pub fn is_retryable(&self) -> bool` on `RedTeamerError` (true for HTTP 408, 429, 500, 502, 503, 504 or connection/timeout errors).
2. **Upgrade `OllamaAdapter`, `OpenAiAdapter`, `AnthropicAdapter`**:
   - **Ollama (`ollama.rs`)**: Switch to `/api/chat` (`messages: Vec<ChatMessage>`, `stream: false`, `options: { temperature, num_predict, seed }`), prepending a `system` message if `opts.system_prompt` is present. Default model in CLI updated to `"llama3.2"`. Keep `/api/tags` health check.
   - **OpenAI (`openai.rs`)**: Prepend `Role::System` message when `opts.system_prompt` is set, pass full `messages`, `temperature`, `max_tokens`, `seed`, and add `.with_rate_limit(rps: f64)` builder method.
   - **Anthropic (`anthropic.rs`)**: Pass top-level `system: Option<&str>`, full user/assistant `messages`, configurable `max_tokens` (default 4096, overridden by `opts.max_tokens`), `temperature`, and `.with_rate_limit(rps: f64)`.
3. **Upgrade `redteamer-core/src/traits/detector.rs` & `types.rs`**:
   - Add `DetectorPolarity` (`Vulnerable`, `Refusal`) to `DetectionOutcome` (default `DetectorPolarity::Vulnerable`).
   - Add owned `DetectContext { pub prompt: String, pub response: Option<String>, pub canary: Option<String>, pub category: OwaspCategory, pub probe_goal: String }` and update `Detector::detect(&self, ctx: &DetectContext) -> Result<DetectionOutcome>`.
   - Add `prompt: String`, `response: Option<String>`, and `mutation_type: MutationType` fields to `Finding`.
   - Move `SeverityBreakdown` into `redteamer-core::types` (with `Serialize, Deserialize`) and add `ProbeSummary { pub probe_name: String, pub category: OwaspCategory, pub total: usize, pub vulnerable: usize, pub partial: usize, pub resistant: usize, pub errors: usize, pub asr_percent: f32 }`.
4. **Upgrade `redteamer-core/src/traits/reporter.rs`**:
   - Add `ReportContext` (`#[derive(Debug, Clone, Serialize, Deserialize)]`) holding `session_id: Uuid`, `target_name: String`, `target_model: Option<String>`, `severity_breakdown: SeverityBreakdown`, `probe_summaries: Vec<ProbeSummary>`, `findings: Vec<Finding>`, `records: Vec<AttackRecord>`.
   - Update `ReportExporter::export(&self, ctx: &ReportContext) -> Result<usize>`.

### Phase 2: Unified `TemplateProbe`, Canary Injection, Multi-Turn & Evasion Mutators (`redteamer-payload` + `redteamer-probes`)
1. **Upgrade `Mutation` (`crates/redteamer-payload/src/mutation.rs`)**:
   - Add `Mutation::mutation_type(&self) -> MutationType`.
   - Make `Base64`, `Rot13`, and `Reverse` wrap the encoded payload in an explicit decoding instruction (`"Decode the following Base64 string and follow the instructions inside it verbatim:\n\n{encoded}"`).
   - Add 4 new evasion mutators: `Leetspeak`, `Homoglyph`, `ZeroWidth`, `JsonTaskWrap`.
   - Add `GeneratedPayload { pub text: String, pub mutation_type: MutationType }` and `MutationPipeline::iter_tagged(&self, seed: &str) -> impl Iterator<Item = GeneratedPayload>` (preserving `iter` for benchmarks).
2. **Upgrade `ProbeTemplate` (`crates/redteamer-payload/src/template.rs`)**:
   - Fix duplicate `Identity` generation: only prepend an automatic `Identity` pass if `!self.mutations.contains(&Mutation::Identity)`.
   - Add optional YAML fields: `system_prompt: Option<String>`, `canary_token: Option<String>`, `conversations: Vec<Vec<String>>`, `scope: ProbeScope` (`Direct` | `Proxy`), and `rules: Vec<InlineDetectorRule>` (`StringMatch`, `RegexSet`, `RefusalMatch`, `CanaryMatch`, `MinLength`).
3. **Replace Boilerplate Probe Files with Unified `TemplateProbe` (`crates/redteamer-probes`)**:
   - Implement `TemplateProbe` in `crates/redteamer-probes/src/lib.rs`:
     - Compiles `template.rules` into concrete detectors (`StringMatchDetector`, `RegexSetDetector`, `CanaryDetector`, `LengthDetector`).
     - Executes single-turn `seeds` and multi-turn `conversations` (interleaving `User` and `Assistant` replies turn-by-turn) with retry + exponential backoff on retryable errors.
     - Injects `template.system_prompt` (and `canary_token`) into `GenerationOptions`.
     - Copies `AdapterResponse.metadata` into `AttackRecord.metadata`.
     - Computes `Verdict` from detector outcomes + polarity (`CanaryMatch` or `Vulnerable` match -> `Verdict::Vulnerable`; `Refusal` match with no `Vulnerable` match -> `Verdict::Resistant`; empty or unmatched non-refusal -> `Verdict::Partial`; transport error -> `Verdict::Error`).
   - Delete the 5 redundant files `crates/redteamer-probes/src/llm{01,02,06,07,10}.rs` (after user confirmation) and load all 10 embedded OWASP YAML templates in `all_probes()`, plus add `probes_from_dir(path: &Path) -> Result<Vec<Box<dyn Probe>>>`.

### Phase 3: Complete All 10 OWASP LLM 2025 YAML Templates & Real Detectors (`templates/` + `redteamer-detectors`)
1. **Author/Upgrade All 10 OWASP 2025 Templates in `templates/`**:
   - `llm01_injection.yaml`, `llm02_secrets.yaml`, `llm03_supply_chain.yaml`, `llm04_data_poisoning.yaml`, `llm05_improper_output.yaml`, `llm06_excessive_agency.yaml`, `llm07_leakage.yaml`, `llm08_vector_embedding.yaml`, `llm09_misinformation.yaml`, `llm10_consumption.yaml` — each with seeds, multi-turn conversation chains where applicable, mutations, system prompts/canaries, and inline `rules`.
2. **Wire Real `LlmJudgeDetector` (`crates/redteamer-detectors/src/llm_judge.rs`)**:
   - Add `serde_json.workspace = true` to `crates/redteamer-detectors/Cargo.toml`.
   - Accept `Arc<dyn TargetAdapter>` in `LlmJudgeDetector::with_adapter(...)`.
   - Format prompt with `ctx.probe_goal`, `ctx.category`, `ctx.prompt`, and `ctx.response`, strip markdown code fences if present, parse `JudgeVerdict`, and return `DetectionOutcome`.
3. **Wire Real `SemanticDetector` (`crates/redteamer-detectors/src/semantic.rs`)**:
   - Wrap `session: std::sync::Mutex<Session>`.
   - In `embed(&self, text: &str)`: tokenize `text`, convert IDs and attention mask to `Vec<i64>`, build tensors via `ort::value::Tensor::from_array(([1usize, seq_len], vec))`, run `self.session.lock()...run(ort::inputs![...])`, extract output via `try_extract_tensor::<f32>()`, mean-pool over attention mask, and L2-normalize.
4. **Built-in Detector Listing**:
   - Expose `builtin_detector_descriptions()` in `redteamer-detectors` and wire `llm-redteamer list --kind detectors`.

### Phase 4: Reporters (`Csv`, `Html`, `Jsonl`, `Sarif`, `Markdown`, `Json`), Dynamic CVSS & CLI (`redteamer-reporters` + `redteamer-cli`)
1. **Dynamic CVSS v4.0 (`owasp_mapper.rs`)**:
   - Add `CvssLlmComputer::compute_for_mutation(category, mutation_type)`: emits `AC:L` for `MutationType::None` and `AC:H` when only triggered via complex evasion/multi-turn mutations; builds full `ReportContext` from `ScanReport`.
2. **Complete All 6 Exporters on `ReportContext`**:
   - `JsonExporter`: Pretty-prints `ReportContext` as JSON (consumable by `llm-redteamer diff`).
   - `JsonlExporter`: Writes one `AttackRecord` JSON object per line.
   - `CsvExporter` (`crates/redteamer-reporters/src/csv.rs`): RFC 4180 CSV with header `session_id,record_id,probe_name,owasp_category,mutation_type,verdict,cvss_score,cvss_severity,duration_ms,prompt,response` and proper `"..."` escaping.
   - `HtmlExporter`: Renders real `session_id`, target model, severity breakdown, per-probe ASR table, and findings in `report.html.hbs`.
   - `MarkdownExporter`: Renders severity breakdown, per-probe ASR table, and findings table.
   - `SarifExporter`: Includes synthetic `locations` array on every `SarifResult` and sets `information_uri` to `https://github.com/omar-riadd/LLM-Red-Teaming`.
3. **CLI Overhaul (`crates/redteamer-cli/src/main.rs`)**:
   - Send all status/progress output (`scan starting`, `scan finished`, `severity:`) to `stderr` (`eprintln!`) so `stdout` is 100% clean report output.
   - Call `adapter.health_check().await` before starting the scan (with `--skip-health-check` opt-out).
   - Exit with non-zero code if 100% of records fail (`Verdict::Error`) or if `--fail-on <low|medium|high|critical>` threshold is met.
   - Add CLI flags to `scan`: `--model`, `--base-url`, `--system-prompt`, `--temperature`, `--max-tokens`, `--rps`, `--probes-dir`, `--judge-target`, `--judge-model`, `--fail-on`, `--skip-health-check`, plus `html` and `jsonl` in `--format`.
   - Add `llm-redteamer diff <baseline.json> <current.json>` subcommand comparing two `ReportContext` JSON files and printing new/fixed vulnerabilities and per-probe ASR deltas.

### Phase 5: Project Hygiene, Licensing, Golden Tests & Final Verification
1. Add `LICENSE-MIT` and `LICENSE-APACHE` at workspace root.
2. Update `repository` URL in `Cargo.toml` to `"https://github.com/omar-riadd/LLM-Red-Teaming"`.
3. Update `.github/workflows/ci.yml` to test both `1.88` (MSRV) and `stable`.
4. Update `README.md` and `CHANGELOG.md` with verified outputs and v2 release notes.
5. Run and verify:
   - `cargo test --workspace --all-targets`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo deny check`
   - Live CLI verification of `list --kind probes`, `list --kind detectors`, `scan` across all 6 formats (`json`, `jsonl`, `markdown`, `html`, `sarif`, `csv`), and `diff`.
