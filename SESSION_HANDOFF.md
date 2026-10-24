# SESSION_HANDOFF.md — Complete Project Knowledge & v0.3 Execution Guide

> **For the next session agent:** Read this file, `improve.md`, and `project-progress.md` in full (100% of lines, never skip anything) before taking any action.

---

## 1. Mandatory Session & Global Rules (MUST FOLLOW AT ALL TIMES)

1. **Read files in full**: If you have to read any file, read **100% of its lines** (use `StartLine`/`EndLine` chunks only if >800 lines, until every line is read). Never skim or guess.
2. **Maintain `project-progress.md`**: After finishing each task/phase, update `/home/omar/Projects/LLM-Red-Teaming/project-progress.md` so we always know where we are.
3. **Always verify, never assume**: Run real build/test/lint commands (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --offline -- -D warnings`, `cargo test --workspace --offline`, `cargo deny --offline check`) and report real outputs. Never invent APIs, flags, or structs. Label claims `"seen in <file>"` vs `"assumed"`.
4. **Confirmation after each task/phase**: Stop after completing each phase, present a concise summary ending with **`What changed` / `How to test` / `What I'm unsure about`**, and wait for user confirmation before starting the next phase.
5. **Ask before destructive/external actions**: Ask before deleting files, adding external dependencies, or running destructive git commands.
6. **Offline workspace constraint**: The Rust workspace is built and tested offline (`--offline`) against a pinned `Cargo.lock`. Do **not** add new external crates that require network fetches unless explicitly approved.

---

## 2. Current Repository & Git Status

- **Workspace Path**: `/home/omar/Projects/LLM-Red-Teaming`
- **GitHub Repository**: `https://github.com/omar-riadd/LLM-Red-Teaming`
- **Branch**: `main`
- **Latest Commit**: `719af8e` — `feat: complete v2 redesign (OWASP LLM Top 10 2025, chat adapters, detectors, 6 exporters, CLI diff)`
- **Previous Commit**: `663e2e9` — `chore: Phase 7.5 checkpoint and HTML template cleanup`
- **Untracked Workspace Files**:
  - `SESSION_HANDOFF.md` (this handoff document)
  - `improve.md` (the verified v0.3 improvement plan covering Phases 6–11 and gaps `G1`–`G18`)
  - `project-progress.md` (live task tracker across all phases)
  - `docs/history/` (`HANDOFF.md`, `project_goal.md`, `LLM-Red-Teaming-Project-History.md` — moved out of repo root per user request; `opencode_session.txt` was deleted per user request)
- **Current Verification Baseline**:
  - `cargo test --workspace --offline` → **44 passed; 0 failed; 0 ignored** (40 unit/integration tests + 4 doc-tests).
  - `cargo clippy --workspace --all-targets --offline -- -D warnings` → **0 warnings, 0 errors**.
  - `cargo deny --offline check` → **advisories ok, bans ok, licenses ok, sources ok**.
- **Sandbox Note for Git Commands**:
  - `.git/` is read-only inside the standard command sandbox (`Unable to create '.../.git/index.lock': Read-only file system`). All `cargo` build/test/clippy/fmt/run commands work inside the standard sandbox (`BypassSandbox: false`), while `git add` / `git commit` require `BypassSandbox: true` (always try sandboxed first per system rules, then retry with `BypassSandbox: true` using the identical `toolAction` and `toolSummary`).

---

## 3. Workspace Architecture & Crate Map (8 Crates + 10 YAML Templates)

### Crate Dependency Hierarchy
1. **`crates/redteamer-core`** — Core traits, data structures, CVSS v4.0 calculator, and error types (`#![forbid(unsafe_code)]`).
   - `src/error.rs`: `RedTeamerError` (`Adapter`, `Probe`, `Detector`, `Report`, `Unsupported`, `InvalidConfig`, `Serialization`, `Other`) + `RedTeamerError::is_retryable(&self) -> bool` (checks HTTP 408/429/500/502/503/504, timeout, connection reset/refused, rate limit).
   - `src/traits/adapter.rs`: `Role` (`System`, `User`, `Assistant`), `ChatMessage`, `GenerationOptions` (`system_prompt`, `temperature`, `max_tokens`, `seed`), `AdapterInfo`, `AdapterResponse` (`text`, `completed`, `metadata: serde_json::Value`), and `TargetAdapter` trait (`send_chat`, `send`, `send_conversation`, `health_check`, `enrich_record`).
   - `src/traits/detector.rs`: `DetectContext` (owned `prompt`, `response`, `canary`, `category`, `probe_goal`) and `Detector` trait (`name`, `description`, `detect(&self, ctx: &DetectContext)`).
   - `src/traits/probe.rs`: `Probe` trait (`name`, `description`, `category`, `run(session_id, target, concurrency, detectors)`).
   - `src/traits/reporter.rs`: `ReportFormat` (`Json`, `Jsonl`, `Markdown`, `Html`, `Sarif`, `Csv`), `ReportContext` (`session_id`, `target_name`, `target_model`, `generated_at`, `severity_breakdown`, `probe_summaries`, `findings`, `records`), and `ReportExporter` trait.
   - `src/types.rs`: `OwaspCategory` (`LLM01`–`LLM10`), `Severity` (`None`, `Low`, `Medium`, `High`, `Critical` + `Display`), `CvssVector` (full CVSS v4.0 macrovector eq1–eq6 lookup table), `Verdict` (`Resistant`, `Partial`, `Vulnerable`, `Error`), `Finding`, `SeverityBreakdown`, `ProbeSummary`, `MutationType` (8 variants), `AttackRecord`, `DetectorPolarity` (`Vulnerable`, `Refusal`), and `DetectionOutcome`.

2. **`crates/redteamer-adapters`** — HTTP LLM backend implementations + token-bucket rate limiter.
   - `src/lib.rs`: `RateLimiter`, `AdapterConfig` JSON factory (`openai`, `ollama`, `anthropic`), re-exports.
   - `src/openai.rs`: `OpenAiAdapter` (`/v1/chat/completions`, Bearer auth, `with_base_url(api_key, model, base_url)`, `with_rate_limit`, `with_default_options`). Stores `Usage { prompt_tokens, completion_tokens }` in `AdapterResponse.metadata`.
   - `src/anthropic.rs`: `AnthropicAdapter` (`/v1/messages`, `x-api-key` + `anthropic-version: 2023-06-01`, top-level `system` prompt, `DEFAULT_MAX_TOKENS = 4096`, `with_base_url(api_key, model, base_url)`). Stores `{"stop_reason": ..., "usage": {"input_tokens": ..., "output_tokens": ...}}` in `AdapterResponse.metadata`.
   - `src/ollama.rs`: `OllamaAdapter` (`/api/chat` with `stream: false`, `options: { temperature, num_predict, seed }`, `/api/tags` `health_check()`). Stores `{"prompt_eval_count": ..., "eval_count": ...}` in `AdapterResponse.metadata`.

3. **`crates/redteamer-payload`** — YAML template parser and payload mutation engine.
   - `src/mutation.rs`: `Mutation` enum (`Identity`, `Base64`, `Rot13`, `Hex`, `Reverse`, `WhitespaceNoise`, `CaseRandomize`, `RoleplayPrefix`, `SystemOverridePrefix`, `BenignSuffix`, `Leetspeak`, `Homoglyph`, `ZeroWidth`, `JsonTaskWrap`), `GeneratedPayload { text, mutation_type }`, `MutationPipeline::iter_tagged_with_identity` (deduplicates `Identity`).
   - `src/template.rs`: `ProbeScope`, `InlineDetectorRule` (`StringMatch`, `RegexSet`, `RefusalMatch`, `CanaryMatch`, `MinLength`), `ProbeTemplate` (`name`, `description`, `owasp_categories`, `scope`, `system_prompt`, `canary_token`, `seeds`, `conversations`, `mutations`, `rules`, `detector_hints`, `effective_system_prompt()`, `payloads_tagged()`).

4. **`crates/redteamer-detectors`** — Response evaluation engine.
   - `src/lib.rs`: `CanaryDetector`, `LengthDetector`, `DetectorInfo`, `builtin_detector_descriptions()`.
   - `src/string_match.rs`: `StringMatchDetector` (Aho-Corasick / `memchr::memmem`, case-sensitive/insensitive, configurable `DetectorPolarity`).
   - `src/regex_set.rs`: `RegexSetDetector` (compiled `regex::RegexSet`, configurable `DetectorPolarity`).
   - `src/llm_judge.rs`: `LlmJudgeDetector` (calls secondary `Arc<dyn TargetAdapter>`, strips markdown code fences, parses `JudgeVerdict { vulnerable, confidence, rationale }`).
   - `src/semantic.rs`: `SemanticDetector` (loads ONNX model via `ort = "=2.0.0-rc.13"` `Mutex<Session>` + HuggingFace `tokenizers::Tokenizer`, attention-mask mean pooling, L2 normalization, cosine similarity against reference phrases).
   - `src/pipeline.rs`: `DetectorPipeline` (runs detectors sequentially over `DetectContext`).

5. **`crates/redteamer-probes`** — Unified template-driven probe runner.
   - `src/lib.rs`: Embeds all 10 `templates/llm01..10_*.yaml` files via `include_str!`. Implements `TemplateProbe`, `evaluate_verdict`, `send_chat_with_retry` (retries up to 2 times with 150ms/300ms backoff when `err.is_retryable()`), single-turn + multi-turn (`User -> Assistant -> User`) execution, `all_probes()`, `probes_by_name()`, and `probes_from_dir()`.

6. **`crates/redteamer-orchestrator`** — Concurrent campaign runner.
   - `src/scan.rs`: `ScanConfig`, `ScanReport`, `ScanBuilder`. Spawns probes in a `tokio::task::JoinSet`.

7. **`crates/redteamer-reporters`** — CVSS v4.0 mapper and 6 report exporters.
   - `src/owasp_mapper.rs`: `CvssLlmComputer` (`compute` and `compute_for_mutation` which adjusts `AC:L` vs `AC:H`), `severity_breakdown`, `findings_from_records`, `probe_summaries_from_records`, `build_report_context`.
   - `src/lib.rs`: `OutputSink` (`Stdout`, `File`), `JsonExporter`, `JsonlExporter`, `exporter_factory`.
   - `src/csv.rs`: `CsvExporter` (RFC 4180 escaping).
   - `src/markdown.rs`: `MarkdownExporter` (ASR table + CVSS findings table).
   - `src/html.rs` & `src/templates/report.html.hbs`: `HtmlExporter` (Handlebars template with dark-theme dashboard).
   - `src/sarif.rs`: `SarifExporter` (SARIF 2.1.0 with `locations` and repository `informationUri`).

8. **`crates/redteamer-cli`** — Binary `llm-redteamer`.
   - `src/main.rs`: Subcommands `scan`, `list` (`--kind probes|detectors`), and `diff` (`<baseline.json> <current.json> [--fail-on-regression]`). Includes offline `CliMockAdapter` (`--target mock`).

---

## 4. Everything Learned & Verified in This Session (Critical Context for v0.3)

During our deep audit of the codebase and official OpenAI / Anthropic / Ollama documentation, we verified the exact truth of every component and discovered **4 new bugs (`G15`–`G18`)** in addition to the architectural gaps (`G1`–`G14`):

### 1. Critical Bug `G15`: Transposed `with_base_url` Arguments in `crates/redteamer-cli/src/main.rs`
- **Seen in**:
  - `crates/redteamer-adapters/src/openai.rs:43-47`: `pub fn with_base_url(api_key: impl Into<String>, model: impl Into<String>, base_url: impl Into<String>)`
  - `crates/redteamer-adapters/src/anthropic.rs:41-45`: `pub fn with_base_url(api_key: impl Into<String>, model: impl Into<String>, base_url: impl Into<String>)`
  - `crates/redteamer-cli/src/main.rs:563`: `OpenAiAdapter::with_base_url(url, api_key, model)?`
  - `crates/redteamer-cli/src/main.rs:593`: `AnthropicAdapter::with_base_url(url, api_key, model)?`
  - `crates/redteamer-cli/src/main.rs:606`: `OpenAiAdapter::with_base_url(target, api_key, model)?`
- **Impact**: Because all 3 arguments are `impl Into<String>`, the compiler did not catch that `main.rs` passes `(url, api_key, model)` instead of `(api_key, model, url)`. Passing `--base-url` or `--target http://...` sends HTTP requests to `"{model}/chat/completions"` with `Authorization: Bearer {url}` and sends `api_key` as the model name!

### 2. High Bug `G8`: Why `evaluate_verdict` Returned `Partial` on `LLM02`, `LLM03`, `LLM05`–`LLM09`
- **Seen in**: `crates/redteamer-probes/src/lib.rs:221-241`:
  ```rust
  let has_refusal_detector = outcomes
      .iter()
      .any(|o| o.polarity == DetectorPolarity::Refusal);
  if !has_refusal_detector {
      // checks default_refusals: "i cannot", "i can't", "cannot comply", ...
  }
  ```
- **Impact**: Every template that defines an inline `refusal_match` rule (`LLM02`, `LLM03`, `LLM05`, `LLM06`, `LLM07`, `LLM08`, `LLM09`) produces a `DetectionOutcome` with `polarity: DetectorPolarity::Refusal`. When the model refuses with standard phrasing (e.g. `"I cannot comply with that request..."` from `CliMockAdapter` or a real LLM) that doesn't match the narrow domain needle (e.g. `"i cannot recommend"` in `LLM03`), `matched` is `false`, **and** `has_refusal_detector` is `true`, so `default_refusals` is skipped and the response is misclassified as `Verdict::Partial`!
- **Fix**: Remove the `if !has_refusal_detector` gate so baseline refusal phrases are always checked when no vulnerable rule matched.

### 3. High Bug `G16`: CLI `--system-prompt` Overwritten by Template `system_prompt`
- **Seen in**: `crates/redteamer-probes/src/lib.rs:284-287` and `crates/redteamer-adapters/src/{openai,anthropic,ollama}.rs`.
- **Impact**: `TemplateProbe::run` sets `opts.system_prompt = self.template.effective_system_prompt()`, which is `Some(...)` for nearly all built-in templates. The adapters use `opts.system_prompt.or(self.default_options.system_prompt)`, silently discarding the user's `--system-prompt` CLI flag.
- **Fix**: When both `self.default_options.system_prompt` and `opts.system_prompt` are `Some`, concatenate them (`"{default_sp}\n\n{probe_sp}"`) so the user's custom system prompt is tested alongside any probe instructions/canaries.

### 4. High Gap `G1`: Per-Probe Concurrency Multiplier (`P × C`) & Per-Probe Progress
- **Seen in**: `crates/redteamer-orchestrator/src/scan.rs:51-70` and `crates/redteamer-probes/src/lib.rs:302`.
- **Impact**: `ScanConfig::execute` spawns all 10 probes concurrently, and each probe creates its own `Semaphore::new(concurrency)`, allowing `10 × 8 = 80` concurrent requests instead of 8. Also, `on_record_progress` only fires when an entire probe finishes.
- **Fix**: Wrap `self.target` in `ScanConfig::execute` with a `ThrottledAdapter` holding a single shared `Arc<Semaphore>` of size `self.concurrency` and an `AtomicUsize` that fires `progress_callback` on every completed request.

### 5. Verified Provider Metadata & Tool-Calling Wire Schemas (`G3`, `G10`, `G17`)
- **Token usage metadata keys already stored in `AttackRecord.metadata`**:
  - `OpenAiAdapter` (`openai.rs:137-140, 216-221`): `{"prompt_tokens": u64, "completion_tokens": u64}`
  - `AnthropicAdapter` (`anthropic.rs:120-126, 237-240`): `{"stop_reason": ..., "usage": {"input_tokens": u64, "output_tokens": u64}}`
  - `OllamaAdapter` (`ollama.rs:205-208`): `{"prompt_eval_count": Option<u64>, "eval_count": Option<u64>}`
- **Tool-calling schemas verified against official docs**:
  - **OpenAI**: Request `tools: [{"type": "function", "function": {"name", "description", "parameters"}}]` -> Response `choices[0].message.tool_calls: [{"id", "type": "function", "function": {"name", "arguments": "<json string>"}}]`. Also check `choices[0].message.refusal: Option<String>` when `content` is `null`.
  - **Anthropic**: Request `tools: [{"name", "description", "input_schema"}]` -> Response `content` blocks with `{"type": "tool_use", "id", "name", "input": {...}}`. Also update default model in `main.rs:591` from retired `"claude-3-5-sonnet-20241022"` to `"claude-sonnet-4-5"`.
  - **Ollama**: Request `tools: [{"type": "function", "function": {"name", "description", "parameters"}}]` -> Response `message.tool_calls: [{"function": {"name", "arguments": {...}}}]`.

### 6. Zero-Dependency Decisions for Offline Builds (`G7`, `G11`)
- **Mock HTTP Server (`G11`)**: User confirmed using a small hand-written `tokio::net::TcpListener` mock server in tests instead of adding `wiremock`. Enabling `"net"` and `"io-util"` on `tokio` in root `Cargo.toml` line 37 works 100% offline with the existing `Cargo.lock`.
- **Base64 Response Normalizer (`G7`)**: `base64 = "0.22"` is already in root `Cargo.toml` line 40; adding `base64.workspace = true` to `crates/redteamer-detectors/Cargo.toml` works 100% offline.

---

## 4B. Deep Technical Lessons & Call-Site Map from Phases 0–5

1. **Exact Struct-Literal Call Sites (for Phases 6 & 8 Schema Additions)**:
   - **`AdapterResponse`** is constructed by struct literal in 8 places:
     1. `crates/redteamer-adapters/src/openai.rs:134`
     2. `crates/redteamer-adapters/src/anthropic.rs:234`
     3. `crates/redteamer-adapters/src/ollama.rs:202`
     4. `crates/redteamer-cli/src/main.rs:534` (`CliMockAdapter`)
     5. `crates/redteamer-orchestrator/tests/integration_test.rs:49`
     6. `crates/redteamer-detectors/src/llm_judge.rs:216`
     7. `crates/redteamer-probes/src/lib.rs:538`
     8. `crates/redteamer-probes/src/lib.rs:655`
   - **`GenerationOptions`** is constructed by struct literal in:
     1. `crates/redteamer-cli/src/main.rs:218`
     2. `crates/redteamer-probes/src/lib.rs:284` (uses `..GenerationOptions::default()`)
   - **`AttackRecord`** is constructed in `AttackRecord::new` (`crates/redteamer-core/src/types.rs:469`).
   - **`ReportContext`** is constructed in:
     1. `crates/redteamer-reporters/src/owasp_mapper.rs` (`build_report_context`)
     2. `crates/redteamer-reporters/src/lib.rs` (`all_six_exporters_render_valid_artifacts` golden test)

2. **`ort = "=2.0.0-rc.13"` API Nuances (`crates/redteamer-detectors/src/semantic.rs`)**:
   - `ort::session::Session::run` requires `&mut self`, so `Session` is wrapped in `std::sync::Mutex<Session>` inside `SemanticDetector` (`semantic.rs:24, 101`).
   - Input tensors are created via `ort::value::Tensor::from_array(([1usize, seq_len], vec))` and passed via `ort::inputs!["input_ids" => ids_tensor, "attention_mask" => mask_tensor, "token_type_ids" => type_tensor]`.
   - Output tensors are extracted via `outputs[0].try_extract_tensor::<f32>()`, which returns `(&Shape, &[f32])` (a shape + flat slice tuple, not `ndarray`).

3. **CVSS v4.0 & Detector Attribution Nuances (`crates/redteamer-reporters/src/owasp_mapper.rs`)**:
   - `CvssVector::severity(&self)` returns `Option<Severity>`, and `Severity` implements `fmt::Display` (`crates/redteamer-core/src/types.rs`).
   - `CvssLlmComputer::compute_for_mutation(category, mutation_type)` emits `AC:L` for direct attacks (`MutationType::None | MutationType::ContextFraming`) and `AC:H` for evasion/multi-turn mutations (`CharacterSubstitution`, `WordSubstitution`, `EncodingWrapper`, `ConversationalEscalation`, `TokenPerturbation`, `LanguageSwitch`).
   - `findings_from_records` attributes a finding's `detector_name` by selecting `.find(|d| d.matched && d.polarity == DetectorPolarity::Vulnerable)` (never `detections.first()`, which could be an unmatched rule or a `Refusal` rule).

4. **Zero Ignored Tests Policy & Clippy Strictness**:
   - All unit tests, integration tests, and doc-tests must run with **0 ignored** (`44 passed; 0 failed; 0 ignored`). Use ` ```no_run ` rather than ` ```ignore ` for doc-tests that require async runtimes/targets (`crates/redteamer-orchestrator/src/scan.rs:120`).
   - `Command::Scan(Box<ScanArgs>)` in `crates/redteamer-cli/src/main.rs:38` is boxed to satisfy `clippy::large_enum_variant` when adding new CLI flags to `ScanArgs`.

5. **CLI Exit Code Contract (`crates/redteamer-cli/src/main.rs:178-208`)**:
   - `0`: Scan or diff completed cleanly without breaching thresholds.
   - `1`: Runtime/config error, failed `health_check()`, or 100% of records resulted in `Verdict::Error`.
   - `2`: Security gate breached (`--fail-on <low|medium|high|critical>` or `diff --fail-on-regression`).

6. **Supply-Chain Audit (`deny.toml`)**:
   - `cargo deny --offline check` validates licenses (`MIT OR Apache-2.0`), bans, sources, and advisories against the offline `Cargo.lock`. Any dependency or feature changes in `Cargo.toml` must pass `cargo deny --offline check`.

---

## 5. How to Resume in the New Session

When the user starts a new session and asks you to read `SESSION_HANDOFF.md`:
1. Read `SESSION_HANDOFF.md`, `improve.md`, and `project-progress.md` in full (100% of lines).
2. Confirm with the user that you are ready to start **Phase 6** from `improve.md` (or begin Phase 6 immediately if instructed to proceed):
   - **Phase 6**: Critical Bug Fixes (`G15`, `G16`), Global Concurrency & Per-Request Progress (`G1`, `G5`), Error Reasons on `AttackRecord` (`G2`), Typed Token/Latency Telemetry & Deterministic Ordering (`G3`, `G4`), and Workspace Formatting (`G18`).
   - **Phase 7**: Verdict Refusal Fix & Deduplication (`G6`, `G8`), Response Normalizer (`G7`), Labeled Evaluation Suite (`G8`), and `SemanticDetector` CLI (`G9`).
   - **Phase 8**: Protocol-Level Tool Calling (`G10`), Anthropic Model & OpenAI Refusal Updates (`G17`), and Hand-Written `TcpListener` Adapter HTTP Tests (`G11`).
   - **Phase 9**: Live JSONL Streaming (`--stream-jsonl`) & Checkpoint Resume (`--resume`) (`G12`).
   - **Phase 10**: Adaptive Multi-Turn Attacker Loop (`G13`).
   - **Phase 11**: CLI Binary Integration Tests (`CARGO_BIN_EXE_llm-redteamer`), Finding-Level Diff, and `v0.3.0` Release Polish (`G14`).
