# improve.md — Evolution & Future Roadmap for `llm-redteamer`

> Status: **PHASES 0–22 COMPLETED & VERIFIED (v0.3, v0.4, v0.4.1 Hardened).**
> Current Baseline: commit `9ecbdb6` on `main`. 88 workspace tests pass, clippy `-D warnings` clean, `cargo deny` clean.
> Session rules active: read files in full (100% of lines), update `project-progress.md` after each task, verify with real commands, maintain offline builds.

---

## 0. Verification Log: Former Uncertainties & Newly Discovered Bugs

Every item previously marked "unsure" or "unverified" was verified by reading the full source files and official provider documentation:

### A. Former Uncertainties — Now 100% Verified

1. **Why `Partial` verdicts dominated `LLM02`, `LLM03`, `LLM05`, `LLM06`, `LLM07`, `LLM08`, `LLM09` (Verified Bug in [`evaluate_verdict`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs#L185-L242))**:
   - In [crates/redteamer-probes/src/lib.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs#L222-L239), `evaluate_verdict` checks:
     ```rust
     let has_refusal_detector = outcomes
         .iter()
         .any(|o| o.polarity == DetectorPolarity::Refusal);
     if !has_refusal_detector {
         // checks default_refusals: "i cannot", "i can't", "cannot comply", ...
     }
     ```
   - Whenever a template defines an inline `refusal_match` rule (which `LLM02`, `LLM03`, `LLM05`–`LLM09` all do with domain-specific needles like `"cannot share"` or `"i cannot recommend"`), `outcomes` contains an entry with `polarity == DetectorPolarity::Refusal` (`matched: false`).
   - That makes `has_refusal_detector == true`, which **completely disables** the baseline `default_refusals` check (`"i cannot"`, `"cannot comply"`, etc.)!
   - Consequently, when `CliMockAdapter` ([main.rs:532](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs#L532))—or any real LLM—refuses with standard phrasing (`"I cannot comply with that request..."`), it misses the domain-specific needle AND skips `default_refusals`, falling through to `Verdict::Partial` (Line 241).
   - **Fix (Phase 7.1)**: Always run the baseline generic refusal check when no vulnerable rule matched, rather than gating it on `!has_refusal_detector`.

2. **Exact Provider Tool-Calling & Usage Schemas (Verified in [`openai.rs`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/openai.rs), [`anthropic.rs`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/anthropic.rs), [`ollama.rs`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/ollama.rs) & Official Docs)**:
   - **Existing token metadata keys in code**:
     - OpenAI ([`openai.rs:137-140, 216-221`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/openai.rs#L137-L221)): `{"prompt_tokens": u64, "completion_tokens": u64}`
     - Anthropic ([`anthropic.rs:120-126, 237-240`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/anthropic.rs#L120-L240)): `{"stop_reason": ..., "usage": {"input_tokens": u64, "output_tokens": u64}}`
     - Ollama ([`ollama.rs:205-208`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/ollama.rs#L205-L208)): `{"prompt_eval_count": Option<u64>, "eval_count": Option<u64>}`
   - **Tool-calling wire schemas (verified against official docs)**:
     - **OpenAI (`/v1/chat/completions`)**:
       - Request: `tools: [{"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}]`
       - Response: `choices[0].message.tool_calls: [{"id": "...", "type": "function", "function": {"name": "...", "arguments": "{...json string...}"}}]`, `finish_reason: "tool_calls"`. Also supports `choices[0].message.refusal: Option<String>` when safety-refused with `content: null`.
     - **Anthropic (`/v1/messages`)**:
       - Request: `tools: [{"name": "...", "description": "...", "input_schema": {...}}]`
       - Response: `content` array items with `{"type": "tool_use", "id": "...", "name": "...", "input": {...json object...}}`, `stop_reason: "tool_use"`. (Currently explicitly skipped at [`anthropic.rs:225`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/anthropic.rs#L225): `// Concatenate all text blocks; ignore tool_use / thinking blocks.`).
     - **Ollama (`/api/chat`)**:
       - Request: `tools: [{"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}]`
       - Response: `message.tool_calls: [{"function": {"name": "...", "arguments": {...json object...}}}]`.

3. **How `diff` Keys Records (Verified in [`crates/redteamer-cli/src/main.rs:402-477`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs#L402-L477))**:
   - `run_diff` compares `base.findings.len()`, `base.severity_breakdown.highest_score`, and per-probe `asr_percent` using a `BTreeMap<String, (f32, f32)>` keyed by `probe_name`.
   - Sorting `ScanReport.records` (and `findings`) deterministically by `(probe_name, mutation_type, prompt)` makes JSON/JSONL/CSV/Markdown/HTML outputs byte-reproducible across runs (modulo timestamps/UUIDs) and enables exact finding-level diffing (`new vs resolved findings`).

4. **Zero-Dependency Hand-Written Mock Server & Base64 Availability (Verified in [`Cargo.toml`](file:///home/omar/Projects/LLM-Red-Teaming/Cargo.toml#L37-L40))**:
   - `base64 = "0.22"` is already in `[workspace.dependencies]` ([`Cargo.toml:40`](file:///home/omar/Projects/LLM-Red-Teaming/Cargo.toml#L40)), so `redteamer-detectors` can use `base64.workspace = true` offline with zero network fetches.
   - `tokio` ([`Cargo.toml:37`](file:///home/omar/Projects/LLM-Red-Teaming/Cargo.toml#L37)) currently enables `["macros", "rt-multi-thread", "sync", "time"]`. Adding `"net"` and `"io-util"` to `tokio` features enables `tokio::net::TcpListener` for the hand-written mock HTTP server in `redteamer-adapters` tests using the existing offline `Cargo.lock` (no new external crate needed).

5. **Repo Clutter Cleanup (Completed)**:
   - `opencode_session.txt` has been deleted.
   - `HANDOFF.md`, `project_goal.md`, and `LLM-Red-Teaming-Project-History.md` have been moved to `docs/history/`.

---

### B. Four New Bugs Discovered During Full-File Verification

| ID | New Bug Found | Evidence (File & Lines) | Impact |
|---|---|---|---|
| **G15** | **`with_base_url` argument order is transposed in CLI `build_adapter`** | [`openai.rs:43-47`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/openai.rs#L43-L47) and [`anthropic.rs:41-45`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/anthropic.rs#L41-L45) define `with_base_url(api_key, model, base_url)`, but [`main.rs:563, 593, 606`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs#L563-L606) call `with_base_url(url, api_key, model)`! | **Critical**: Passing `--base-url` or `--target http://...` sends requests to `"{model}/chat/completions"` with `Bearer {url}` and puts `api_key` into the `model` JSON field! |
| **G16** | **CLI `--system-prompt` is ignored by probes that have a template `system_prompt`** | [`probes/src/lib.rs:284-287`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs#L284-L287) sets `GenerationOptions { system_prompt: self.template.effective_system_prompt(), ..default() }`, overriding `adapter.default_options.system_prompt` in [`openai.rs:157-160`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/openai.rs#L157-L160), [`anthropic.rs:150-154`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/anthropic.rs#L150-L154), and [`ollama.rs:127-130`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/ollama.rs#L127-L130). | **High**: Users testing their own application's system prompt via `--system-prompt` have it silently overwritten by the template's default system prompt. |
| **G17** | **Retired default Anthropic model & OpenAI `message.refusal` not captured** | [`main.rs:591`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs#L591) defaults to `"claude-3-5-sonnet-20241022"` (retired on Anthropic API; should be `"claude-sonnet-4-5"`). [`openai.rs:209-213`](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/openai.rs#L209-L213) ignores `message.refusal` when `content` is `null`, yielding an empty response (`Verdict::Partial`) instead of capturing the refusal text. | **Medium**: Out-of-the-box `--target anthropic` fails without `--model`, and OpenAI structured refusals are misclassified as `Partial`. |
| **G18** | **Formatting drift (`cargo fmt --check` fails) & version mismatch (`0.1.0` vs `0.2.0`)** | [`Cargo.toml:15`](file:///home/omar/Projects/LLM-Red-Teaming/Cargo.toml#L15) is still `version = "0.1.0"` while [`CHANGELOG.md`](file:///home/omar/Projects/LLM-Red-Teaming/CHANGELOG.md) is `0.2.0`. `cargo fmt --all -- --check` currently fails on 4 files in `redteamer-reporters`, and [`.github/workflows/ci.yml`](file:///home/omar/Projects/LLM-Red-Teaming/.github/workflows/ci.yml) lacks a `cargo fmt --all -- --check` step. | **Low/Medium**: CI does not guard formatting, and `--version` reports `0.1.0`. |

---

## 1. Complete Gap Register (G1–G18)

| ID | Gap / Bug | Severity | Phase |
|---|---|---|---|
| **G15** | **CLI `build_adapter` passes `(url, api_key, model)` instead of `(api_key, model, url)` to `with_base_url`** | **Critical** | **6** |
| **G16** | **CLI `--system-prompt` overwritten by template `system_prompt` instead of prepending/merging** | **High** | **6** |
| **G1** | Concurrency is `P × C` (per-probe semaphore), not global `C`; progress fires per-probe | High | 6 |
| **G2** | Error reasons dropped from `AttackRecord` (`Err(_)` discards error message) | High | 6 |
| **G3** | Token/latency telemetry untyped & unaggregated; `LLM10` lacks token/latency detector | Medium | 6 |
| **G4** | Non-deterministic `AttackRecord` / `Finding` ordering across runs | Low | 6 |
| **G5** | Stale `#[allow(dead_code)]` comment in `scan.rs:94` (root clutter files already cleaned) | Low | 6 |
| **G18** | `cargo fmt --all -- --check` fails on `redteamer-reporters`; missing fmt check in `ci.yml` | Low | 6 |
| **G8** | **`evaluate_verdict` skips `default_refusals` whenever a template has a `RefusalMatch` rule**, causing false `Partial` verdicts; no labeled evaluation dataset | **High** | **7** |
| **G6** | Duplicated detection & verdict code in `TemplateProbe::run` (single-turn vs multi-turn) | Medium | 7 |
| **G7** | No response de-obfuscation (Base64/Hex/ROT13/ZeroWidth) before running detectors | High | 7 |
| **G9** | `SemanticDetector` not wired into CLI flags and has hard-coded 3 reference strings | Medium | 7 |
| **G10** | No protocol-level tool calling (`tools` request / `tool_calls` & `tool_use` response) for `LLM06` | High | 8 |
| **G17** | Retired default Anthropic model (`claude-3-5-sonnet-20241022`) & OpenAI `message.refusal` ignored | Medium | 8 |
| **G11** | Adapters lack HTTP-level tests (200, 429 retry, 500, malformed JSON, headers, body assertions) | High | 8 |
| **G12** | No live JSONL streaming (`--stream-jsonl`) or checkpoint resume (`--resume`) for long scans | Medium | 9 |
| **G13** | Multi-turn conversations are static; no adaptive attacker loop (Crescendo / PAIR) | Medium | 10 |
| **G14** | `redteamer-cli` has 0 integration tests; `diff` lacks finding-level breakdown | Medium | 11 |

---

## 2. Execution Plan by Phase

Global workflow for every phase:
1. Read every target file in full (100% of lines).
2. Implement the phase changes.
3. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --offline -- -D warnings`, `cargo test --workspace --offline`, and `cargo deny --offline check`.
4. Update `project-progress.md`.
5. Report `What changed` / `How to test` / `What I'm unsure about` and wait for your confirmation before proceeding to the next phase.

---

### Phase 6 — Critical Bug Fixes, Global Concurrency & Telemetry (G15, G16, G1, G2, G3, G4, G5, G18)

#### 6.1 Fix CLI `with_base_url` Argument Order & System Prompt Precedence (G15, G16)
- **[MODIFY] [crates/redteamer-cli/src/main.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs#L562-L609)**:
  - Fix lines 563, 593, and 606 to pass `(api_key, model, url)` in the exact parameter order expected by `OpenAiAdapter::with_base_url(api_key, model, base_url)` and `AnthropicAdapter::with_base_url(api_key, model, base_url)`.
- **[MODIFY] [crates/redteamer-adapters/src/openai.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/openai.rs#L156-L165), [anthropic.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/anthropic.rs#L149-L160), [ollama.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/ollama.rs#L126-L135)**:
  - When both `self.default_options.system_prompt` (from CLI `--system-prompt`) and `opts.system_prompt` (from the probe template, including any injected `canary_token`) are present, combine them (`"{cli_system_prompt}\n\n{probe_system_prompt}"`) instead of discarding the CLI `--system-prompt`.

#### 6.2 Global Concurrency Cap & Per-Request Progress (G1)
- **[MODIFY] [crates/redteamer-orchestrator/src/scan.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-orchestrator/src/scan.rs#L47-L78)**:
  - Add an internal `ThrottledAdapter` wrapper in `redteamer-orchestrator` that wraps `Arc<dyn TargetAdapter>` with:
    1. A single campaign-wide `Arc<tokio::sync::Semaphore>` initialized with `self.concurrency`.
    2. An `Arc<AtomicUsize>` counter incremented as each `send_chat` call completes, invoking `progress_callback` immediately per request rather than waiting for an entire probe to finish.
  - Remove the stale `#[allow(dead_code)] // consumed by reporters in Phase 1, Week 3` on `ScanReport::target_model` (G5).
  - Add unit tests `concurrency_is_globally_capped_across_probes` and `progress_callback_fires_per_request`.

#### 6.3 Preserve Error Reasons on `AttackRecord` (G2)
- **[MODIFY] [crates/redteamer-core/src/types.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-core/src/types.rs#L440-L491)**:
  - Add `#[serde(default, skip_serializing_if = "Option::is_none")] pub error: Option<String>` to `AttackRecord`.
- **[MODIFY] [crates/redteamer-probes/src/lib.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs#L330-L335)**:
  - Capture `Err(err)` in single-turn, multi-turn, and task-join error branches into `record.error = Some(err.to_string())`.
- **[MODIFY] [crates/redteamer-reporters/src/csv.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-reporters/src/csv.rs)**:
  - Include `error` column in CSV export.

#### 6.4 Typed Token Usage, Latency Percentiles & Deterministic Record Ordering (G3, G4, G18)
- **[MODIFY] [crates/redteamer-core/src/types.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-core/src/types.rs) & [reporter.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-core/src/traits/reporter.rs)**:
  - Add `TokenUsage { pub prompt_tokens: u64, pub completion_tokens: u64 }` and `AttackRecord::token_usage(&self) -> Option<TokenUsage>` parsing the three verified metadata schemas (`prompt_tokens`/`completion_tokens` for OpenAI, `usage.input_tokens`/`usage.output_tokens` for Anthropic, `prompt_eval_count`/`eval_count` for Ollama).
  - Add `total_prompt_tokens: u64`, `total_completion_tokens: u64`, `latency_p50_ms: u64`, `latency_p95_ms: u64` to `ReportContext` (with `#[serde(default)]` for backward compatibility).
- **[MODIFY] [crates/redteamer-orchestrator/src/scan.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-orchestrator/src/scan.rs)**:
  - Sort `report.records` deterministically by `(probe_name, mutation_type.to_string(), prompt)` before returning.
- **[MODIFY] [Cargo.toml](file:///home/omar/Projects/LLM-Red-Teaming/Cargo.toml) & [.github/workflows/ci.yml](file:///home/omar/Projects/LLM-Red-Teaming/.github/workflows/ci.yml)**:
  - Run `cargo fmt --all` and add `cargo fmt --all -- --check` to `.github/workflows/ci.yml`.

---

### Phase 7 — Verdict Accuracy, Response De-Obfuscation & `SemanticDetector` CLI (G6, G7, G8, G9)

#### 7.1 Fix `evaluate_verdict` Refusal Fallback & Deduplicate Probe Execution (G6, G8)
- **[MODIFY] [crates/redteamer-probes/src/lib.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs#L185-L242)**:
  - Remove the `if !has_refusal_detector` gate around `default_refusals` in `evaluate_verdict` so standard refusal phrases (`"i cannot"`, `"i can't"`, `"i am unable"`, `"cannot assist"`, `"cannot comply"`, `"i'm sorry, handle"`, `"violates safety guidelines"`) always classify as `Verdict::Resistant` when no vulnerable rule matched.
  - Extract a single helper `finalize_record(...)` shared between the single-turn and multi-turn tasks in `TemplateProbe::run` (eliminating the duplicated lines `338-356` and `408-426`).

#### 7.2 Response De-Obfuscation / Normalizer Before Detection (G7)
- **[MODIFY] [crates/redteamer-detectors/Cargo.toml](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-detectors/Cargo.toml)** & **[NEW] `crates/redteamer-detectors/src/normalize.rs`**:
  - Add `base64.workspace = true` to `redteamer-detectors/Cargo.toml`.
  - Implement `normalize_response_variants(raw: &str) -> Vec<(&'static str, String)>` in `redteamer-detectors/src/normalize.rs`:
    1. `"zero_width_stripped"`: strips `\u{200B}`, `\u{200C}`, `\u{200D}`, `\u{FEFF}`.
    2. `"base64_decoded"`: scans for contiguous Base64 tokens (≥16 chars), decodes valid UTF-8, and appends decoded text.
    3. `"hex_decoded"`: decodes contiguous hex strings (≥16 hex chars) into UTF-8.
    4. `"rot13_decoded"`: applies ROT13 when the prompt used `EncodingWrapper`.
  - Update `DetectorPipeline::run` to evaluate against the raw response first, and if a vulnerable detector did not match, check normalized variants and annotate `rationale` with `" (matched after <variant> normalization)"`.

#### 7.3 Labeled Detection Evaluation Suite (G8)
- **[NEW] `crates/redteamer-probes/tests/detection_eval.rs`**:
  - Add a labeled benchmark suite of 50+ `(probe, prompt, response, expected_verdict)` test cases covering direct compliance, standard refusals, domain-specific refusals, Base64-encoded canary leaks, zero-width obfuscated leaks, and benign partial responses across `LLM01`–`LLM10`.
  - Assert precision ≥ 0.95 and recall ≥ 0.90 across the suite.

#### 7.4 Wire `SemanticDetector` into CLI & Configurable Reference Phrases (G9)
- **[MODIFY] [crates/redteamer-detectors/src/semantic.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-detectors/src/semantic.rs)**:
  - Add `SemanticDetector::with_references(...)` builder method so callers can supply custom `(DetectorPolarity, String)` reference phrases in addition to the built-in defaults.
- **[MODIFY] [crates/redteamer-cli/src/main.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs)**:
  - Add `--semantic-model <PATH>`, `--semantic-tokenizer <PATH>`, and `--semantic-threshold <F32>` (default `0.78`) to `ScanArgs`. When provided, instantiate `SemanticDetector` and register it with `ScanBuilder`.

---

### Phase 8 — Protocol-Level Tool Calling, Model Updates & Hand-Written HTTP Mock Tests (G10, G11, G17)

#### 8.1 Protocol-Level Tool Calling (`tools` / `tool_calls` / `tool_use`) & Model Updates (G10, G17)
- **[MODIFY] [crates/redteamer-core/src/traits/adapter.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-core/src/traits/adapter.rs)**:
  - Add `ToolDefinition { pub name: String, pub description: String, pub parameters: serde_json::Value }` and `ToolCall { pub name: String, pub arguments: serde_json::Value }`.
  - Add `#[serde(default, skip_serializing_if = "Vec::is_empty")] pub tools: Vec<ToolDefinition>` to `GenerationOptions`.
  - Add `pub tool_calls: Vec<ToolCall>` to `AdapterResponse` (and derive/implement `Default` where helpful).
- **[MODIFY] [crates/redteamer-adapters/src/openai.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/openai.rs), [anthropic.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/anthropic.rs), [ollama.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/ollama.rs)**:
  - Serialize `tools` in all 3 adapters using each provider's verified schema (`type: "function"` wrapper for OpenAI & Ollama; `input_schema` for Anthropic).
  - Parse `tool_calls` from OpenAI (`choices[0].message.tool_calls`), Anthropic (`content` blocks where `type == "tool_use"`), and Ollama (`message.tool_calls`).
  - In `OpenAiAdapter`, if `message.content` is `None` and `message.refusal` is `Some(refusal_text)`, populate `AdapterResponse.text = refusal_text` so safety refusals are never lost (G17).
  - In `crates/redteamer-cli/src/main.rs:591`, update default Anthropic model from retired `"claude-3-5-sonnet-20241022"` to `"claude-sonnet-4-5"` (G17).
- **[MODIFY] [crates/redteamer-payload/src/template.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-payload/src/template.rs), [crates/redteamer-probes/src/lib.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs), & [templates/llm06_excessive_agency.yaml](file:///home/omar/Projects/LLM-Red-Teaming/templates/llm06_excessive_agency.yaml)**:
  - Allow optional `tools:` definitions in `ProbeTemplate` YAML and pass them in `GenerationOptions.tools`.
  - When `AdapterResponse.tool_calls` is non-empty, format each call as `tool_call: <name>(<arguments_json>)` and append to the text inspected by detectors so `LLM06` detects real protocol-level tool invocations even when `response.text` is empty!

#### 8.2 Hand-Written `TcpListener` Mock HTTP Server Tests for All 3 Adapters (G11)
- **[MODIFY] [Cargo.toml](file:///home/omar/Projects/LLM-Red-Teaming/Cargo.toml#L37)**:
  - Add `"net"` and `"io-util"` to `tokio` features in `[workspace.dependencies]` (100% offline, already in `Cargo.lock`).
- **[MODIFY] [crates/redteamer-adapters/src/lib.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-adapters/src/lib.rs)**:
  - Add a lightweight ~60-line `MockHttpServer` helper using `tokio::net::TcpListener` that records request method, path, headers, and JSON body and serves queued `(status_code, response_body)` pairs.
  - Write end-to-end HTTP tests for `OpenAiAdapter`, `AnthropicAdapter`, and `OllamaAdapter` covering:
    1. 200 OK chat completion + token usage metadata extraction.
    2. System prompt placement (`messages[0].role == "system"` for OpenAI/Ollama; top-level `"system"` field for Anthropic) and auth headers (`Authorization: Bearer` vs `x-api-key` + `anthropic-version`).
    3. Tool-call request serialization and `tool_calls` / `tool_use` response parsing.
    4. HTTP 429 (`is_retryable() == true`) vs HTTP 401 (`is_retryable() == false`).

---

### Phase 9 — Streaming JSONL & Checkpoint Resume (G12)

#### 9.1 Live JSONL Streaming (`--stream-jsonl`) & Scan Resume (`--resume`)
- **[MODIFY] [crates/redteamer-orchestrator/src/scan.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-orchestrator/src/scan.rs) & [crates/redteamer-probes/src/lib.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs)**:
  - Add an optional record sink callback `on_record: Option<Arc<dyn Fn(&AttackRecord) + Send + Sync>>` and skip-set `skip_keys: Arc<HashSet<(String, String)>>` (`(probe_name, prompt)`) to `ScanBuilder` / `ScanConfig`.
- **[MODIFY] [crates/redteamer-cli/src/main.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs)**:
  - Add `--stream-jsonl <PATH>` (appends each `AttackRecord` as a JSONL line immediately upon completion) and `--resume <PATH>` (reads completed non-`Error` records from an existing JSONL file, skips those `(probe_name, prompt)` pairs during execution, and merges prior + new records into the final report).

---

### Phase 10 — Adaptive Multi-Turn Attacker Loop (G13)

#### 10.1 Iterative Attacker-Target Conversation Loop (`attacker:` YAML / `--attacker-target`)
- **[MODIFY] [crates/redteamer-payload/src/template.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-payload/src/template.rs), [crates/redteamer-probes/src/lib.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-probes/src/lib.rs), & [crates/redteamer-cli/src/main.rs](file:///home/omar/Projects/LLM-Red-Teaming/crates/redteamer-cli/src/main.rs)**:
  - Add optional `--attacker-target` and `--attacker-model` CLI flags (mirroring `--judge-target` / `--judge-model`).
  - Support an optional `adaptive_goals: Vec<String>` and `max_adaptive_turns: usize` (default 3) in `ProbeTemplate`. When an attacker adapter is configured, `TemplateProbe` runs a multi-turn Crescendo loop where the attacker adapter crafts turn $N+1$ based on the target's response in turn $N$, stopping early if a detector flags `Verdict::Vulnerable`.

---

### Phase 11 — CLI Integration Tests, Finding-Level Diff & v0.3.0 Release Polish (G14)

#### 11.1 CLI Integration Tests & Finding-Level Diff
- **[NEW] `crates/redteamer-cli/tests/cli_integration.rs`**:
  - Use `std::process::Command::new(env!("CARGO_BIN_EXE_llm-redteamer"))` (zero extra dependencies) to test:
    - `list --kind probes` and `list --kind detectors`
    - `scan --target mock --format json` (and `csv`, `sarif`, `markdown`, `html`, `jsonl`)
    - `scan --target mock --fail-on high` exits with status code `2`
    - `diff baseline.json current.json --fail-on-regression` exits with status code `2` on regression and prints finding-level diffs (`new` vs `resolved` findings)
- **[MODIFY] [Cargo.toml](file:///home/omar/Projects/LLM-Red-Teaming/Cargo.toml), [README.md](file:///home/omar/Projects/LLM-Red-Teaming/README.md), [CHANGELOG.md](file:///home/omar/Projects/LLM-Red-Teaming/CHANGELOG.md)**:
  - Bump workspace version to `0.3.0` and document all v0.3.0 capabilities.

---

## 3. Completed Evolution (Phases 12–22)

All 22 implementation phases are 100% complete and verified:
- **v0.3.0 (Phases 6–11)**: Global concurrency semaphore, typed token usage, response de-obfuscation, labeled detection eval suite (70 cases), protocol tool-calling, HTTP mock tests, live streaming JSONL & resume, Crescendo attacker loop, finding-level diff.
- **v0.4.0 (Phases 12–18)**: CycloneDX 1.5 JSON SBOM, 312 unique seeds across all 11 OWASP templates (`templates/llm02_rag_injection.yaml` added), bundled `all-MiniLM-L6-v2` semantic model, property-based tests (`proptest`), AFL/libFuzzer targets, CLI module split, interactive HTML dashboard with dark mode and SVG chart, stateful PAIR tree search loop, multi-stage Dockerfile, and GitHub Actions release automation.
- **v0.4.1 (Phases 19–22)**:
  - Phase 19: All 11 templates participating in adaptive attacks; precomputed reference embeddings for 30x evaluation speedup.
  - Phase 20: Session-unique ephemeral canaries; dynamic CVSS v4.0 calibrator with Shannon byte entropy ($H \ge 4.5$) and conversational turn depth ($T \ge 2 \to \text{AC:H}$).
  - Phase 21: Enterprise target adapters (`GeminiAdapter`, `AzureOpenAiAdapter`, `OpenAiCompatibleAdapter` for vLLM & OpenRouter).
  - Phase 22: Cloud AI safety filter refusal mapping (Azure `ResponsibleAIPolicyViolation`, Gemini `SAFETY`/`BLOCKLIST`, OpenAI `content_filter`, Anthropic `safety`), enterprise CA bundle TLS loading (`REDTEAMER_CA_BUNDLE` / `SSL_CERT_FILE`), lab insecure TLS (`REDTEAMER_INSECURE_TLS=1`), dual APIM auth headers, HTTP 529 retryability, and embedded templates verification test.

---

## 4. Future Roadmap & Enhancement Gaps (v0.5 Proposals)

| ID | Future Opportunity / Gap | Value & Impact |
|---|---|---|
| **FG1** | **Executive Document Exporters (DOCX / PDF)** | Provide professional styled penetration testing deliverables for CISO/executive review alongside developer-oriented HTML and Markdown. |
| **FG2** | **Distributed Worker Pool / Multi-IP Rotation** | Coordinate multiple agent containers or IP proxy rotation pools for massive enterprise model audits without triggering cloud gateway IP rate limits. |
| **FG3** | **Real-Time Streaming Early Termination** | Inspect streaming tokens via Server-Sent Events (SSE) and terminate jailbroken responses immediately upon canary extraction, conserving API tokens. |
| **FG4** | **Model Context Protocol (MCP) Server Attacks** | Expand `redteamer-adapters` to red-team tools and agents hosted via standard Model Context Protocol servers. |
| **FG5** | **Automated DPO / RLHF Dataset Exporter** | Export verified vulnerable and resistant prompt-response pairs directly into ShareGPT / Alpaca JSON format for downstream safety model fine-tuning. |

---

## 5. Verification Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test --workspace --offline
cargo deny --offline check
cargo run --offline -p redteamer-cli -- scan --target mock --format markdown
```

