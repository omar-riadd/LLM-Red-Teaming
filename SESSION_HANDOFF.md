# SESSION_HANDOFF.md — Complete Project Knowledge & Execution Guide

> **For the incoming agent in the new session:** Read this file, `project-progress.md`, and `improve.md` in full (100% of lines, never skip or guess) before taking any action.

---

## 1. Mandatory Session & Global Rules (MUST FOLLOW AT ALL TIMES)

1. **Read files in full**: If you need to read any file, read **100% of its lines** (using `StartLine`/`EndLine` chunks only if >800 lines, until every line is read). Never skim or assume contents.
2. **Maintain `project-progress.md`**: After finishing each task/phase, update `/home/omar/Projects/LLM-Red-Teaming/project-progress.md` to record real state.
3. **Always verify before saying "done"**: Run real build, test, and lint commands (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --offline -- -D warnings`, `cargo test --workspace --offline`, `cargo deny --offline check`) and report real results. Never invent APIs, flags, or library functions.
4. **Touch 3+ files / add dependencies / destructive commands**: Write a plan first and wait for approval. Small verified edits can be executed directly.
5. **Ask before destructive/external actions**: Ask before deleting files, adding external crates, or running destructive git operations (`git reset --hard`, force push, `rm -rf`).
6. **Offline workspace constraint**: The Rust workspace is built and tested offline (`--offline`) against pinned dependencies in `Cargo.lock`. Do not add new external crates requiring network access unless explicitly approved.
7. **Sandbox & Git Operations**:
   - The command sandbox has full read/write access to the workspace, but `.git/` is write-protected in standard sandbox mode.
   - Run preparation, cargo builds, tests, clippy, and formatting with `BypassSandbox: false`.
   - Git operations that write to `.git/` (`git add`, `git commit`, `git tag`) must use `BypassSandbox: true` keeping identical `toolAction` and `toolSummary`.

---

## 2. Current Repository & Git Status

- **Workspace Path**: `/home/omar/Projects/LLM-Red-Teaming`
- **GitHub Repository**: `https://github.com/omar-riadd/LLM-Red-Teaming`
- **Branch**: `main`
- **Latest Commit**: `9b3ab42` — `docs: document MCP attacks, DPO export, and streaming in README and CHANGELOG`
- **Previous Significant Commits**:
  - `205eabe` — `feat(adapters): implement Phase 25 real-time streaming early termination (FG3)`
  - `6e7832a` — `feat(reporters): implement Phase 24 automated DPO / RLHF dataset exporter (FG5)`
  - `1527cf1` — `feat(adapters): implement Phase 23 Model Context Protocol (MCP) server attacks (FG4)`
  - `490f338` — `feat(detectors): expand default semantic reference corpus to 52 calibrated phrases`
  - `c29e5d1` — `feat(azure): send Ocp-Apim-Subscription-Key header for native APIM gateway support`
  - `29e7b84` — `fix(azure): support APIM enterprise routing, pre-specified api-version, and Entra ID bearer auth`
  - `44b5a64` — `feat: implement Phase 20 ephemeral canaries and dynamic CVSS calibration`
  - `347b2c9` — `feat: implement Phase 19 template adaptive coverage and semantic embedding optimization`
  - `20833a6` — `feat: complete v0.4 (Phases 12-18) enterprise red-teaming release`
  - `69a8e78` — `chore: release v0.3.0 and finalize all Phase 6-11 improvements`
- **Current Verification Baseline**:
  - `cargo test --workspace --offline` → **99 passed; 0 failed; 0 ignored** across all 8 crates, 8 integration test suites, and 4 doc-tests.
  - `cargo clippy --workspace --all-targets --offline -- -D warnings` → **0 warnings, 0 errors**.
  - `cargo fmt --all -- --check` → **100% clean**.
  - `cargo deny --offline check` → **advisories ok, bans ok, licenses ok, sources ok**.
- **Working Tree**: Clean (`git status` reports nothing to commit, working tree clean).

---

## 3. Workspace Architecture & Crate Map (8 Crates + 11 Embedded OWASP Templates)

```
LLM-Red-Teaming/
├── crates/
│   ├── redteamer-core/          # Core traits, error model (retryable), CVSS v4.0 engine
│   ├── redteamer-adapters/      # 6 LLM target adapters, client builder, CA bundle TLS loader
│   ├── redteamer-payload/       # 14 mutators, template schema, ephemeral canary generator
│   ├── redteamer-detectors/     # Regex, canary, Aho-Corasick, LLM judge, ONNX semantic detector
│   ├── redteamer-probes/        # Unified TemplateProbe, 11 embedded OWASP templates, PAIR loop
│   ├── redteamer-orchestrator/  # Scan engine, global semaphore, streaming JSONL, resume
│   ├── redteamer-reporters/     # Dynamic CVSS v4.0 calibrator (entropy+depth), 6 exporters
│   └── redteamer-cli/           # Modular CLI (scan, diff, list, health), integration tests
├── templates/                   # 11 OWASP Top 10 for LLM (2025) YAML attack templates
├── models/all-MiniLM-L6-v2/     # Vendored ONNX tokenizer & download helper for offline semantic eval
├── sbom/                        # CycloneDX 1.5 JSON Software Bill of Materials (233 components)
├── fuzz/                        # AFL / libFuzzer targets (YAML loader & mutation engine)
└── .github/workflows/           # CI workflow (clippy, test, fmt, deny, sbom) & Release workflow
```

### Detailed Crate Functionality

1. **`crates/redteamer-core`**:
   - `traits/adapter.rs`: `Role`, `ChatMessage`, `GenerationOptions` (system prompt, tools, temperature, max_tokens, seed), `AdapterInfo`, `AdapterResponse` (`text`, `tool_calls`, `completed`, `metadata`), and `TargetAdapter` trait.
   - `error.rs`: `RedTeamerError` and `RedTeamerError::is_retryable()`, which recognizes transient failures: HTTP 408, 429, 500, 502, 503, 504, 529, timeouts, connection resets, and `"overloaded"`.
   - `types.rs`: `OwaspCategory` (`LLM01`–`LLM10`), `Severity`, `CvssVector` (full CVSS v4.0 macrovector lookup table), `Verdict` (`Resistant`, `Partial`, `Vulnerable`, `Error`), `Finding`, `SeverityBreakdown`, `ProbeSummary`, `MutationType` (14 variants), `AttackRecord`, `DetectorPolarity`, and `DetectionOutcome`.

2. **`crates/redteamer-adapters`**:
   - `lib.rs`: Exposes `build_http_client` and `build_http_client_with_timeout`. Bypasses proxy for loopback targets (`localhost`, `127.0.0.1`, `[::1]`). Reads custom PEM CA certificates from `REDTEAMER_CA_BUNDLE` or `SSL_CERT_FILE`. Enables `danger_accept_invalid_certs(true)` when `REDTEAMER_INSECURE_TLS=1`. Contains `RateLimiter` and `create_adapter` factory.
   - `azure.rs` (`AzureOpenAiAdapter`): Deployment-based routing (`build_azure_url`), dual authentication headers (`api-key` and `Ocp-Apim-Subscription-Key`), Entra ID JWT Bearer token auto-detection, and safety refusal interception for HTTP 400 (`ResponsibleAIPolicyViolation`, `content_filter`) and HTTP 200 (`finish_reason == "content_filter"`).
   - `gemini.rs` (`GeminiAdapter`): REST API (v1beta `generateContent`), `systemInstruction`, usage metadata extraction, safety refusal interception on HTTP 400/403 and HTTP 200 (`finishReason == "SAFETY" | "BLOCKLIST" | "PROHIBITED_CONTENT"` or `promptFeedback.blockReason`).
   - `openai.rs` (`OpenAiAdapter`) & `openai_compatible.rs` (`OpenAiCompatibleAdapter`): Handles `/v1/chat/completions`, function tool-calling, specialized presets for OpenRouter (`HTTP-Referer`, `X-Title`) and vLLM, and intercepts `content_filter` / `content_policy_violation`.
   - `anthropic.rs` (`AnthropicAdapter`): Messages API (`/v1/messages`), top-level system prompt, `claude-sonnet-4-5` default, `tool_use` blocks, and HTTP 400 safety block interception.
   - `ollama.rs` (`OllamaAdapter`): Local inference adapter, 300s timeout, `/api/chat` with tool calls, `/api/tags` health check.
   - `mcp.rs` (`McpAdapter`): Model Context Protocol server adapter (HTTP and Stdio transports, JSON-RPC 2.0 handshake, tool discovery via `tools/list`, tool execution via `tools/call`, tool error/refusal interception, and canary extraction).

3. **`crates/redteamer-payload`**:
   - `mutation.rs`: 14 mutation types: `Identity`, `Base64`, `Rot13`, `Hex`, `Reverse`, `WhitespaceNoise`, `CaseRandomize`, `RoleplayPrefix`, `SystemOverridePrefix`, `BenignSuffix`, `Leetspeak`, `Homoglyph`, `ZeroWidth`, and `JsonTaskWrap`.
   - `template.rs`: `ProbeTemplate` schema. Implements `generate_ephemeral_canary(session_id)` generating format `CANARY-{session_prefix}-{probe_hash}-{uuid}`, and `effective_system_prompt_with_canary(...)`.

4. **`crates/redteamer-detectors`**:
   - `normalize.rs`: `normalize_response_variants` de-obfuscates zero-width characters, Base64 (>=16 chars), Hex (>=16 chars), and ROT13 before detector evaluation.
   - `semantic.rs`: `SemanticDetector` using vendored ONNX model (`all-MiniLM-L6-v2`) via `ort = "=2.0.0-rc.13"`. Precomputes 52 reference embeddings at construction time for a 30x evaluation speedup.
   - `llm_judge.rs`: Secondary LLM evaluator parsing JSON verdict fences.
   - `string_match.rs`, `regex_set.rs`, `lib.rs` (`CanaryDetector`, `LengthDetector`).

5. **`crates/redteamer-probes`**:
   - `lib.rs`: Embeds all 11 YAML templates. Implements `TemplateProbe`, PAIR (Prompt Automatic Iterative Refinement) tree search attacker loop with candidate scoring (`score_candidate`), temperature ramping, and early exit on `Verdict::Vulnerable`.
   - `evaluate_verdict`: Polarity-aware verdict calculation. Checked against `default_refusals` (expanded to include cloud safety phrases: `blocked by`, `content management policy`, `content filtering policy`, `content safety policy`, `responsible ai`, `safety filters`).

6. **`crates/redteamer-orchestrator`**:
   - `scan.rs`: Global semaphore concurrency cap, per-request progress updates via `AtomicUsize`, live streaming JSONL records (`--stream-jsonl`), and checkpoint resume (`--resume`).

7. **`crates/redteamer-reporters`**:
   - `owasp_mapper.rs`: Dynamic CVSS v4.0 calculator incorporating Shannon byte entropy ($H \ge 4.5$ bits escalates `VC:H` / `SC:H`) and conversational turn depth ($T \ge 2$ escalates `AC:H`).
   - 7 Exporters: JSON, JSONL, CSV, Markdown, interactive HTML (Handlebars dark-mode dashboard with SVG severity chart and sortable tables), SARIF 2.1.0, and DPO / ShareGPT alignment dataset exporter.

8. **`crates/redteamer-cli`**:
   - Modular CLI structure in `src/cmd/` (`scan.rs`, `diff.rs`, `list.rs`, `health.rs`) and `adapter_builder.rs`. Integration tests in `tests/cli_integration.rs`.

---

## 4. Key Architectural Insights & Lessons Learned

1. **Cloud Safety Filter Status Codes vs. Red-Team Verdict**:
   - Azure OpenAI returns HTTP 400 on `ResponsibleAIPolicyViolation`.
   - Gemini returns HTTP 400/403 or HTTP 200 with `finishReason: "SAFETY"`.
   - OpenAI returns HTTP 400 on `content_filter`.
   - Without adapter-level interception, returning `Err(RedTeamerError::Adapter)` causes the probe runner to record `Verdict::Error`.
   - Intercepting these safety signals and converting them to `Ok(AdapterResponse)` with refusal text ensures that `evaluate_verdict` correctly scores them as `Verdict::Resistant` (the security control successfully defended the model).

2. **Enterprise Gateway Authentication**:
   - Direct Azure OpenAI endpoints (`*.openai.azure.com`) accept `api-key`.
   - Azure API Management gateways (`*.azure-api.net`) require `Ocp-Apim-Subscription-Key`.
   - `AzureOpenAiAdapter` sends both headers simultaneously, working transparently across both direct resources and enterprise proxies. Entra ID JWT Bearer tokens are automatically recognized and routed via `Authorization: Bearer <token>`.

3. **Enterprise TLS & Corporate Proxies**:
   - Standard sandbox mode runs offline. In live deployments with corporate SSL inspection, setting `REDTEAMER_CA_BUNDLE=/path/to/corporate-ca.pem` (or `SSL_CERT_FILE`) loads the custom root certificates into reqwest's rustls engine.
   - Setting `REDTEAMER_INSECURE_TLS=1` enables lab testing against internal self-signed test environments.

4. **Ephemeral Canaries vs. Static Tokens**:
   - Static canaries in templates cause cross-session bleed and false positives.
   - `ProbeTemplate::generate_ephemeral_canary(session_id)` generates a cryptographic UUID-derived token unique to that exact scan session, dynamically injected into system prompts and evaluated by `CanaryDetector`.

5. **Dynamic CVSS v4.0 Threat Calibration**:
   - Single-turn prompt injections with low complexity are scored with `AC:L`.
   - Multi-turn conversational escalations requiring >=2 turns are scored with `AC:H` (higher attack complexity).
   - Responses exfiltrating high-entropy strings ($H \ge 4.5$ bits per byte, characteristic of API keys, hashes, or base64 secrets) escalate confidentiality impact to `VC:H` / `SC:H`.

---

## 5. Verification Commands (Run to Confirm State)

To re-verify the complete workspace offline in the new session, run:

```bash
# 1. Format check
cargo fmt --all -- --check

# 2. Strict static analysis (all warnings denied)
cargo clippy --workspace --all-targets --offline -- -D warnings

# 3. Comprehensive test suite (96 tests)
cargo test --workspace --offline

# 4. Dependency and license audit
cargo deny --offline check

# 5. End-to-end CLI scan against built-in mock target
cargo run --offline -p redteamer-cli -- scan --target mock --format markdown
```

---

## 6. How to Resume in the New Session
 
When starting the next session:
1. Confirm that `git status` is clean and all 99 workspace tests pass.
2. Review `improve.md` section 4 for the future roadmap proposals:
   - **`FG1`**: Executive Document Exporters (DOCX / PDF).
   - **`FG2`**: Distributed Worker Pool / Multi-IP Rotation.
   - **`FG3`**: Real-Time Streaming Early Termination (Completed in Phase 25).
   - **`FG4`**: Model Context Protocol (MCP) Server Attacks (Completed in Phase 23).
   - **`FG5`**: Automated DPO / RLHF Dataset Exporter (Completed in Phase 24).
3. Ask the user which feature or roadmap item they would like to pursue next, or proceed with tagging and releasing `v0.5.0`.
