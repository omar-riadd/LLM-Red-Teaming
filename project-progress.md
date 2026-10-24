# LLM-Red-Teaming Project Progress

> Tracked continuously after each task per session rules.

## Session Rules Active
1. Read every file in full (never skip lines).
2. Update `project-progress.md` after finishing each task.
3. Always verify with real commands/tests; never assume.
4. Wait for user confirmation after each task before moving to the next.
5. Follow all rules for the entire session.

---

## Phase 0: Git Checkpoint & Cleanup
- [x] **0.1** Read `HANDOFF.md` in full (327/327 lines read).
- [x] **0.2** Read `crates/redteamer-reporters/src/html.rs` (76/76 lines), `crates/redteamer-reporters/src/templates/report.html.hbs` (44/44 lines), and `crates/redteamer-reporters/templates/report.html.hbs` (2/2 lines) in full.
- [x] **0.3** Restore `CHANGELOG.md` from `HEAD` and remove the accidental `// crates/redteamer-reporters/src/templates/report.html.hbs` line from `crates/redteamer-reporters/src/templates/report.html.hbs`.
- [x] **0.4** Delete orphan `crates/redteamer-reporters/templates/report.html.hbs` and commit Phase 7.5 checkpoint on `main`.

## Phase 1: Core & Adapter v2 Redesign (`redteamer-core` + `redteamer-adapters`)
- [x] **1.1** Upgrade `redteamer-core/src/traits/adapter.rs` & `error.rs` (`Role`, `ChatMessage`, `GenerationOptions`, `send_chat`, `RedTeamerError::is_retryable`).
- [x] **1.2** Upgrade `OllamaAdapter` (`/api/chat`, system prompt, options), `OpenAiAdapter` (system prompt, chat history, rate limit builder), and `AnthropicAdapter` (system prompt, configurable `max_tokens`, chat history, rate limit builder).
- [x] **1.3** Upgrade `redteamer-core/src/traits/detector.rs` & `types.rs` (`DetectorPolarity`, owned `DetectContext`, `Finding` fields, `SeverityBreakdown`, `ProbeSummary`).
- [x] **1.4** Upgrade `redteamer-core/src/traits/reporter.rs` (`ReportContext` and `ReportExporter::export(&self, ctx: &ReportContext)`).

## Phase 2: Unified `TemplateProbe`, Canary Injection, Multi-Turn & Evasion Mutators (`redteamer-payload` + `redteamer-probes`)
- [x] **2.1** Upgrade `Mutation` & `MutationPipeline` (`mutation_type()`, actionable decoding wrappers for `Base64`/`Rot13`/`Reverse`, add `Leetspeak`, `Homoglyph`, `ZeroWidth`, `JsonTaskWrap`, add `iter_tagged` while keeping `iter` for benchmarks).
- [x] **2.2** Upgrade `ProbeTemplate` (fix duplicate `Identity` generation, add `system_prompt`, `canary_token`, `conversations`, `scope`, and inline `rules`).
- [x] **2.3** Implement unified `TemplateProbe` in `crates/redteamer-probes/src/lib.rs`, delete redundant `llm{01,02,06,07,10}.rs`, load embedded OWASP templates in `all_probes()`, add `probes_from_dir`, and make all doc-tests runnable (`0 ignored`).

## Phase 3: Complete All 10 OWASP LLM 2025 YAML Templates & Real Detectors (`templates/` + `redteamer-detectors`)
- [x] **3.1** Upgrade existing 5 YAML templates (`llm01`, `llm02`, `llm06`, `llm07`, `llm10`) and author 5 new YAML templates (`llm03`, `llm04`, `llm05`, `llm08`, `llm09`) with inline detector rules, canaries, and multi-turn conversations.
- [x] **3.2** Wire real `LlmJudgeDetector` in `crates/redteamer-detectors/src/llm_judge.rs` (using `Arc<dyn TargetAdapter>` and `serde_json`).
- [x] **3.3** Wire real `SemanticDetector` in `crates/redteamer-detectors/src/semantic.rs` (using `Mutex<Session>` and `ort-2.0.0-rc.13` `Tensor::from_array` / `try_extract_tensor::<f32>()`).
- [x] **3.4** Expose `builtin_detector_descriptions()` and wire `llm-redteamer list --kind detectors`.

## Phase 4: Reporters, Dynamic CVSS & CLI Overhaul (`redteamer-reporters` + `redteamer-cli`)
- [x] **4.1** Dynamic CVSS v4.0 (`compute_for_mutation`) and `ReportContext` builder in `owasp_mapper.rs`.
- [x] **4.2** Upgrade all 6 exporters (`JsonExporter`, `JsonlExporter`, `CsvExporter`, `HtmlExporter`, `MarkdownExporter`, `SarifExporter`) on `ReportContext`.
- [x] **4.3** Overhaul `crates/redteamer-cli/src/main.rs` (stderr logs, health check pre-flight, non-zero exit codes on total failure or `--fail-on`, new CLI flags, `diff` subcommand).

## Phase 5: Project Hygiene, Licensing, Golden Tests & Final Verification
- [x] **5.1** Add `LICENSE-MIT` and `LICENSE-APACHE`, update `Cargo.toml` repository URL, and add MSRV `1.88` to `.github/workflows/ci.yml`.
- [x] **5.2** Update `README.md` and `CHANGELOG.md`.
- [x] **5.3** Full verification (`cargo test`, `cargo clippy`, `cargo deny`, and live CLI tests across all subcommands and formats).
- [x] **5.4** Commit v2 redesign to `main` (`719af8e`) and re-verify full workspace test suite (`44 passed; 0 failed; 0 ignored`) and end-to-end CLI scan (`243 records`, all 10 OWASP LLM 2025 probes, `0 errors`).
- [x] **5.5** Audit workspace, verify all uncertainties, clean repo root (`opencode_session.txt` deleted, history docs moved to `docs/history/`), and write `improve.md` + `SESSION_HANDOFF.md`.

---

## v0.3 Improvement Plan (`improve.md` & `SESSION_HANDOFF.md`)

### Phase 6: Critical Bug Fixes, Global Concurrency & Telemetry (`G15`, `G16`, `G1`, `G2`, `G3`, `G4`, `G5`, `G18`)
- [x] **6.1** Fix CLI `with_base_url` argument order (`G15`) and combine CLI `--system-prompt` with template `system_prompt` (`G16`).
- [x] **6.2** Implement campaign-wide `Semaphore` concurrency cap and per-request progress updates in `redteamer-orchestrator` (`G1`, `G5`).
- [x] **6.3** Preserve adapter error reasons on `AttackRecord.error` and surface in CSV/JSON/Markdown/HTML (`G2`).
- [x] **6.4** Add typed `TokenUsage`, `ReportContext` token/latency (`p50`/`p95`) stats (`G3`), deterministic record sorting (`G4`), and `cargo fmt --all -- --check` in CI (`G18`).

### Phase 7: Verdict Accuracy, Response De-Obfuscation & `SemanticDetector` CLI (`G6`, `G7`, `G8`, `G9`)
- [x] **7.1** Fix `evaluate_verdict` so baseline refusal phrases always run when no vulnerable detector matched (`G8`), and deduplicate `TemplateProbe::run` record finalization (`G6`).
- [x] **7.2** Implement response de-obfuscation normalizer (zero-width, Base64, Hex, ROT13) in `redteamer-detectors` (`G7`).
- [x] **7.3** Add labeled detection evaluation test suite (`50+` cases across `LLM01`–`LLM10`) asserting precision/recall (`G8`).
- [x] **7.4** Add configurable reference phrases to `SemanticDetector` and wire `--semantic-model`, `--semantic-tokenizer`, and `--semantic-threshold` in `redteamer-cli` (`G9`).

### Phase 8: Protocol-Level Tool Calling, Model Updates & Hand-Written HTTP Mock Tests (`G10`, `G11`, `G17`)
- [x] **8.1** Add `ToolDefinition` and `ToolCall`, wire provider tool schemas in OpenAI/Anthropic/Ollama (`G10`), capture OpenAI `message.refusal` and update Anthropic default model to `claude-sonnet-4-5` (`G17`), and update `llm06_excessive_agency.yaml`.
- [x] **8.2** Enable `tokio` `"net"`/`"io-util"` features and test all 3 adapters against a hand-written `tokio::net::TcpListener` mock server (`G11`).

### Phase 9: Live JSONL Streaming & Checkpoint Resume (`G12`)
- [x] **9.1** Add `--stream-jsonl <PATH>` and `--resume <PATH>` for long-scan crash recovery (`G12`).

### Phase 10: Adaptive Multi-Turn Attacker Loop (`G13`)
- [x] **10.1** Add `--attacker-target` / `--attacker-model` and multi-turn Crescendo attacker loop (`G13`).

### Phase 11: CLI Integration Tests, Finding-Level Diff & v0.3.0 Release (`G14`)
- [x] **11.1** Add binary integration tests (`CARGO_BIN_EXE_llm-redteamer`), finding-level `diff` output, and bump workspace to `0.3.0` (`G14`).

---

## Post-Phase Verification & Rating

- [x] **V.1** Full workspace check: `cargo fmt --check` ✅, `cargo clippy -D warnings` ✅ (0 warnings), `cargo test` ✅ (63 tests, 0 failed), `cargo bench --no-run` ✅, `cargo deny --offline check` ✅ (advisories/bans/licenses/sources ok).
- [x] **V.2** Wrote honest project assessment artifact (`project-rating.md`): overall **6.7/10**. Top gaps: uncommitted code, thin seed corpus, stateless attacker, no SBOM, no bundled semantic model.

**Status**: All v0.3.0 changes verified and working. **44 files modified + 7 untracked on `main` — uncommitted.** Next action: `git commit && git tag v0.3.0`.

---

## v0.4 Improvement Plan (`PLAN_v0.4.md`)

- [x] **P.1** Wrote `PLAN_v0.4.md` covering all 14 gaps (GA1–GA14) across 7 phases (12–18). Awaiting user approval to execute.

### Phase 12 — Git Commit, Tag v0.3.0, SBOM, CI Hardening (GA1, GA4, GA12)
- [x] **12.1** `git add -A && git commit && git tag v0.3.0` (commit `69a8e78`, tag `v0.3.0`).
- [x] **12.2** `cargo-cyclonedx` v0.5.9 installed; generated CycloneDX 1.5 JSON SBOM with 233 components at `sbom/llm-redteamer-v0.3.0.cdx.json`; added `sbom` job to `.github/workflows/ci.yml`.

### Phase 13 — Expanded Seeds, RAG Injection, Multilingual Probes (GA2, GA8, GA9)
- [x] **13.1** Expanded all 10 templates to 30+ seeds each (corpus expanded from 60 to 312 unique seeds).
- [x] **13.2** Created new `templates/llm02_rag_injection.yaml` (30 seeds, canary, embedded in binary).
- [x] **13.3** Added multilingual seeds (Arabic, Simplified Chinese, French) and refusal needles to `llm01`, `llm02`, `llm07`.
- [x] **13.4** Updated `detection_eval.rs` with 15 new labeled cases (70 cases total) asserting 100% precision and recall; updated `cli_integration.rs` counts. Full scan record count grew from 243 to 1,361.

### Phase 14 — Bundled `all-MiniLM-L6-v2` Semantic Model (GA3)
- [x] **14.1** Download + vendor model to `models/all-MiniLM-L6-v2/` (`model.onnx` ignored, `tokenizer.json` and `download_model.sh` tracked).
- [x] **14.2** Added `--semantic-model=builtin` shorthand in `crates/redteamer-cli/src/main.rs` with automatic tokenizer path resolution.
- [x] **14.3** Documented semantic detection in `README.md` with usage instructions, download helper script, and custom model guidelines.
- [x] **14.4** Added offline semantic detector integration test `crates/redteamer-detectors/tests/semantic_offline.rs` verifying refusal and jailbreak detection against bundled ONNX weights.

### Phase 15 — Property Tests, Fuzz Targets, Judge Eval (GA5, GA11, GA14)
- [x] **15.1** Added `proptest` dev-dependency and 4 property tests in `crates/redteamer-payload/tests/mutation_proptest.rs` (non-empty iteration, non-empty mutation invariants, Base64 roundtrip, reverse inversion).
- [x] **15.2** Added `fuzz/` directory with `probe_yaml_loader` and `mutation_pipeline` fuzz targets (workspace excluded).
- [x] **15.3** Added mock HTTP server integration test in `crates/redteamer-detectors/tests/judge_mock.rs` validating `LlmJudgeDetector` accuracy, refusal detection, markdown/embedded JSON parsing, and malformed JSON error handling.

### Phase 16 — CLI Module Split & Interactive HTML Report (GA6, GA10)
- [x] **16.1** Split `crates/redteamer-cli/src/main.rs` into `adapter_builder.rs` and modular subcommands `cmd/{mod, scan, diff, list, health}.rs`; reduced `main.rs` to ~80 lines; added `-o` short flag and dedicated `health` subcommand.
- [x] **16.2** Upgraded `report.html.hbs` with dark mode toggle, client-side persistence, SVG severity doughnut chart, sortable findings and ASR tables, and collapsible `<details>` sections; added `crates/redteamer-reporters/tests/html_snapshot.rs`.

### Phase 17 — Stateful PAIR Attacker Loop (GA7)
- [x] **17.1** Implemented stateful PAIR (Prompt Automatic Iterative Refinement) tree search attacker loop with candidate branch generation (N=3 default, configurable via `--attacker-branches` or YAML `pair_branches`), temperature ramping, polarity-aware candidate scoring (`score_candidate`), winning branch commit to conversation history, and early exit on `Verdict::Vulnerable`. Added integration tests in `crates/redteamer-probes/tests/pair_loop.rs`. All 75 workspace tests passing.

### Phase 18 — Docker Image & Release Automation (GA13)
- [x] **18.1** Created multi-stage `Dockerfile` (`rust:bookworm` builder + `debian:bookworm-slim` runtime, non-root user `redteamer`, CA certificates), `.dockerignore`, and validated `docker-compose.yml` for local red-teaming against an Ollama service. Documented in `README.md`.
- [x] **18.2** Created `.github/workflows/release.yml` automating cross-platform binary builds (Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64), SHA-256 checksums, CycloneDX 1.5 JSON SBOM attachment, GitHub Releases on `v*` tags, and multi-arch Docker publishing to GitHub Container Registry (`ghcr.io`).

---

## v0.4 Completion Status
All 7 phases (12–18) and all 14 improvement gaps (`GA1`–`GA14`) from `PLAN_v0.4.md` are 100% completed, verified with real tests, audited with `cargo deny`, and documented.

---

## Phase 19 — Template Adaptive Coverage & Semantic Embedding Optimization
- [x] **19.1** Added `adaptive_goals` and `max_adaptive_turns: 3` to all remaining 9 probe templates (`llm02_secrets`, `llm02_rag_injection`, `llm03`, `llm04`, `llm05`, `llm06`, `llm08`, `llm09`, `llm10`). 100% of the 11 OWASP templates now participate in PAIR tree search adaptive attacks.
- [x] **19.2** Optimized `SemanticDetector` to precompute reference embeddings at instantiation (`SemanticDetector::new()` / `with_references()`), eliminating 30+ redundant ONNX inferences per evaluated response and yielding a ~30x evaluation speedup.
- [x] **19.3** Expanded `default_semantic_references()` to 52 calibrated phrases (50+ phrases) covering all 10 OWASP categories and nuanced refusal phrasing per roadmap specification.
- [x] **19.4** Wired `with_override` in `CvssLlmComputer` to CVSS v4.0 Threat Metrics (`/E:A` for $\ge 1.1$, `/E:P` for $\le 0.9$) and added unit test. Total workspace test count: 76 passing.

---

## Phase 20 — Ephemeral Canaries & Dynamic CVSS Calibration
- [x] **20.1** Implemented session-unique ephemeral canary generator (`generate_ephemeral_canary` and `effective_system_prompt_with_canary`) in `redteamer-payload` and `redteamer-probes`, eliminating cross-session false positives while automatically propagating dynamic tokens to system prompts, single-turn attacks, multi-turn conversations, and PAIR tree search evaluations.
- [x] **20.2** Implemented Shannon byte entropy calculator (`shannon_entropy`) and dynamic CVSS v4.0 calibrator in `owasp_mapper.rs`, automatically incorporating conversational turn depth (`AC:H` for multi-turn chains $\ge 2$) and escalating confidentiality impact (`VC:H` and `SC:H`) when high-entropy cryptographic material, tokens, or dense secrets ($H \ge 4.5$) are exfiltrated.
- [x] **20.3** Added unit tests for ephemeral canary generation, canary extraction in mock targets, Shannon entropy discrimination, and dynamic CVSS vector calibration.

---

## Phase 21 — Enterprise Target Adapter Expansion
- [x] **21.1** Implemented `GeminiAdapter` in `crates/redteamer-adapters/src/gemini.rs` for Google Gemini REST API (v1beta `generateContent`), with `contents` role mapping (`user` / `model`), `systemInstruction`, usage metadata extraction, and safety finish reason tracking.
- [x] **21.2** Implemented `AzureOpenAiAdapter` in `crates/redteamer-adapters/src/azure.rs` supporting deployment-based endpoint routing (`{endpoint}/openai/deployments/{deployment}/chat/completions`) and `api-key` header authentication.
- [x] **21.3** Implemented `OpenAiCompatibleAdapter` in `crates/redteamer-adapters/src/openai_compatible.rs` for generic inference gateways (vLLM, OpenRouter, TGI, LocalAI), with specialized presets `for_openrouter` (`HTTP-Referer` and `X-Title` attribution) and `for_vllm`.
- [x] **21.4** Integrated `gemini`, `azure`, `openrouter`, and `vllm` target providers into `create_adapter` factory and CLI `adapter_builder.rs`. Documented provider environment variables in `README.md`.
- [x] **21.5** Added mock HTTP server integration tests in `crates/redteamer-adapters/src/lib.rs` verifying wire protocols, header formats, and payload parsing for Gemini, Azure, and OpenRouter/vLLM.
- [x] **21.6** Full verification: all 84 workspace tests passing, 0 clippy warnings, zero cargo deny advisories.

---

## Phase 22 — Verification & Enterprise Hardening: Cloud Safety Refusals, TLS CA Roots & Template Validation
- [x] **22.1** Intercepted Cloud Safety Filter Violations across all adapters to prevent safety interventions from classifying as `Verdict::Error`:
  - **Azure OpenAI**: Intercepts HTTP 400 with `ResponsibleAIPolicyViolation`, `content_filter`, or `content management policy` and HTTP 200 with `finish_reason == "content_filter"`.
  - **Google Gemini**: Intercepts HTTP 400/403 safety errors and HTTP 200 with `finish_reason == "SAFETY" | "BLOCKLIST" | "PROHIBITED_CONTENT"` or `promptFeedback.blockReason`.
  - **OpenAI & OpenAI-Compatible**: Intercepts HTTP 400 `content_filter` / `content_policy_violation` and HTTP 200 `finish_reason == "content_filter"`.
  - **Anthropic**: Intercepts HTTP 400 safety blocks.
  - **Probes**: Expanded `evaluate_verdict`'s `default_refusals` to include `blocked by`, `content management policy`, `content filtering policy`, `content safety policy`, and `responsible ai` so all safety blocks reliably resolve to `Verdict::Resistant`.
- [x] **22.2** Enterprise Proxy & Custom TLS CA Root Support:
  - Centralized `build_http_client` and `build_http_client_with_timeout` across all adapters in `crates/redteamer-adapters/src/lib.rs`.
  - Supports loading custom corporate PEM CA bundles via `REDTEAMER_CA_BUNDLE` or `SSL_CERT_FILE`.
  - Supports isolated lab environments via `REDTEAMER_INSECURE_TLS=1` (`danger_accept_invalid_certs(true)`).
  - Preserved automatic proxy bypass for loopback targets (`127.0.0.1`, `localhost`, `[::1]`).
- [x] **22.3** Universal Azure & APIM Gateway Authentication:
  - `AzureOpenAiAdapter` sends both `api-key` and `Ocp-Apim-Subscription-Key` headers simultaneously, enabling frictionless authentication against direct Azure OpenAI endpoints and corporate APIM gateways.
  - Added Entra ID Bearer token auto-detection for JWT tokens.
- [x] **22.4** Core Error Retryability:
  - Extended `RedTeamerError::is_retryable()` to recognize `http 529` and `overloaded`.
- [x] **22.5** Built-in Template Compilation & Schema Verification:
  - Added unit test `all_eleven_embedded_owasp_templates_compile_and_validate` verifying all 11 built-in templates compile and meet schema, category, description, and inline rule requirements.
- [x] **22.6** Full Workspace Verification & Git Commit:
  - All 88 tests passing (`cargo test --workspace --offline`), 0 clippy warnings (`cargo clippy --workspace --all-targets --offline -- -D warnings`), `cargo fmt --all -- --check` clean, `cargo deny --offline check` clean (`advisories ok, bans ok, licenses ok, sources ok`).
---

## Phase 23 — Model Context Protocol (MCP) Server Attacks (FG4)
- [x] **23.1** Implemented `McpAdapter` in `crates/redteamer-adapters/src/mcp.rs` for Model Context Protocol servers:
  - Supports HTTP JSON-RPC 2.0 endpoints (`http://.../mcp`) and local Stdio subprocess commands (`stdio://...` / `mcp://...`).
  - Implements full MCP 2024-11-05 handshake: `initialize` client negotiation and `notifications/initialized`.
  - Discovers exposed tools via `tools/list` and caches schemas as `ToolDefinition`.
  - Executes targeted tool attacks via `tools/call`, mapping prompt arguments and extracting text/data content blocks.
  - Intercepts `isError: true` and JSON-RPC errors, returning structured execution and refusal text for detector evaluations.
- [x] **23.2** Wired `McpAdapter` into `crates/redteamer-adapters/src/lib.rs` and `create_adapter` factory under `AdapterConfig::Mcp`.
- [x] **23.3** Wired `--target mcp` and `--target stdio://<cmd>` in `crates/redteamer-cli/src/adapter_builder.rs`.
- [x] **23.4** Added mock HTTP JSON-RPC integration test suite in `crates/redteamer-adapters/tests/mcp_mock.rs` testing `initialize`, `tools/list`, `tools/call` with canary extraction, tool error handling, and `health_check`.
- [x] **23.5** Full Workspace Verification:
  - All 92 tests passing (`cargo test --workspace --offline` across 8 crates and 8 test suites).
  - Clippy `-D warnings` 100% clean (0 warnings, 0 errors).
  - `cargo fmt --all -- --check` 100% clean.
  - `cargo deny --offline check` clean (advisories ok, bans ok, licenses ok, sources ok).

---

## Phase 24 — Automated DPO / RLHF Dataset Exporter (FG5)
- [x] **24.1** Added `ReportFormat::Dpo` to `redteamer-core/src/traits/reporter.rs`.
- [x] **24.2** Implemented `DpoExporter`, `DpoPair`, `ShareGptDpoEntry`, and category-tailored gold-standard refusal fallbacks in `crates/redteamer-reporters/src/dpo.rs`:
  - Automatically matches vulnerable elicited responses (`rejected`) with observed resistant responses from the model (`chosen`), or falls back to category-calibrated refusal phrasing.
  - Generates deduplicated DPO preference pairs and ShareGPT conversation objects.
  - Added unit tests for category refusal coverage, vulnerable/resistant pairing, findings fallback, and ShareGPT structure.
- [x] **24.3** Registered `dpo` in `crates/redteamer-reporters/src/lib.rs` and updated `exporter_factory`.
- [x] **24.4** Added `--format dpo` and `--export-dpo <PATH>` companion export flag in `crates/redteamer-cli/src/cmd/scan.rs`.
- [x] **24.5** Updated CLI integration test suite in `crates/redteamer-cli/tests/cli_integration.rs` covering all 7 export formats and `--export-dpo`.
- [x] **24.6** Full Workspace Verification:
  - All 96 tests passing (`cargo test --workspace --offline` across all 8 crates, 8 integration suites, and 4 doc-tests).
  - Clippy `-D warnings` 100% clean (0 warnings, 0 errors).
  - `cargo fmt --all -- --check` 100% clean.
  - `cargo deny --offline check` clean (advisories ok, bans ok, licenses ok, sources ok).

---

## Phase 25 — Real-Time Streaming Early Termination (FG3)
- [x] **25.1** Extended `redteamer-core/src/traits/adapter.rs`:
  - Added `early_terminate_strings: Vec<String>` and `stream: bool` to `GenerationOptions`.
  - Added `AdapterResponse::is_early_terminated(&self) -> bool` reading `metadata["early_terminated"]`.
- [x] **25.2** Implemented zero-dependency streaming in `crates/redteamer-adapters/src/stream.rs`:
  - Zero-dependency Server-Sent Events (SSE) data frame parser (`parse_sse_data`).
  - Provider-specific delta extraction functions: `extract_openai_delta`, `extract_anthropic_delta`, `extract_ollama_delta`.
  - `StreamAccumulator` with multi-needle substring detection and match position truncation.
  - `consume_stream` async engine utilizing `reqwest::Response::chunk()`: drops the HTTP connection immediately upon needle encounter to conserve remote tokens, returning structured metadata (`stream`, `early_terminated`, `terminated_by`, `chunk_count`).
  - Added 5 unit tests validating SSE parsing, JSON delta extraction, and needle accumulation.
- [x] **25.3** Wired streaming and early termination into target adapters:
  - `OpenAiAdapter`: `complete_stream` and `ChatRequest.stream: Some(true)`.
  - `AnthropicAdapter`: SSE message event processing and early termination.
  - `OllamaAdapter`: newline-delimited JSON stream processing and early termination.
  - Added mock HTTP streaming integration test in `crates/redteamer-adapters/src/lib.rs` verifying canary extraction stops HTTP streaming after partial tokens.
- [x] **25.4** Dynamic canary propagation in `crates/redteamer-probes/src/lib.rs`:
  - `TemplateProbe::run` automatically populates `early_terminate_strings` from the session's ephemeral or static canary tokens.
- [x] **25.5** CLI flag and mock simulation:
  - Added `--stream` flag to `redteamer-cli/src/cmd/scan.rs` and propagated to `default_opts`.
  - Updated `CliMockAdapter` in `adapter_builder.rs` to store `default_options`, respect `--stream`, and simulate canary truncation.
  - Added `scan_with_stream_flag_executes_successfully` in `crates/redteamer-cli/tests/cli_integration.rs`.
- [x] **25.6** Full Workspace Verification:
  - All 99 tests passing (`cargo test --workspace --offline` across all 8 crates, 8 integration suites, and 4 doc-tests).
  - Clippy `-D warnings` 100% clean (0 warnings, 0 errors).
  - `cargo fmt --all -- --check` 100% clean.
  - `cargo deny --offline check` clean (advisories ok, bans ok, licenses ok, sources ok).


