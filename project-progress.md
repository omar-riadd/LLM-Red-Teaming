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
- [ ] **13.1** Expand all 10 templates to 30+ seeds each
- [ ] **13.2** New `templates/llm02_rag_injection.yaml`
- [ ] **13.3** Multilingual seeds (ar/zh-CN/fr) in LLM01, LLM02, LLM07
- [ ] **13.4** Update `detection_eval.rs` labeled cases to cover new seeds

### Phase 14 — Bundled `all-MiniLM-L6-v2` Semantic Model (GA3)
- [ ] **14.1** Download + vendor model to `models/all-MiniLM-L6-v2/`
- [ ] **14.2** Add `--semantic-model=builtin` shorthand to CLI
- [ ] **14.3** Document semantic detection in `README.md`
- [ ] **14.4** Add `#[ignore]` offline semantic detector test

### Phase 15 — Property Tests, Fuzz Targets, Judge Eval (GA5, GA11, GA14)
- [ ] **15.1** `proptest` for `MutationPipeline` (3 properties)
- [ ] **15.2** `cargo fuzz` targets for YAML loader and mutation pipeline
- [ ] **15.3** `LlmJudgeDetector` mock accuracy test

### Phase 16 — CLI Module Split & Interactive HTML Report (GA6, GA10)
- [ ] **16.1** Split `main.rs` into `cmd/{scan,diff,list,health}.rs`
- [ ] **16.2** HTML report: dark mode + sortable table + SVG chart + collapsible sections

### Phase 17 — Stateful PAIR Attacker Loop (GA7)
- [ ] **17.1** Replace stateless Crescendo with scored PAIR tree search (N=3 branches, judge scoring)

### Phase 18 — Docker Image & Release Automation (GA13)
- [ ] **18.1** `Dockerfile` (distroless) + `docker-compose.yml` for Ollama
- [ ] **18.2** `.github/workflows/release.yml` for tagged releases
