# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-24

### Added

- **Complete OWASP LLM Top 10 (2025) Probe Suite**: Added `llm03_supply_chain`, `llm04_data_and_model_poisoning`, `llm05_improper_output_handling`, `llm08_vector_and_embedding_weaknesses`, and `llm09_misinformation` alongside upgraded `llm01`, `llm02`, `llm06`, `llm07`, and `llm10` templates.
- **Unified `TemplateProbe` Engine**: Replaced per-category boilerplate probe structs with a single YAML-driven `TemplateProbe` supporting `system_prompt` + `canary_token` injection, multi-turn `User -> Assistant -> User` conversation chains, inline detector rules (`string_match`, `regex_set`, `refusal_match`, `canary_match`, `min_length`), and retry with exponential backoff on transient HTTP 429/5xx errors.
- **Chat-First `TargetAdapter` Redesign**: Added `Role`, `ChatMessage`, `GenerationOptions`, and `TargetAdapter::send_chat`, upgrading `OllamaAdapter` to `/api/chat`, `OpenAiAdapter` to support system prompts and generation options, and `AnthropicAdapter` to use top-level `system` fields and configurable `max_tokens` (default `4096`).
- **Evasion Mutators & Lineage Tracking**: Added `Leetspeak`, `Homoglyph`, `ZeroWidth`, and `JsonTaskWrap` mutators, actionable decoding instructions for `Base64`/`Rot13`/`Reverse`, and preserved exact `MutationType` lineage on every generated payload.
- **Full Detector Suite**: Implemented `CanaryDetector`, `LengthDetector`, adapter-backed `LlmJudgeDetector`, and ONNX Runtime `SemanticDetector` (`ort` mean-pooled, L2-normalized cosine similarity), plus `llm-redteamer list --kind detectors`.
- **6 Report Exporters & Dynamic CVSS v4.0**: Added `CsvExporter` (RFC 4180) and `JsonlExporter`, upgraded `JsonExporter`, `HtmlExporter`, `MarkdownExporter`, and `SarifExporter` (with SARIF 2.1.0 `locations`), and added `CvssLlmComputer::compute_for_mutation` (`AC:L` vs `AC:H`) and per-probe Attack Success Rate (`ProbeSummary`).
- **CLI Overhaul & Regression Diffing**: Added `llm-redteamer diff <baseline.json> <current.json> [--fail-on-regression]`, `--fail-on <low|medium|high|critical>`, `--probes-dir`, `--judge-target`, `--skip-health-check`, and moved all status banners to `stderr`.
- **Project Hygiene**: Added `LICENSE-MIT` and `LICENSE-APACHE`, updated repository metadata to `https://github.com/omar-riadd/LLM-Red-Teaming`, and added an MSRV `1.88` + `stable` matrix in `.github/workflows/ci.yml`.

## [0.1.0] - 2026-08-27

Initial release.

### Added

- **Workspace structure**: `redteamer-core`, `redteamer-adapters`, `redteamer-payload`, `redteamer-detectors`, `redteamer-probes`, `redteamer-orchestrator`, `redteamer-reporters`, `redteamer-cli`.
- **Target adapters**: Ollama (local), OpenAI, and Anthropic, selectable via `--target`.
- **Probes** for 5 OWASP LLM Top 10 categories: `llm01_prompt_injection`, `llm02_sensitive_info_disclosure`, `llm06_excessive_agency`, `llm07_system_prompt_leakage`, `llm10_unbounded_consumption`, each with YAML-defined seeds and a mutation pipeline.
- **Detectors**: functional `string_match` and `regex_set` detectors (`memchr`/`regex` backed).
- **Orchestration**: concurrent scan execution via `ScanBuilder`/`ScanConfig` with per-probe `tokio::task::JoinSet` fan-out and a live progress spinner (`indicatif`) that ticks as probes complete.
- **CVSS 4.0 scoring**: real score computation via the `cvss` crate, with valid 11-metric vectors emitted per OWASP category (`CvssLlmComputer`).
- **CLI**: `scan` and `list` subcommands (`list --kind probes` fully working; `list --kind detectors` cleanly stubbed).
- **CI pipeline**: GitHub Actions running `cargo test`, `cargo clippy -- -D warnings`, and `cargo deny check`, all green.
- **Reporters** (`Json`, `Markdown`, `Html`, `Sarif`) implemented and unit-tested standalone via `exporter_factory`.
- **README** with architecture diagram, verified quickstart, real sample output, and an honest limitations/roadmap section.
