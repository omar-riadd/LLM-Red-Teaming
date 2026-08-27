# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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

### Known Limitations

See the README's Limitations section for full detail. Highlights:

- Only 5 of 10 OWASP LLM Top 10 categories have probes (`llm03/04/05/08/09` absent).
- `SemanticDetector` and `LlmJudgeDetector` are stubbed (`Unsupported` error, no ONNX fixture / judge transport yet).
- `detector_hints` field is parsed from YAML but not wired to any runtime lookup.
- `--format` flag is parsed and logged but not dispatched to any `ReportExporter` — CLI output is a fixed summary line regardless of value.
- CVSS scores are computed internally but not yet surfaced in CLI output.
- `Csv` reporter is a stub (`Unsupported`).
- No `LICENSE` file at repo root yet (license declared only in `Cargo.toml`) — planned for a future release.
- No MSRV matrix in CI despite a declared `rust-version = "1.88"` floor (CI tests on `stable` only).
