# llm-redteamer

High-performance, concurrent LLM red-teaming framework — probes a target LLM across all **10 OWASP Top 10 for LLM Applications (2025)** categories using single-turn evasion mutators, multi-turn conversational escalation, and canary-injected system prompts, and exports structured security reports with dynamic **CVSS v4.0** scoring.

## Architecture

```mermaid
graph TD
  CLI["redteamer-cli<br/>scan / list / diff"] --> Orchestrator
  Orchestrator["redteamer-orchestrator<br/>ScanBuilder / ScanConfig"] --> Probes
  Orchestrator --> Adapters
  Probes["redteamer-probes<br/>TemplateProbe (LLM01–LLM10)"] --> Payload["redteamer-payload<br/>ProbeTemplate + MutationPipeline"]
  Adapters["redteamer-adapters<br/>TargetAdapter: ollama / openai / anthropic / gemini / azure / mcp / mock"] --> LLM[("Target LLM / MCP Server")]
  Probes -- "send_chat + retry/backoff" --> Adapters
  Probes --> Detectors["redteamer-detectors<br/>DetectorPipeline (string, regex, canary, length, judge, semantic)"]
  Orchestrator --> Report["ScanReport<br/>records: Vec&lt;AttackRecord&gt;"]
  Report --> Reporters["redteamer-reporters<br/>CvssLlmComputer + exporter_factory"]
  Reporters --> Sink["OutputSink<br/>Stdout / File (json, jsonl, md, html, sarif, csv, dpo, pdf)"]
  Core["redteamer-core<br/>types, traits, error, CVSS v4.0"] -. defines .-> CLI
  Core -. defines .-> Orchestrator
  Core -. defines .-> Probes
  Core -. defines .-> Adapters
  Core -. defines .-> Detectors
  Core -. defines .-> Reporters
```

### Workspace Crates

| Crate | Purpose |
|---|---|
| `redteamer-core` | Core domain types (`OwaspCategory`, `AttackRecord`, `Finding`, `CvssVector`, `SeverityBreakdown`, `ProbeSummary`, `TokenUsage`, `ToolDefinition`, `ToolCall`), error model (`is_retryable()`), and async trait contracts (`TargetAdapter::send_chat`, `Detector`, `Probe`, `ReportExporter`). |
| `redteamer-adapters` | Chat-, tool-, and protocol-aware backends (`OllamaAdapter`, `OpenAiAdapter`, `AnthropicAdapter`, `GeminiAdapter`, `AzureOpenAiAdapter`, `OpenAiCompatibleAdapter`, and `McpAdapter` for HTTP & Stdio Model Context Protocol servers) with multi-IP proxy rotation (`ProxyPool`, `RotatingAdapter`), circuit-breaker cooldown recovery, token-bucket rate limiting, real-time SSE streaming early termination, and `GenerationOptions`. |
| `redteamer-payload` | YAML `ProbeTemplate` loader with inline detector rules, tool schemas, canary injection, static & adaptive multi-turn conversation chains, and `MutationPipeline` (`Identity`, `Base64`, `Rot13`, `Reverse`, `Uppercase`, `Wrap`, `Leetspeak`, `Homoglyph`, `ZeroWidth`, `JsonTaskWrap`). |
| `redteamer-detectors` | Concurrent `DetectorPipeline` with pre-detection response de-obfuscation (`zero-width`, `Base64`, `Hex`, `ROT13`), `StringMatchDetector` (SIMD `memchr`), `RegexSetDetector`, `CanaryDetector`, `LengthDetector`, `ToolCallDetector`, `LlmJudgeDetector`, and ONNX Runtime `SemanticDetector`. |
| `redteamer-probes` | Unified `TemplateProbe` engine embedding all 11 OWASP LLM 2025 templates (`templates/llm01_*.yaml` – `templates/llm10_*.yaml`), stateful PAIR tree search attacker loop, and custom directory loading (`--probes-dir`). |
| `redteamer-orchestrator` | Concurrent campaign runner (`ScanBuilder`, `ScanConfig`, `ScanReport`) with global concurrency semaphore, per-request progress callbacks, live JSONL streaming, and checkpoint resume. |
| `redteamer-reporters` | Dynamic CVSS v4.0 computer (`CvssLlmComputer::compute_for_mutation`), per-probe ASR calculator, token/latency (`p50`/`p95`) telemetry, and 8 exporters (`Json`, `Jsonl`, `Markdown`, `Html`, `Sarif` v2.1.0, RFC 4180 `Csv`, `DpoExporter` for automated RLHF preference datasets, and `PdfExporter` for executive CISO deliverables). |
| `redteamer-cli` | `llm-redteamer` binary (`scan`, `list`, `diff`, `health`) with `stderr` progress/telemetry, live JSONL streaming (`--stream-jsonl`), real-time token streaming (`--stream`), DPO dataset export (`--export-dpo`), executive PDF export (`--export-pdf`), crash recovery (`--resume`), adaptive attacker (`--attacker-target`), and CI quality gates (`--fail-on`, `--fail-on-regression`). |

## OWASP Top 10 for LLM Applications (2025) Coverage

| Probe Name | Category | Scope | Primary Detection Mechanism |
|---|---|---|---|
| `llm01_prompt_injection` | `LLM01` Prompt Injection | `direct` | Canary exfiltration + compliance/refusal substring rules |
| `llm02_sensitive_info_disclosure` | `LLM02` Sensitive Information Disclosure | `direct` | System-prompt secret canary + credential markers |
| `llm03_supply_chain` | `LLM03` Supply Chain | `proxy` | Unsafe command/pickle regex automaton + compliance rules |
| `llm04_data_and_model_poisoning` | `LLM04` Data and Model Poisoning | `proxy` | Backdoor trigger & poisoned few-shot compliance markers |
| `llm05_improper_output_handling` | `LLM05` Improper Output Handling | `direct` | Unescaped XSS / SQLi / command-substitution regex automaton |
| `llm06_excessive_agency` | `LLM06` Excessive Agency | `direct` | Protocol-level `tool_call_match` + execution vs confirmation polarity rules |
| `llm07_system_prompt_leakage` | `LLM07` System Prompt Leakage | `direct` | Policy canary token + system prompt structural markers |
| `llm08_vector_and_embedding_weaknesses` | `LLM08` Vector and Embedding Weaknesses | `proxy` | Cross-tenant RAG chunk canary token + disclosure rules |
| `llm09_misinformation` | `LLM09` Misinformation | `direct` | Fabricated CVE / DOI / standard citation regex & substring rules |
| `llm10_unbounded_consumption` | `LLM10` Unbounded Consumption | `direct` | Quantitative output length threshold (`min_length >= 8192`) |

> **Scope Note (`direct` vs `proxy`):** Categories marked `direct` test intrinsic prompt/response vulnerabilities directly. Categories marked `proxy` evaluate behavioral susceptibility (e.g., recommending unverified artifacts in `LLM03`, responding to backdoor triggers in `LLM04`, or violating simulated RAG tenant boundaries in `LLM08`).

## Requirements & Target Providers

- **Rust** `1.88` or newer (`rust-version = "1.88"` in `Cargo.toml`, tested in CI against `1.88` and `stable`).
- Supported Target Providers:
  - **OpenAI**: `--target openai` (reads `OPENAI_API_KEY`)
  - **Anthropic**: `--target anthropic` (reads `ANTHROPIC_API_KEY`)
  - **Google Gemini**: `--target gemini` (reads `GEMINI_API_KEY` or `GOOGLE_API_KEY`)
  - **Azure OpenAI**: `--target azure` (reads `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, and `AZURE_OPENAI_DEPLOYMENT`)
  - **OpenRouter**: `--target openrouter` (reads `OPENROUTER_API_KEY`)
  - **vLLM / Local Inference**: `--target vllm` (reads `VLLM_BASE_URL` or defaults to `http://localhost:8000/v1`)
  - **Ollama**: `--target ollama` (`ollama serve` + `ollama pull llama3.2`)
  - **Model Context Protocol (MCP)**: `--target mcp` (reads `MCP_SERVER_URL` or defaults to `http://127.0.0.1:8000/mcp`) or `--target stdio://<command>`
  - **Mock / Offline Testing**: `--target mock`
  - **Custom Gateway**: `--target http(s)://...`

## Quickstart

```bash
# 1. Build workspace
cargo build --workspace --all-targets

# 2. List built-in probes (all 11 OWASP LLM 2025 templates) and detectors
cargo run -p redteamer-cli -- list --kind probes
cargo run -p redteamer-cli -- list --kind detectors

# 3. Run an offline smoke scan against the built-in deterministic mock target
cargo run -p redteamer-cli -- scan --target mock --probes llm01_prompt_injection --format markdown

# 4. Stream records live to JSONL and resume from a checkpoint if interrupted
cargo run -p redteamer-cli -- scan --target ollama --model llama3.2 --stream-jsonl checkpoint.jsonl --output report.json
cargo run -p redteamer-cli -- scan --target ollama --model llama3.2 --resume checkpoint.jsonl --stream-jsonl checkpoint.jsonl --output report.json

# 5. Run real-time streaming with early termination upon canary extraction
cargo run -p redteamer-cli -- scan --target mock --probes llm01_prompt_injection --stream --format markdown

# 6. Export automated DPO / RLHF preference dataset alongside markdown report
cargo run -p redteamer-cli -- scan --target mock --export-dpo dpo_dataset.json --format markdown

# 7. Export executive PDF report deliverable with scorecard, OWASP matrix & roadmap
cargo run -p redteamer-cli -- scan --target mock --probes llm01_prompt_injection --format markdown --export-pdf executive_report.pdf

# 8. Multi-IP proxy rotation with automatic circuit-breaker failover (round-robin, random, least-loaded, failover)
cargo run -p redteamer-cli -- scan --target openai --proxies http://proxy1:8080,http://proxy2:8080 --proxy-strategy round-robin --format markdown

# 9. Deterministic distributed worker sharding across cluster containers (zero duplicate attacks)
cargo run -p redteamer-cli -- scan --target mock --worker-id 0 --total-workers 2 --stream-jsonl shard0.jsonl
cargo run -p redteamer-cli -- scan --target mock --worker-id 1 --total-workers 2 --stream-jsonl shard1.jsonl
# Consolidate distributed shard checkpoints into an executive deliverable:
cargo run -p redteamer-cli -- scan --target mock --resume shard0.jsonl,shard1.jsonl --format pdf --output full_cluster_report.pdf

# 10. Run adaptive multi-turn evaluations with a secondary attacker model (stateful PAIR tree search)
cargo run -p redteamer-cli -- scan --target ollama --model llama3.2 --attacker-target ollama --attacker-model llama3.2 --format html --output report.html

# 11. Enforce a CI quality gate (exits with code 2 if any High/Critical finding occurs)
cargo run -p redteamer-cli -- scan --target mock --fail-on high --format json --output current.json

# 12. Compare two JSON scan reports for per-probe ASR & finding-level regressions
cargo run -p redteamer-cli -- diff baseline.json current.json --fail-on-regression

# 13. Run scan with bundled ONNX sentence-transformer semantic detector
cargo run -p redteamer-cli -- scan --target mock --semantic-model builtin --semantic-threshold 0.78
```

## Semantic Detection

`llm-redteamer` features an offline, embedding-based `SemanticDetector` powered by ONNX Runtime (`ort`). It encodes target responses into mean-pooled, L2-normalized dense embeddings and measures cosine similarity against a calibrated reference corpus of known-vulnerable and refusal phrasing.

- **Bundled Model**: `sentence-transformers/all-MiniLM-L6-v2` (Apache-2.0 license).
- **Out-of-the-Box**: Pass `--semantic-model builtin` (automatically resolves `models/all-MiniLM-L6-v2/model.onnx` and its HuggingFace tokenizer).
- **Download Helper**: If setting up on a fresh machine without pre-downloaded weights, execute:
  ```bash
  ./models/all-MiniLM-L6-v2/download_model.sh
  ```
- **Custom Models**: Bring your own sentence-transformer ONNX export and tokenizer:
  ```bash
  cargo run -p redteamer-cli -- scan --target ollama --semantic-model path/to/model.onnx --semantic-tokenizer path/to/tokenizer.json --semantic-threshold 0.80
  ```

## Docker & Containerization

### Docker Run
Run scans inside an isolated, non-root container without local Rust tooling:
```bash
# Build the container image
docker build -t llm-redteamer:latest .

# Run scan against a target (mounting ./reports for artifact output)
docker run --rm -v $(pwd)/reports:/home/redteamer/reports llm-redteamer:latest \
  scan --target mock --format html -o /home/redteamer/reports/report.html
```

### Docker Compose (Local Ollama Red-Teaming)
Orchestrate an end-to-end local red-teaming campaign with Ollama:
```bash
# Start Ollama service and execute automated scan against local model
docker compose up --build
```

## Development & Verification

```bash
# Code quality, clippy, and full workspace test suite (including proptests & judge evals)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check

# Property testing (proptest for mutation invariants)
cargo test -p redteamer-payload --test mutation_proptest

# Fuzz testing (requires nightly and cargo-fuzz)
# cargo +nightly fuzz run probe_yaml_loader
# cargo +nightly fuzz run mutation_pipeline
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
