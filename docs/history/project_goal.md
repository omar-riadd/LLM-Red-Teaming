# LLM-Red-Teaming — Project Goal

This describes what **llm-redteamer** looks like once every currently-known
limitation is closed and the tool works the way it was originally imagined
when the plan was first laid out — a complete, trustworthy,
production-quality automated red-teaming framework for LLMs, not a
portfolio stub.

## What it is

A command-line tool, `llm-redteamer`, that takes any target LLM (a local
Ollama model, OpenAI, or Anthropic) and systematically attacks it with
adversarial payloads covering the full **OWASP LLM Top 10**, judges every
response with real pluggable detectors, scores every genuine finding with
real CVSS 4.0 severity, and produces a clean, exportable report a security
team could actually hand to a client or attach to a CI pipeline.

## Full OWASP LLM Top 10 coverage

All 10 categories have real probes and real template content, not just the
5 that exist today:

- llm01 Prompt Injection
- llm02 Sensitive Information Disclosure
- llm03 Supply Chain
- llm04 Data and Model Poisoning
- llm05 Improper Output Handling
- llm06 Excessive Agency
- llm07 System Prompt Leakage
- llm08 Vector and Embedding Weaknesses
- llm09 Misinformation
- llm10 Unbounded Consumption

Each has a genuine set of realistic adversarial seed payloads, a mutation
pipeline, and detector_hints that actually correspond to real, configured
detectors — not plausible-sounding placeholder names.

## A real, fully-wired detection pipeline

Every probe's `evaluate()` heuristic remains as a fast first-pass signal,
but it's no longer the *only* signal. The full `DetectorPipeline` runs for
real on every attack record:

- **`string_match`** and **`regex_set`** detectors — already functional
  today — are configured with real match content for every probe's
  `detector_hints`, not just one proof-of-concept probe.
- **`semantic`** detection works end-to-end: a real ONNX embedding model and
  tokenizer are bundled or fetched, and semantic similarity to known
  jailbreak/leak patterns contributes real detection signal beyond exact
  string/regex matches.
- **`llm_judge`** detection works end-to-end: an existing `TargetAdapter`
  (Ollama/OpenAI/Anthropic) is reused as the judge transport, asking a
  model to evaluate whether a response constitutes a genuine policy
  violation — catching cases no string or regex pattern could.
- `record.detections` is populated for every record where hints match
  configured detectors, giving full evidence and attribution for every
  finding, not just a bare heuristic verdict.

## Real, surfaced severity

CVSS 4.0 scoring (already mathematically correct today) is visible
everywhere it matters: in the CLI's live scan summary, in every exported
report format, and reflected accurately in the `Finding` objects that
downstream tools consume. Severity banding (Critical/High/Medium/Low) helps
a user triage results at a glance without reading raw JSON.

## Fully functional multi-format reporting

`--format json|markdown|html|sarif|csv` all produce real, complete report
files — including a working `Csv` exporter (currently the one stubbed
format). SARIF output is clean enough to feed directly into GitHub code
scanning or another SARIF-consuming security dashboard. HTML output is
presentable enough to email to a stakeholder without further editing.

## Configurable, resilient scanning

Concurrency is configurable (already true today via `--concurrency`) and
the tool degrades gracefully under load — no silent timeouts, clear
progress feedback throughout a run via the existing spinner, and clean,
actionable errors (bad target, bad model name, bad format) instead of
panics or opaque failures. Running against a local model, a hosted API, or
a self-hosted endpoint all feel equally first-class.

## Verified, trustworthy claims

No feature is documented as working unless it has actually been run and
independently verified against real output — the project's own hard-won
lesson (the verdict-stuck-at-`Error` bug slipped past documentation once
already). The README's sample output, limitations section, and CHANGELOG
stay accurate and current, with genuine bugs logged as *fixed*, not quietly
reworded into permanent caveats.

## Clean project hygiene

- A real `LICENSE` file exists at the repo root (not just a `Cargo.toml`
  field), matching the declared dual MIT/Apache-2.0 license.
- CI runs a real MSRV matrix in addition to stable, so the declared
  `rust-version` floor is actually enforced, not just descriptive.
- The two current RUSTSEC "unmaintained" exceptions are gone because the
  underlying transitive dependencies (`indicatif`'s pull of `tokenizers`)
  have been updated or replaced upstream, or a maintained alternative has
  been adopted.
- Test coverage extends to every probe, every detector, and every reporter,
  including integration tests that exercise the real (not mock) adapters
  where feasible.

## What this achieves

A finished `llm-redteamer` at this state is a legitimate, demonstrable piece
of offensive-security tooling: something Omar can point to in interviews or
a CV not as "a Rust project that compiles" but as "a red-teaming framework
that finds real prompt injection and system-prompt-leakage vulnerabilities
in real models, scores them correctly, and reports them the way a
professional pentest tool would" — the original idea, fully realized.
