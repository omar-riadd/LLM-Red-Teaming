# LLM-Red-Teaming — Full Project History

Repo: `~/Projects/LLM-Red-Teaming` → github.com/omar-riadd/LLM-Red-Teaming (main branch)

## The Idea

Omar chose this project after researching market need for cybersecurity
projects in 2026 and finding LLM red-teaming as the top result. The goal:
build **llm-redteamer**, a modular Rust workspace for automated red-teaming
of LLMs — probes fire adversarial payloads at a target model, pluggable
detectors judge the responses, and reports get exported in multiple formats.
Intended as a CV/portfolio project demonstrating real, working offensive-security
tooling rather than a toy.

Workspace crates: `redteamer-core`, `redteamer-adapters`, `redteamer-payload`,
`redteamer-detectors`, `redteamer-probes`, `redteamer-orchestrator`,
`redteamer-reporters`, `redteamer-cli`.

There was an original/target project structure Omar was following that
differed from what actually got built — it had included an llm06
excessive-agency probe, a custom_rest adapter, scheduler/checkpoint/progress
orchestrator modules, CLI subcommands plus on-disk TOML config, ONNX model
files, a dummy-llm-api docker test fixture, and cargo-deny. The real build
diverged from that scaffold in places, which is part of why several "stub"
files caused real bugs later (see below).

## Working Method

Claude drafts a scoped prompt → Omar pastes it to an AI coding agent
(originally "OX alpha", later switched to **GLM 4.7 Flash** when OX
alpha's OpenRouter/Zen free-preview access expired) → the agent implements
and reports back with exact file:line references and verification output →
Claude reviews/pressure-tests the claims before moving to the next step. One
phase (or sub-phase) at a time. When a task proved too large for the agent to
handle in one request, it got split into smaller sequential prompts
(investigation-only steps before implementation steps).

---

## Phase 1 — llm06 Excessive Agency probe

Created `crates/redteamer-probes/src/llm06.rs` and
`templates/llm06_excessive_agency.yaml`, wired into `lib.rs` via `pub mod
llm06;`. All 4 unit tests passed after fixing two snags: `AttackRecord` has
no `Default` impl (had to construct field-by-field), and a shell quoting bug
from pasting file content via `>>` redirect (apostrophes got mangled by
shell interpretation — fixed by using `nano` instead).

## Phase 2 — CLI `list` subcommand (and 3 real bugs found along the way)

Investigation surfaced three genuine, pre-existing bugs in `main.rs`:
1. `run_scan` never called `.probes(...)` on `ScanBuilder` — **every CLI scan
   run up to that point had executed against an empty probe list** (zero
   records, not a false-negative result).
2. `build_adapter` ignored the `target` argument entirely via a
   wildcard-only match — it always built an `OpenAiAdapter` and demanded
   `OPENAI_API_KEY` no matter what target was requested. Ollama/Anthropic
   were unreachable from the CLI.
3. `--probes` was accepted and printed but never actually passed into the
   scan config.

Fixed all three: wired `.probes(...)` via the existing (already-functional)
`inventory`-based probe registry (`all_probes()`/`probes_by_name()`, no
registry work needed — just plumbing), fixed `build_adapter`'s match to
correctly dispatch openai/ollama/anthropic with a clear error on unknown
targets, wired `--probes` through with warnings on unmatched names, and
added the `list --kind probes` subcommand (`list --kind detectors` stubbed
to print "not implemented" and exit(1) rather than panic).

**Bonus bug found during verification:** `templates/llm02_secrets.yaml` and
`templates/llm10_consumption.yaml` were stub files (only an `id:` field)
that had passed silently until `all_probes()` was actually exercised for the
first time — at which point they panicked on deserialization. Authored full
real content for both (name, description, owasp_categories, 8-12 realistic
adversarial seeds each, mutations, detector_hints).

End-to-end verified: `scan --target ollama` → `records=168, vulnerable=0,
failed_probes=0` (vulnerable=0 was expected at this point — detector
evaluation logic wasn't wired yet). All 5 probes loaded cleanly via `list
--kind probes`.

Also confirmed at this point: `detector_hints` was NOT wired to any runtime
lookup anywhere (grep-verified) — inert metadata from the start.

## Phase 3 — Kill panics in stubbed detectors

`SemanticDetector` and `LlmJudgeDetector` both had `todo!()` calls that would
panic if ever invoked. Split into two sub-prompts (3a: `semantic.rs`, 3b:
`llm_judge.rs`) after the combined prompt hit an OpenRouter credit cap.
Replaced both `todo!()`s with a proper `RedTeamerError::Unsupported(...)`
(the variant already existed, no new error type needed). Added a passing
unit test for `llm_judge.rs`; `semantic.rs` was left with a `// TODO: needs a
test fixture ONNX model + tokenizer` comment since no such fixture exists —
GLM correctly declined to fabricate one rather than faking a test.

`cargo test --workspace`: all green, 12 tests + 3 passing doctests (1
ignored), zero regressions. `scan --target ollama` still showed
`vulnerable=0` as expected (neither stubbed detector was in any active path
yet).

## Phase 3.5 — Clippy cleanup pass

Running `cargo clippy` first required `rustup component add clippy` (wasn't
installed). Clippy found one **real** issue, not just cosmetic: `semantic.rs`
used `Option::is_none_or` (stable since Rust 1.82) while the workspace MSRV
was declared as 1.75 — a genuine MSRV mismatch. Decision was deferred at
first, later resolved in Phase 4 (bump MSRV to 1.82 rather than rewrite for
1.75 support).

Other findings were cosmetic: needless_borrow, obfuscated_if_else, an unused
import, 2x unnecessary_to_owned, useless_conversion, needless_return. Ran
`cargo clippy --fix --workspace --allow-dirty` as a cleanup pass so CI would
start from a clean baseline (5 fixes landed across `openai.rs`,
`string_match.rs`, `main.rs` — no git repo existed yet at this point, so no
diff could be shown, only clippy's own "Fixed N" output as evidence).

Remaining warnings left in place intentionally: `dead_code` on
`SemanticDetector::session` (real ONNX work is future), the MSRV mismatch
(decision pending), 2 `unnecessary_to_owned` not auto-fixable, and 3
newly-surfaced `new_without_default` warnings on three probe structs (masked
until other warnings were cleared). `cargo test --workspace`: still
11 passed/0 failed/1 ignored.

Decided at this point: bump MSRV to 1.82, and fold the 3
`new_without_default` fixes into Phase 4 rather than deferring further.

## Phase 4 — cargo-deny + CI pipeline (the biggest saga of the project)

**Round 1:** MSRV bumped to 1.82 in `Cargo.toml`, `Default` impls added for
the 3 probe structs, `deny.toml` created via `cargo-deny` (4 licenses added —
ISC/Unicode-3.0/BSD-3-Clause/CDLA-Permissive-2.0 — to pass the licenses
check), `.github/workflows/ci.yml` created with test (1.82/stable matrix),
clippy (`-D warnings`), and deny jobs.

**Two real failures surfaced on final verification:**
1. `cargo deny check` failed on 2 real RUSTSEC advisories — `number_prefix
   0.4.0` (RUSTSEC-2025-0119, via `indicatif`→`tokenizers`) and `paste
   1.0.15` (RUSTSEC-2024-0436, via `tokenizers`) — both transitive
   "unmaintained" (not exploitable-vulnerability) advisories. GLM correctly
   declined to just silence them without justification.
2. `cargo clippy -- -D warnings` failed outright on the previously-preserved
   `dead_code` warning on `SemanticDetector::session`, since `-D warnings`
   escalates every warning (including intentional ones) into a hard failure.

**Fix:** added `ignore = [...]` with an explanatory comment to `deny.toml`'s
`[advisories]` for the 2 named RUSTSEC IDs, and added a scoped
`#[allow(dead_code)]` with a comment directly on the `session` field — this
doesn't contradict "don't touch it" from Phase 3, since that was about not
fixing the underlying unused-field issue, not about silencing an
expected-and-understood compiler warning.

**Phase 4 locally complete**, zero warnings/failures across
build/clippy/test/deny — but then came the actual GitHub push, which had its
own saga:

1. `target/` build artifacts got committed by mistake (>100MB files, GitHub
   rejected the push) — fixed with `rm -rf .git`, added `.gitignore` with
   `/target`, re-initialized and re-committed from a clean state.
2. The GitHub PAT lacked the `workflow` scope needed to push
   `.github/workflows/ci.yml` — fixed by regenerating the classic PAT with
   `workflow` scope added.
3. After the push finally succeeded, the Actions test job **still failed**:
   a transitive dependency (`cpufeatures 0.3.0`) required `edition2024`
   (stabilized in Rust 1.85, not 1.82) — the real MSRV floor was higher than
   what had been declared and tested locally. Bumped `rust-version` to
   "1.85" and pushed again — CI run still not confirmed green at that point.
4. **Further MSRV chasing:** 1.82→1.85 still wasn't enough once actually
   tested in CI, because member crates used `rust-version.workspace = true`
   inheritance. Briefly tried removing `rust-version` from the workspace
   root entirely (to make CI stable-only) — this broke all 3 jobs, since the
   member crates' inherited field then pointed at nothing. **Final fix:**
   restored `rust-version = "1.88"` at the workspace root (the real observed
   floor, driven by `ort`/`icu_*` transitive deps) while keeping CI's test
   job stable-only (no MSRV matrix), with a comment noting the field is
   descriptive/inherited but not itself enforced by a matrix.

All 3 GitHub Actions jobs (test/clippy/deny) finally confirmed **green** in
real CI. **PHASE 4 FULLY DONE.**

(Side note logged along the way: `git credential.helper` set to `store`
locally for convenience — accepted tradeoff of the token sitting in
plaintext in `~/.git-credentials` on this personal machine.)

## Phase 5 — Progress bar (indicatif)

Design decision: simple version — one spinner + running record count, not
per-probe granular progress. Investigation found `ScanConfig::execute()` uses
concurrent `JoinSet` fan-out (one task per probe, non-deterministic
completion order), so progress naturally resolves per-probe-completion, not
per-record; no prior progress hook existed anywhere. `indicatif 0.17.11` was
already a transitive dependency via `tokenizers`.

Implemented additively: a new `Option<Arc<dyn Fn(usize)+Send+Sync>>`
`progress_callback` field on `ScanConfig`/`ScanBuilder` with an
`on_record_progress()` builder method (fires with the running
`report.records.len()` after each probe's task completes) —
`execute()`'s signature/return type unchanged, 100% backward compatible.
Added `indicatif` as a direct `redteamer-cli` dependency (pinned to match
the already-resolved transitive version). Wired a spinner with a steady
100ms tick, cleared before the summary print. `cargo test --workspace`: all
green, no regressions (existing tests never call the new callback). Manual
run confirmed the spinner ticks and clears correctly.

## Phase 6 — Real CVSS 4.0 scoring

Investigation found CVSS 4.0 scoring is **not** a closed-form formula — the
official FIRST.org spec uses equivalence classes plus a 270-entry
MacroVector lookup table, so hand-porting the algorithm was ruled out.
Evaluated 3 crates (`cvss` 2.2.0, `polycvss` 0.4.0, `cvss-rs` 0.4.0); chose
`cvss` 2.2.0 (RustSec-maintained, MIT OR Apache-2.0), verified locally
against FIRST's published test vectors (matched 9.3 and 5.2 exactly).

Also found: `CvssLlmComputer::compute()` in `owasp_mapper.rs` was emitting
**invalid** CVSS 4.0 vector strings — missing the mandatory `AT` metric, and
carrying a leftover CVSS 3.x-style `S:U` scope metric that doesn't exist in
v4.0. Would have made real scoring fail even after wiring the crate in.

Fixed: added the `cvss` crate dependency, corrected `owasp_mapper.rs` to
emit all 11 mandatory CVSS 4.0 base metrics per OWASP category (with
category-appropriate values, e.g. `AT:P` for categories requiring prior
access), dropped the invalid `S:U`, implemented `CvssVector::score()` via
`cvss::v4::Vector::from_str` + `.score().value()` (with a defensive 0.0
fallback on parse failure, not expected to trigger post-fix). Added 5 unit
tests against FIRST-verified vectors plus a regression test iterating all 10
`OwaspCategory` variants confirming each produces a valid, positively-scored
vector. `cargo test --workspace`: 17 passed/1 ignored/0 failed. `cargo deny
check`: clean (7 pre-existing, unrelated warn-level duplicate-version
warnings noted but not blocking).

Noted but deliberately not scope-crept into Phase 6: scores still weren't
surfaced anywhere in CLI output — flagged as a gap for later (became Phase
7.5a).

## Phase 7 — Live Ollama run + honest README

Pulled and ran real `llama3.2:latest` (2.0 GB) locally via `ollama serve`,
confirmed genuine (not mock) adapter usage via a concurrent curl latency
check against Ollama's `/api/generate` while the scan ran. Result:
`records=168, vulnerable=0, failed_probes=0`.

**(This "vulnerable=0 confirmed expected" explanation was later discovered
in Phase 7.5(c) to be based on a false premise — see below. The number
happened to be numerically right for the wrong reason.)**

Investigation also caught an additional undisclosed gap: `--format`
(json/markdown/sarif/csv) was parsed and logged but never dispatched to any
`ReportExporter` — a dead `From<OutputFormat>` impl and an explicit
`TODO(Week 3)` comment confirmed it as a known-unfinished piece, not a
silent bug. Added to the Limitations section before README finalization.

**README.md written and approved:** accurate project description, a Mermaid
architecture diagram traced to real code, a quickstart with verified
`--help` output and real MSRV/Ollama setup steps, the actual captured
terminal output as sample output (not fabricated), and an honest
limitations/roadmap section (missing OWASP categories, stubbed
semantic/llm_judge detectors, inert `detector_hints`, CVSS not surfaced,
`--format` inert, no CI MSRV matrix, the 2 RUSTSEC exceptions). No `LICENSE`
file exists at repo root (only `Cargo.toml`'s license field) — flagged
honestly as a to-do rather than fabricated. Pushed to GitHub, confirmed
rendering correctly. **PHASE 7 FULLY DONE.**

## Phase 8 planning — CHANGELOG + tag decisions

Decided: yes to a `CHANGELOG.md` summarizing v0.1.0; LICENSE files (MIT/Apache)
deliberately deferred, not added now; tag message for v0.1.0 to be short.
`CHANGELOG.md` drafted (Keep a Changelog format) — before it could be
finalized, Omar asked to close as many README limitations as feasible
first, which became **Phase 7.5**.

---

## Phase 7.5 — Closing README limitations before tagging

Decided scope, after weighing effort vs. value:
- **(a)** Surface CVSS score/severity in CLI scan output
- **(b)** Wire `--format`/reporters so `exporter_factory` actually runs
- **(c)** Wire `detector_hints` to filter which detectors run per probe
- **(d)** Author probes/templates for missing OWASP categories
  (llm03/llm04/llm05/llm08/llm09)
- **(e)** Wire `llm_judge` detector by reusing an existing `TargetAdapter` as
  the judge transport

Deliberately deferred past v0.1.0: the `semantic` detector (needs a real
ONNX model+tokenizer fixture — genuine separate infra, not a coding fix),
CI MSRV matrix (cosmetic), RUSTSEC exceptions (upstream unmaintained-crate
warnings, nothing to fix locally).

### (a) — CVSS severity in CLI output — DONE

Added a `SeverityBreakdown` struct + pure `severity_breakdown()`/
`severity_breakdown_from_map()` functions in `owasp_mapper.rs` (buckets
`Vulnerable` records' CVSS scores into Critical/High/Medium/Low, tracks
highest score). Wired into `run_scan` via a `probe_name -> OwaspCategory`
map built *before* `ScanBuilder` consumes the probes (category info would
otherwise be lost after `execute()` — a real gotcha caught during
investigation). Prints `"severity: highest X.X (Band) | Critical N High N
Medium N Low N"` or `"severity: none"`. 7 new unit tests, all passing.
`cargo test --workspace`: 17 passed/1 ignored/0 failed. Live-verified the
empty-vulnerable-records case prints cleanly with no crash.

### (b) — Wire `--format`/reporters — DONE (split into 3 sub-steps)

Too large for one agent request, split into:
- **(b1) investigation:** confirmed `exporter_factory(format, sink) ->
  Result<Box<dyn ReportExporter>>`; `ReportExporter::export(&self, findings:
  &[Finding]) -> Result<usize>` is async and writes via `OutputSink`
  internally (not returning content to the caller); the existing
  `From<OutputFormat>` impl already mapped all variants correctly, just
  never called; no `Finding` conversion existed anywhere yet.
- **(b2) AttackRecord → Finding conversion:** added
  `findings_from_records()`/`findings_from_records_with_map()` pure
  functions (filtering to `Verdict::Vulnerable`, same defensive
  unknown-probe-skip pattern as severity_breakdown), using `Finding::new()`
  + `CvssLlmComputer` for the cvss field. 5 new unit tests, all passing.
- **(b3) actual CLI wiring:** added an optional `--output <PATH>` arg,
  built the `Vec<Finding>`, built an `OutputSink` (File or Stdout), called
  `exporter_factory` (finally making the dead `From` impl live) then
  `.export().await`. The `Csv` case (still `Unsupported`) is caught
  specifically with a clean error + `exit(1)` instead of panicking.

Live-verified all 3 usable formats (json/markdown/sarif) producing correct
real files, stdout fallback working, and the csv error path exiting cleanly
with no file created. **PHASE 7.5(b) FULLY DONE.**

### (c) — Wire `detector_hints` — biggest surprise of Phase 7.5

**Investigation revealed the scope was far bigger than assumed:**
`DetectorPipeline` was **entirely dead code** — never constructed, never
called by the orchestrator anywhere. Every `AttackRecord`'s `Verdict` had
always come from a probe-local heuristic `evaluate()` function (simple
`.contains()` checks), not from any detector. `record.detections` was
always an empty `Vec`, hints or no hints. `ScanConfig.detectors` existed as
a field but nothing (not even `main.rs`) ever populated it.

Flagged this to Omar before proceeding; decided **Option A (additive)** —
keep `evaluate()` as the sole source of `Verdict` (zero risk to existing
tested behavior), separately wire the pipeline to just populate
`detections`. Further decided **scope C2**: also author real detector
patterns for one probe (llm07) as a genuine proof-of-concept, rather than
fabricating patterns for all ~20 existing hint strings without real specs.

**Plumbing implementation:** threaded `detectors: Arc<[Arc<dyn Detector>]>`
through `Probe::run`, all 5 probe impls, `ScanConfig::execute` (single
`Arc::from` + per-probe `Arc::clone`), and `run_template` — filters by exact
`detector.name() == hint` match, runs `DetectorPipeline::from_detectors` on
the filtered set, populates `record.detections`.

**A real, independently-verified pre-existing bug surfaced during this
work** — the biggest single finding of the project:

> In `run_template`, the line `if record.verdict != Verdict::Error {
> record.verdict = evaluate(&record) }` meant `evaluate()` **never ran**
> after a successful model response, because `AttackRecord::new()` defaults
> `verdict` to `Error` and the success path never changed it. **Every
> CLI-driven scan record, project-wide, since the project's inception, had
> `Verdict::Error`** — not `Resistant`/`Partial` as the already-published
> README's Phase 7 explanation claimed.

This was demanded to be verified, not taken at face value — the agent was
asked to show the exact `git show HEAD` diff and reconcile it against
previously-observed test behavior. The reconciliation held up: `llm06`'s
unit tests call `probe.evaluate()` directly (bypassing `run_template`
entirely), and the integration test's `DummyProbe` sets verdict manually —
neither path ever exercised the buggy gate. And `vulnerable_count() == 0`
looks numerically identical whether records are stuck at `Error` or
genuinely `Resistant`/`Partial`, so the live scan summary never revealed the
bug either. **Fix:** removed the gate; `evaluate()` now runs unconditionally.
`cargo test --workspace`: 0 failed. `clippy -D warnings`: clean.

**Consequence:** the already-live-on-GitHub README's explanation of why
`vulnerable=0` was factually wrong (real cause was the stuck-at-Error bug,
not genuine resistance) — the `vulnerable=0` number itself was still
correct, by coincidence. Decided to re-run the live scan and correct the
README/CHANGELOG rather than leave the false explanation live.

**Re-verification with real data:** default env (`OLLAMA_MODEL` unset)
turned out to hit a *separate* real gap — `main.rs` defaults to `"llama3"`,
not `"llama3.2"` (the actually-pulled model), so unset-env runs 404 and
produce genuine send-failure `Error`s, unrelated to the verdict bug.
Explicitly setting `OLLAMA_MODEL=llama3.2` hit a different real-world
problem: the model saturated and timed out under the default concurrency of
8 on this hardware (`EXIT 124` after 120s). Switched to a smaller model,
`qwen2:0.5b` (352 MB), for a real completed run:
- `llm06_excessive_agency` → `Resistant=1 Partial=39 Error=0` (proves
  `evaluate()` now genuinely runs, no longer stuck at `Error`)
- `llm01_prompt_injection` → `Vulnerable=2 Resistant=22`, `severity: highest
  9.3 (Critical)` — a real detected vulnerability (jailbreak prompts got
  "Of course!"/"Certainly!" compliance-marker responses), with real `Finding`
  JSON output.

**Quick fix along the way:** rather than just documenting the newly-found
concurrency-hardcoded issue as another limitation, Omar asked to actually
fix it — added a `--concurrency <N>` CLI flag (default 8, unchanged
behavior if omitted), with validation rejecting `0` cleanly (`InvalidConfig`
error instead of a hang). Live-verified `--concurrency 2` behaves
identically otherwise and `--concurrency 0` exits cleanly.

**Pending (drafted, not yet pasted into repo):** corrected README Sample
Output section using the real `qwen2:0.5b` llm01 vulnerable-finding output,
a new "Fixed bugs worth knowing about" README subsection documenting the
verdict-stuck-at-Error bug and its fix, and a CHANGELOG.md `### Fixed`
section covering the verdict bug, `detector_hints` wiring, and the
concurrency fix.

**Not yet done:** (c2) — authoring real detector patterns for llm07 as the
proof-of-concept, plus items (d) missing OWASP probes and (e) llm_judge
wiring.

---

## Current status (as of this document)

- Phases 1-7: fully complete and pushed to GitHub.
- Phase 7.5(a): fully complete.
- Phase 7.5(b): fully complete.
- Phase 7.5(c): plumbing complete, verdict bug found and fixed, concurrency
  quick-fix complete; README/CHANGELOG corrections drafted but not yet
  applied; real detector patterns for llm07 (c2) not yet started.
- Phase 7.5(d) (missing OWASP probes) and (e) (llm_judge wiring): not started.
- Phase 8 (tag v0.1.0): blocked on finishing as much of 7.5 as feasible first.
