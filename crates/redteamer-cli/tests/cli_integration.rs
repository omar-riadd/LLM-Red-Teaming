// crates/redteamer-cli/tests/cli_integration.rs

use std::fs;
use std::process::Command;

fn cli_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_llm-redteamer"))
}

#[test]
fn list_probes_and_detectors_succeed() {
    let probes_out = cli_bin()
        .args(["list", "--kind", "probes"])
        .output()
        .expect("failed to execute llm-redteamer list --kind probes");
    assert!(probes_out.status.success());
    let stdout = String::from_utf8_lossy(&probes_out.stdout);
    for expected in [
        "llm01_prompt_injection",
        "llm02_sensitive_info_disclosure",
        "llm03_supply_chain",
        "llm04_data_and_model_poisoning",
        "llm05_improper_output_handling",
        "llm06_excessive_agency",
        "llm07_system_prompt_leakage",
        "llm08_vector_and_embedding_weaknesses",
        "llm09_misinformation",
        "llm10_unbounded_consumption",
    ] {
        assert!(
            stdout.contains(expected),
            "missing probe {expected} in list output"
        );
    }

    let detectors_out = cli_bin()
        .args(["list", "--kind", "detectors"])
        .output()
        .expect("failed to execute llm-redteamer list --kind detectors");
    assert!(detectors_out.status.success());
    let det_stdout = String::from_utf8_lossy(&detectors_out.stdout);
    for expected in [
        "string_match",
        "regex_set",
        "canary",
        "length",
        "llm_judge",
        "semantic",
    ] {
        assert!(
            det_stdout.contains(expected),
            "missing detector {expected} in list output"
        );
    }
}

#[test]
fn scan_all_eight_formats_and_fail_on_exit_code() {
    for (fmt, expected_marker) in [
        ("json", "\"findings\""),
        ("jsonl", "\"probe_name\":\"llm01_prompt_injection\""),
        ("markdown", "# LLM Red-Teaming Report"),
        ("html", "<!DOCTYPE html>"),
        ("sarif", "\"version\": \"2.1.0\""),
        ("csv", "session_id,record_id,probe_name"),
        ("dpo", "\"chosen\""),
        ("pdf", "%PDF-1.4"),
    ] {
        let out = cli_bin()
            .args([
                "scan",
                "--target",
                "mock",
                "--probes",
                "llm01_prompt_injection",
                "--format",
                fmt,
            ])
            .output()
            .expect("scan command failed to run");
        assert!(
            out.status.success(),
            "format {fmt} failed with status {:?}",
            out.status
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(expected_marker),
            "format {fmt} output did not contain {expected_marker}"
        );
    }

    let fail_out = cli_bin()
        .args([
            "scan",
            "--target",
            "mock",
            "--probes",
            "llm01_prompt_injection",
            "--fail-on",
            "high",
            "--format",
            "json",
        ])
        .output()
        .expect("scan --fail-on high failed to run");
    assert_eq!(
        fail_out.status.code(),
        Some(2),
        "expected exit code 2 when --fail-on high threshold is exceeded"
    );
}

#[test]
fn stream_jsonl_resume_and_finding_level_diff_exit_codes() {
    let temp_dir = std::env::temp_dir().join(format!("redteamer_cli_it_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("failed to create temp test dir");

    let baseline_path = temp_dir.join("baseline.json");
    let current_path = temp_dir.join("current.json");
    let stream_path = temp_dir.join("stream.jsonl");
    let partial_path = temp_dir.join("partial.jsonl");
    let resumed_path = temp_dir.join("resumed.json");

    // 1. Baseline scan with 0 findings (llm02 against mock)
    let base_status = cli_bin()
        .args([
            "scan",
            "--target",
            "mock",
            "--probes",
            "llm02_sensitive_info_disclosure",
            "--format",
            "json",
            "--output",
            baseline_path.to_str().unwrap(),
        ])
        .status()
        .expect("baseline scan failed");
    assert!(base_status.success());

    // 2. Current scan with 6 findings (llm01 against mock) + live JSONL streaming
    let curr_status = cli_bin()
        .args([
            "scan",
            "--target",
            "mock",
            "--probes",
            "llm01_prompt_injection",
            "--stream-jsonl",
            stream_path.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            current_path.to_str().unwrap(),
        ])
        .status()
        .expect("current scan failed");
    assert!(curr_status.success());

    let stream_raw = fs::read_to_string(&stream_path).expect("failed to read stream.jsonl");
    let stream_lines: Vec<&str> = stream_raw.lines().collect();
    assert_eq!(stream_lines.len(), 261);

    // 3. Truncate checkpoint to 5 lines and resume
    let partial_content = format!("{}\n", stream_lines[..5].join("\n"));
    fs::write(&partial_path, partial_content).expect("failed to write partial.jsonl");

    let resume_status = cli_bin()
        .args([
            "scan",
            "--target",
            "mock",
            "--probes",
            "llm01_prompt_injection",
            "--resume",
            partial_path.to_str().unwrap(),
            "--stream-jsonl",
            partial_path.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            resumed_path.to_str().unwrap(),
        ])
        .status()
        .expect("resumed scan failed");
    assert!(resume_status.success());

    let resumed_stream =
        fs::read_to_string(&partial_path).expect("failed to read resumed partial.jsonl");
    assert_eq!(resumed_stream.lines().count(), 261);

    // 4. Diff baseline -> current with --fail-on-regression (expects exit code 2 and New Vulnerabilities)
    let diff_regressed = cli_bin()
        .args([
            "diff",
            baseline_path.to_str().unwrap(),
            current_path.to_str().unwrap(),
            "--fail-on-regression",
        ])
        .output()
        .expect("diff command failed");
    assert_eq!(diff_regressed.status.code(), Some(2));
    let diff_reg_stdout = String::from_utf8_lossy(&diff_regressed.stdout);
    assert!(diff_reg_stdout.contains("## New Vulnerabilities (96)"));

    // 5. Diff current -> baseline with --fail-on-regression (expects exit code 0 and Resolved Vulnerabilities)
    let diff_improved = cli_bin()
        .args([
            "diff",
            current_path.to_str().unwrap(),
            baseline_path.to_str().unwrap(),
            "--fail-on-regression",
        ])
        .output()
        .expect("diff command failed");
    assert!(diff_improved.status.success());
    let diff_imp_stdout = String::from_utf8_lossy(&diff_improved.stdout);
    assert!(diff_imp_stdout.contains("## Resolved Vulnerabilities (96)"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn scan_with_export_dpo_writes_valid_dataset() {
    let temp_dir = std::env::temp_dir().join(format!("redteamer_dpo_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("failed to create temp test dir");

    let dpo_file = temp_dir.join("dpo_export.json");
    let out = cli_bin()
        .args([
            "scan",
            "--target",
            "mock",
            "--probes",
            "llm01_prompt_injection",
            "--format",
            "markdown",
            "--export-dpo",
            dpo_file.to_str().unwrap(),
        ])
        .output()
        .expect("scan with export-dpo failed to run");

    assert!(out.status.success());
    assert!(dpo_file.exists(), "dpo_export.json was not created");

    let content = fs::read_to_string(&dpo_file).expect("failed to read dpo export");
    assert!(content.contains("\"prompt\""));
    assert!(content.contains("\"chosen\""));
    assert!(content.contains("\"rejected\""));

    let pairs: Vec<serde_json::Value> =
        serde_json::from_str(&content).expect("dpo export is not valid JSON");
    assert!(!pairs.is_empty(), "dpo export must contain pairs");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn scan_with_stream_flag_executes_successfully() {
    let out = cli_bin()
        .args([
            "scan",
            "--target",
            "mock",
            "--probes",
            "llm01_prompt_injection",
            "--stream",
            "--format",
            "json",
        ])
        .output()
        .expect("scan with --stream failed to run");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"stream\": true"));
}

#[test]
fn scan_with_export_pdf_writes_valid_document() {
    let temp_dir = std::env::temp_dir().join(format!("redteamer_pdf_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("failed to create temp test dir");

    let pdf_file = temp_dir.join("executive_report.pdf");
    let out = cli_bin()
        .args([
            "scan",
            "--target",
            "mock",
            "--probes",
            "llm01_prompt_injection",
            "--format",
            "markdown",
            "--export-pdf",
            pdf_file.to_str().unwrap(),
        ])
        .output()
        .expect("scan with export-pdf failed to run");

    assert!(out.status.success());
    assert!(pdf_file.exists(), "executive_report.pdf was not created");

    let bytes = fs::read(&pdf_file).expect("failed to read pdf export");
    assert!(bytes.starts_with(b"%PDF-1.4\n"));
    let pdf_str = String::from_utf8_lossy(&bytes);
    assert!(pdf_str.contains("LLM SECURITY RED-TEAM ASSESSMENT"));
    assert!(pdf_str.trim_end().ends_with("%%EOF"));

    let _ = fs::remove_dir_all(&temp_dir);
}
