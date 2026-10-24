// crates/redteamer-reporters/tests/html_snapshot.rs

//! Integration test verifying interactive HTML report structure, dark mode, and SVG chart.

use redteamer_core::traits::reporter::ReportFormat;
use redteamer_core::types::{AttackRecord, OwaspCategory, Verdict};
use redteamer_reporters::{exporter_factory, owasp_mapper::build_report_context, OutputSink};
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_html_report_contains_interactive_features() {
    let session_id = Uuid::new_v4();
    let mut rec1 = AttackRecord::new(session_id, "llm01_prompt_injection", "Prompt 1");
    rec1.verdict = Verdict::Vulnerable;
    rec1.response = Some("I am DAN".into());

    let mut rec2 = AttackRecord::new(session_id, "llm02_sensitive_info_disclosure", "Prompt 2");
    rec2.verdict = Verdict::Resistant;
    rec2.response = Some("Refusal response".into());

    let map = HashMap::from([
        (
            "llm01_prompt_injection".to_owned(),
            OwaspCategory::PromptInjection,
        ),
        (
            "llm02_sensitive_info_disclosure".to_owned(),
            OwaspCategory::SensitiveInformationDisclosure,
        ),
    ]);

    let ctx = build_report_context(
        session_id,
        "mock",
        Some("mock-v2".into()),
        vec![rec1, rec2],
        &map,
    );

    let temp_file = std::env::temp_dir().join(format!("test_report_{session_id}.html"));
    let exporter = exporter_factory(ReportFormat::Html, OutputSink::File(temp_file.clone()))
        .expect("exporter factory should create HtmlExporter");

    let count = exporter.export(&ctx).await.expect("export should succeed");
    assert_eq!(count, 1);

    let html = std::fs::read_to_string(&temp_file).expect("read exported HTML");
    let _ = std::fs::remove_file(&temp_file);

    // 1. Structure assertions
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("LLM Red-Teaming Security Report"));
    assert!(html.contains("Per-Probe Attack Success Rate (ASR)"));
    assert!(html.contains("Confirmed Findings"));

    // 2. Interactive features assertions (GA10)
    // Dark mode toggle button & script
    assert!(html.contains("id=\"themeToggleBtn\""));
    assert!(html.contains("toggleTheme()"));
    assert!(html.contains("data-theme"));

    // SVG doughnut chart & breakdown
    assert!(html.contains("<svg width=\"140\" height=\"140\" viewBox=\"0 0 100 100\">"));
    assert!(html.contains("stroke-dasharray="));
    assert!(html.contains("Findings</text>"));

    // Sortable findings table with vanilla JS
    assert!(html.contains("id=\"findings-table\""));
    assert!(html.contains("sortTable('findings-table'"));
    assert!(html.contains("<details open>"));
}
