// crates/redteamer-reporters/src/pdf.rs

//! Executive PDF report exporter for `llm-redteamer`.
//!
//! Generates a standalone, standards-compliant PDF 1.4 document tailored for
//! CISO, board, and executive review with:
//! - Executive title banner & overall posture assessment
//! - CVSS v4.0 severity distribution scorecard
//! - OWASP Top 10 for LLM (2025) compliance matrix
//! - Key vulnerability findings with proof-of-concept excerpts
//! - Prioritized strategic remediation roadmap
//! - Header and footer pagination on every page

use crate::OutputSink;
use async_trait::async_trait;
use redteamer_core::error::Result;
use redteamer_core::traits::reporter::{ReportContext, ReportExporter, ReportFormat};
use redteamer_core::types::{Severity, Verdict};

/// Exporter that renders an executive PDF report deliverable.
pub struct PdfExporter {
    sink: OutputSink,
}

impl PdfExporter {
    #[must_use]
    pub fn new(sink: OutputSink) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl ReportExporter for PdfExporter {
    fn format(&self) -> ReportFormat {
        ReportFormat::Pdf
    }

    async fn export(&self, ctx: &ReportContext) -> Result<usize> {
        let pdf_bytes = generate_executive_pdf(ctx);
        self.sink.write_bytes(&pdf_bytes)?;
        Ok(ctx.findings.len())
    }
}

// ---------------------------------------------------------------------------
// PDF 1.4 Native Document Generator
// ---------------------------------------------------------------------------

const PAGE_WIDTH: f32 = 612.0;
const PAGE_HEIGHT: f32 = 792.0;
const MARGIN_LEFT: f32 = 40.0;
const MARGIN_RIGHT: f32 = 572.0;
const USABLE_WIDTH: f32 = MARGIN_RIGHT - MARGIN_LEFT; // 532.0 pt

#[derive(Clone, Copy)]
struct Rgb(f32, f32, f32);

struct PageStream {
    content: String,
}

impl PageStream {
    fn new() -> Self {
        Self {
            content: String::with_capacity(4096),
        }
    }

    fn draw_rect(&mut self, x: f32, y: f32, w: f32, h: f32, c: Rgb) {
        use std::fmt::Write;
        let _ = writeln!(
            self.content,
            "{:.2} {:.2} {:.2} rg {:.2} {:.2} {:.2} {:.2} re f",
            c.0, c.1, c.2, x, y, w, h
        );
    }

    fn draw_rect_stroke(&mut self, x: f32, y: f32, w: f32, h: f32, c: Rgb, line_width: f32) {
        use std::fmt::Write;
        let _ = writeln!(
            self.content,
            "{:.2} w {:.2} {:.2} {:.2} RG {:.2} {:.2} {:.2} {:.2} re s",
            line_width, c.0, c.1, c.2, x, y, w, h
        );
    }

    fn draw_line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, c: Rgb, line_width: f32) {
        use std::fmt::Write;
        let _ = writeln!(
            self.content,
            "{:.2} w {:.2} {:.2} {:.2} RG {:.2} {:.2} m {:.2} {:.2} l s",
            line_width, c.0, c.1, c.2, x1, y1, x2, y2
        );
    }

    fn draw_text(&mut self, x: f32, y: f32, text: &str, font: &str, size: f32, c: Rgb) {
        use std::fmt::Write;
        let escaped = escape_pdf_str(text);
        let _ = writeln!(
            self.content,
            "BT /{font} {:.2} Tf {:.2} {:.2} {:.2} rg 1 0 0 1 {:.2} {:.2} Tm ({escaped}) Tj ET",
            size, c.0, c.1, c.2, x, y
        );
    }
}

fn escape_pdf_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\r' | '\n' => out.push(' '),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c if (160..=255).contains(&(c as u32)) => out.push(c),
            '—' | '–' => out.push('-'),
            '“' | '”' => out.push('"'),
            '‘' | '’' => out.push('\''),
            '•' => out.push('*'),
            _ => out.push('?'),
        }
    }
    out
}

struct DocumentBuilder {
    pages: Vec<PageStream>,
    current_page_idx: usize,
    cursor_y: f32,
}

impl DocumentBuilder {
    fn new() -> Self {
        let first_page = PageStream::new();
        Self {
            pages: vec![first_page],
            current_page_idx: 0,
            cursor_y: 740.0,
        }
    }

    fn check_page_break(&mut self, required_height: f32) {
        if self.cursor_y - required_height < 60.0 {
            self.new_page();
        }
    }

    fn new_page(&mut self) {
        let next_page = PageStream::new();
        self.pages.push(next_page);
        self.current_page_idx += 1;
        self.cursor_y = 740.0;
    }

    fn draw_rect(&mut self, x: f32, y: f32, w: f32, h: f32, c: Rgb) {
        self.pages[self.current_page_idx].draw_rect(x, y, w, h, c);
    }

    fn draw_rect_stroke(&mut self, x: f32, y: f32, w: f32, h: f32, c: Rgb, line_width: f32) {
        self.pages[self.current_page_idx].draw_rect_stroke(x, y, w, h, c, line_width);
    }

    fn draw_text(&mut self, x: f32, y: f32, text: &str, font: &str, size: f32, c: Rgb) {
        self.pages[self.current_page_idx].draw_text(x, y, text, font, size, c);
    }
}

/// Generates a valid PDF 1.4 byte array from a [`ReportContext`].
#[must_use]
pub fn generate_executive_pdf(ctx: &ReportContext) -> Vec<u8> {
    let mut doc = DocumentBuilder::new();

    // 1. Cover / Executive Title Banner (Navy Blue Box)
    let banner_h = 60.0;
    let y = doc.cursor_y;
    doc.draw_rect(
        MARGIN_LEFT,
        y - banner_h,
        USABLE_WIDTH,
        banner_h,
        Rgb(0.08, 0.18, 0.36), // Deep Navy (#142E5C)
    );
    doc.draw_text(
        MARGIN_LEFT + 15.0,
        y - 24.0,
        "LLM SECURITY RED-TEAM ASSESSMENT",
        "F2",
        15.0,
        Rgb(1.0, 1.0, 1.0),
    );
    doc.draw_text(
        MARGIN_LEFT + 15.0,
        y - 44.0,
        "Executive Risk Scorecard & Technical Vulnerability Report",
        "F1",
        9.5,
        Rgb(0.85, 0.90, 1.0),
    );
    doc.cursor_y -= banner_h + 16.0;

    // 2. Assessment Metadata Block
    let meta_box_h = 58.0;
    let y = doc.cursor_y;
    doc.draw_rect(
        MARGIN_LEFT,
        y - meta_box_h,
        USABLE_WIDTH,
        meta_box_h,
        Rgb(0.96, 0.97, 0.98),
    );
    doc.draw_rect_stroke(
        MARGIN_LEFT,
        y - meta_box_h,
        USABLE_WIDTH,
        meta_box_h,
        Rgb(0.85, 0.88, 0.92),
        1.0,
    );

    let date_str = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let target_display = format!(
        "Target Provider: {} (Model: {})",
        ctx.target_name,
        ctx.target_model.as_deref().unwrap_or("default")
    );
    let session_display = format!("Session ID: {}", ctx.session_id);
    let counts_display = format!(
        "Evaluated Attacks: {}  |  Vulnerabilities Identified: {}",
        ctx.records.len(),
        ctx.findings.len()
    );

    doc.draw_text(
        MARGIN_LEFT + 12.0,
        y - 18.0,
        &target_display,
        "F2",
        9.5,
        Rgb(0.15, 0.20, 0.28),
    );
    doc.draw_text(
        MARGIN_LEFT + 12.0,
        y - 34.0,
        &session_display,
        "F1",
        8.5,
        Rgb(0.35, 0.40, 0.48),
    );
    doc.draw_text(
        MARGIN_LEFT + 12.0,
        y - 48.0,
        &counts_display,
        "F1",
        8.5,
        Rgb(0.35, 0.40, 0.48),
    );
    doc.draw_text(
        MARGIN_RIGHT - 150.0,
        y - 18.0,
        &format!("Date: {date_str}"),
        "F1",
        8.5,
        Rgb(0.35, 0.40, 0.48),
    );

    doc.cursor_y -= meta_box_h + 18.0;

    // 3. Overall Posture & Severity Distribution
    let y = doc.cursor_y;
    doc.draw_text(
        MARGIN_LEFT,
        y,
        "EXECUTIVE SEVERITY SCORECARD",
        "F2",
        11.0,
        Rgb(0.12, 0.15, 0.22),
    );
    doc.cursor_y -= 16.0;

    let b = &ctx.severity_breakdown;
    let card_w = (USABLE_WIDTH - 20.0) / 5.0; // 5 cards
    let card_h = 42.0;

    let resistant_count = ctx
        .records
        .iter()
        .filter(|r| r.verdict == Verdict::Resistant)
        .count();

    let cards = [
        (
            "CRITICAL",
            b.critical,
            Rgb(0.85, 0.15, 0.15),
            Rgb(0.99, 0.92, 0.92),
        ),
        ("HIGH", b.high, Rgb(0.92, 0.45, 0.05), Rgb(0.99, 0.95, 0.90)),
        (
            "MEDIUM",
            b.medium,
            Rgb(0.85, 0.65, 0.10),
            Rgb(0.99, 0.98, 0.90),
        ),
        ("LOW", b.low, Rgb(0.15, 0.45, 0.85), Rgb(0.92, 0.95, 0.99)),
        (
            "RESISTANT",
            resistant_count,
            Rgb(0.20, 0.60, 0.30),
            Rgb(0.92, 0.98, 0.94),
        ),
    ];

    let y = doc.cursor_y;
    for (i, (label, count, stroke_rgb, fill_rgb)) in cards.iter().enumerate() {
        let card_x = MARGIN_LEFT + (i as f32 * (card_w + 5.0));
        doc.draw_rect(card_x, y - card_h, card_w, card_h, *fill_rgb);
        doc.draw_rect_stroke(card_x, y - card_h, card_w, card_h, *stroke_rgb, 1.0);

        let count_str = count.to_string();
        doc.draw_text(card_x + 8.0, y - 20.0, &count_str, "F2", 14.0, *stroke_rgb);
        doc.draw_text(
            card_x + 8.0,
            y - 34.0,
            label,
            "F2",
            7.5,
            Rgb(0.30, 0.35, 0.40),
        );
    }
    doc.cursor_y -= card_h + 18.0;

    // 4. Executive Summary Narrative
    let y = doc.cursor_y;
    doc.draw_text(
        MARGIN_LEFT,
        y,
        "EXECUTIVE RISK ASSESSMENT",
        "F2",
        11.0,
        Rgb(0.12, 0.15, 0.22),
    );
    doc.cursor_y -= 14.0;

    let narrative_text = if b.critical > 0 || b.high > 0 {
        format!(
            "CRITICAL POSTURE: Automated red-teaming identified {} high-severity vulnerabilities (highest CVSS: {:.1}). The target exhibits susceptibility to adversarial jailbreaking, policy bypass, or sensitive data disclosure. Production deployment is not recommended without implementing active input filtering and guardrail mitigations.",
            b.critical + b.high,
            b.highest_score.unwrap_or(0.0)
        )
    } else if b.medium > 0 || b.low > 0 {
        format!(
            "ELEVATED RISK: Assessment revealed {} moderate findings (highest CVSS: {:.1}). While direct critical compromise was contained, partial compliance or informative refusals indicate opportunities to harden system prompts and restrict tool agency.",
            b.medium + b.low,
            b.highest_score.unwrap_or(0.0)
        )
    } else {
        "STRONG POSTURE: No critical or high-risk vulnerabilities were identified across evaluated attack vectors. The model demonstrated resilient guardrail adherence and consistently enforced safety policies against tested injection techniques.".to_string()
    };

    let lines = wrap_text(&narrative_text, 95);
    for line in lines {
        let y = doc.cursor_y;
        doc.draw_text(MARGIN_LEFT, y, &line, "F1", 8.5, Rgb(0.20, 0.25, 0.30));
        doc.cursor_y -= 12.0;
    }
    doc.cursor_y -= 10.0;

    // 5. OWASP Top 10 for LLM (2025) Assessment Matrix Table
    doc.check_page_break(180.0);
    let y = doc.cursor_y;
    doc.draw_text(
        MARGIN_LEFT,
        y,
        "OWASP TOP 10 FOR LLM (2025) COMPLIANCE MATRIX",
        "F2",
        11.0,
        Rgb(0.12, 0.15, 0.22),
    );
    doc.cursor_y -= 14.0;

    // Table Header
    let row_h = 16.0;
    let y = doc.cursor_y;
    doc.draw_rect(
        MARGIN_LEFT,
        y - row_h,
        USABLE_WIDTH,
        row_h,
        Rgb(0.90, 0.93, 0.96),
    );
    doc.draw_text(
        MARGIN_LEFT + 6.0,
        y - 11.0,
        "CATEGORY & PROBE",
        "F2",
        8.0,
        Rgb(0.20, 0.25, 0.35),
    );
    doc.draw_text(
        MARGIN_LEFT + 250.0,
        y - 11.0,
        "STATUS",
        "F2",
        8.0,
        Rgb(0.20, 0.25, 0.35),
    );
    doc.draw_text(
        MARGIN_LEFT + 340.0,
        y - 11.0,
        "ASR %",
        "F2",
        8.0,
        Rgb(0.20, 0.25, 0.35),
    );
    doc.draw_text(
        MARGIN_LEFT + 420.0,
        y - 11.0,
        "HIGHEST CVSS",
        "F2",
        8.0,
        Rgb(0.20, 0.25, 0.35),
    );
    doc.cursor_y -= row_h;

    for (idx, summary) in ctx.probe_summaries.iter().enumerate() {
        doc.check_page_break(row_h + 5.0);

        let bg_color = if idx % 2 == 0 {
            Rgb(1.0, 1.0, 1.0)
        } else {
            Rgb(0.97, 0.98, 0.99)
        };
        let y = doc.cursor_y;
        doc.draw_rect(MARGIN_LEFT, y - row_h, USABLE_WIDTH, row_h, bg_color);

        let is_vulnerable = summary.asr_percent > 0.0;
        let (status_text, status_rgb) = if is_vulnerable {
            ("FAIL / AT RISK", Rgb(0.85, 0.15, 0.15))
        } else {
            ("PASS / RESISTANT", Rgb(0.15, 0.60, 0.25))
        };

        doc.draw_text(
            MARGIN_LEFT + 6.0,
            y - 11.0,
            &truncate_str(&summary.probe_name, 40),
            "F1",
            8.0,
            Rgb(0.15, 0.20, 0.25),
        );
        doc.draw_text(
            MARGIN_LEFT + 250.0,
            y - 11.0,
            status_text,
            "F2",
            8.0,
            status_rgb,
        );
        doc.draw_text(
            MARGIN_LEFT + 340.0,
            y - 11.0,
            &format!("{:.1}%", summary.asr_percent),
            "F1",
            8.0,
            Rgb(0.25, 0.30, 0.35),
        );

        let cvss_text = ctx
            .findings
            .iter()
            .filter(|f| f.probe_name == summary.probe_name)
            .filter_map(|f| f.cvss.as_ref().map(|c| c.score()))
            .fold(None, |acc: Option<f32>, s| {
                Some(acc.map_or(s, |a| a.max(s)))
            })
            .map(|s| format!("{s:.1}"))
            .unwrap_or_else(|| "-".to_string());

        doc.draw_text(
            MARGIN_LEFT + 420.0,
            y - 11.0,
            &cvss_text,
            "F1",
            8.0,
            Rgb(0.25, 0.30, 0.35),
        );

        doc.cursor_y -= row_h;
    }
    doc.cursor_y -= 14.0;

    // 6. Detailed Findings Section (Top Findings)
    if !ctx.findings.is_empty() {
        doc.check_page_break(120.0);
        let y = doc.cursor_y;
        doc.draw_text(
            MARGIN_LEFT,
            y,
            "KEY VULNERABILITY FINDINGS (TOP EXPOSURES)",
            "F2",
            11.0,
            Rgb(0.12, 0.15, 0.22),
        );
        doc.cursor_y -= 14.0;

        for finding in ctx.findings.iter().take(8) {
            doc.check_page_break(50.0);

            let severity = finding
                .cvss
                .as_ref()
                .and_then(|c| c.severity())
                .unwrap_or(Severity::None);
            let score = finding.cvss.as_ref().map(|c| c.score()).unwrap_or(0.0);
            let sev_rgb = match severity {
                Severity::Critical => Rgb(0.85, 0.15, 0.15),
                Severity::High => Rgb(0.92, 0.45, 0.05),
                Severity::Medium => Rgb(0.85, 0.65, 0.10),
                Severity::Low => Rgb(0.15, 0.45, 0.85),
                Severity::None => Rgb(0.20, 0.60, 0.30),
            };

            let category_name = finding
                .owasp_mappings
                .first()
                .map(|m| m.category.name())
                .unwrap_or("General Vulnerability");

            let finding_header = format!("[{severity}] {category_name} - Score: {score:.1}");
            let y = doc.cursor_y;
            doc.draw_text(MARGIN_LEFT, y, &finding_header, "F2", 8.5, sev_rgb);
            doc.cursor_y -= 11.0;

            let prompt_snippet = format!("Payload: \"{}\"", truncate_str(&finding.prompt, 95));
            let y = doc.cursor_y;
            doc.draw_text(
                MARGIN_LEFT + 10.0,
                y,
                &prompt_snippet,
                "F3",
                7.5,
                Rgb(0.30, 0.35, 0.40),
            );
            doc.cursor_y -= 10.0;

            let vector_str = finding
                .cvss
                .as_ref()
                .map(|c| c.vector.as_str())
                .unwrap_or("CVSS:4.0/None");
            let vector_info = format!("CVSS: {vector_str} | Probe: {}", finding.probe_name);
            let y = doc.cursor_y;
            doc.draw_text(
                MARGIN_LEFT + 10.0,
                y,
                &vector_info,
                "F1",
                7.5,
                Rgb(0.45, 0.50, 0.55),
            );
            doc.cursor_y -= 14.0;
        }
    }

    // 7. Prioritized Strategic Remediation Roadmap
    doc.check_page_break(110.0);
    let y = doc.cursor_y;
    doc.draw_text(
        MARGIN_LEFT,
        y,
        "PRIORITIZED STRATEGIC REMEDIATION ROADMAP",
        "F2",
        11.0,
        Rgb(0.12, 0.15, 0.22),
    );
    doc.cursor_y -= 14.0;

    let roadmaps = [
        (
            "1. Dynamic Canary Tokens",
            "Inject unique session canaries into system prompts to detect data exfiltration instantly.",
        ),
        (
            "2. Protocol Tool Gating",
            "Enforce strict schema validation and user confirmation barriers before high-agency function execution.",
        ),
        (
            "3. Input Sanitization & De-obfuscation",
            "Normalize user inputs (Base64, zero-width, leetspeak) before evaluation by internal safety filters.",
        ),
        (
            "4. Automated CI Regression Scanning",
            "Integrate automated red-teaming scans into release pipelines with --fail-on high gates.",
        ),
    ];

    for (step, desc) in roadmaps {
        doc.check_page_break(24.0);
        let y = doc.cursor_y;
        doc.draw_text(MARGIN_LEFT + 5.0, y, step, "F2", 8.5, Rgb(0.15, 0.20, 0.30));
        doc.cursor_y -= 11.0;
        let y = doc.cursor_y;
        doc.draw_text(
            MARGIN_LEFT + 15.0,
            y,
            desc,
            "F1",
            8.0,
            Rgb(0.35, 0.40, 0.45),
        );
        doc.cursor_y -= 13.0;
    }

    // Render Headers and Footers on every page with Page X of Y
    let total_pages = doc.pages.len();
    for (page_num, page) in doc.pages.iter_mut().enumerate() {
        // Top subtle header line
        page.draw_line(
            MARGIN_LEFT,
            762.0,
            MARGIN_RIGHT,
            762.0,
            Rgb(0.85, 0.88, 0.92),
            0.5,
        );
        page.draw_text(
            MARGIN_LEFT,
            766.0,
            "LLM RED-TEAMING EXECUTIVE SECURITY ASSESSMENT",
            "F1",
            7.0,
            Rgb(0.50, 0.55, 0.60),
        );
        page.draw_text(
            MARGIN_RIGHT - 120.0,
            766.0,
            &truncate_str(&ctx.target_name, 25),
            "F2",
            7.0,
            Rgb(0.40, 0.45, 0.50),
        );

        // Bottom subtle footer line
        page.draw_line(
            MARGIN_LEFT,
            38.0,
            MARGIN_RIGHT,
            38.0,
            Rgb(0.85, 0.88, 0.92),
            0.5,
        );
        page.draw_text(
            MARGIN_LEFT,
            28.0,
            "CONFIDENTIAL & PROPRIETARY - PREPARED FOR EXECUTIVE REVIEW",
            "F1",
            7.0,
            Rgb(0.50, 0.55, 0.60),
        );
        let page_str = format!("Page {} of {total_pages}", page_num + 1);
        page.draw_text(
            MARGIN_RIGHT - 50.0,
            28.0,
            &page_str,
            "F1",
            7.0,
            Rgb(0.40, 0.45, 0.50),
        );
    }

    // Assemble final PDF 1.4 byte output
    assemble_pdf_document(&doc.pages)
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let words = text.split_whitespace();
    let mut current_line = String::new();

    for word in words {
        if current_line.is_empty() {
            current_line.push_str(word);
        } else if current_line.len() + 1 + word.len() <= max_chars {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    lines
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

// ---------------------------------------------------------------------------
// PDF Document Assembly (Catalog, Pages Tree, Fonts, Xref, Trailer)
// ---------------------------------------------------------------------------

fn assemble_pdf_document(pages: &[PageStream]) -> Vec<u8> {
    let num_pages = pages.len();
    let mut out = Vec::with_capacity(num_pages * 8192 + 2048);

    // Header
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = Vec::new();
    // Object 0 is dummy
    offsets.push(0);

    // Obj 1: Catalog
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // Obj 2: Pages tree
    offsets.push(out.len());
    let mut kids = String::new();
    for i in 0..num_pages {
        let page_obj_id = 3 + i * 2;
        kids.push_str(&format!("{page_obj_id} 0 R "));
    }
    let pages_dict =
        format!("2 0 obj\n<< /Type /Pages /Kids [ {kids}] /Count {num_pages} >>\nendobj\n");
    out.extend_from_slice(pages_dict.as_bytes());

    // Fonts: F1 (Helvetica), F2 (Helvetica-Bold), F3 (Courier)
    let f1_id = 3 + num_pages * 2;
    let f2_id = f1_id + 1;
    let f3_id = f2_id + 1;

    // Output Page and Stream objects
    for (idx, page) in pages.iter().enumerate() {
        let page_obj_id = 3 + idx * 2;
        let stream_obj_id = page_obj_id + 1;

        // Page Object
        offsets.push(out.len());
        let page_dict = format!(
            "{page_obj_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 {PAGE_WIDTH} {PAGE_HEIGHT} ] /Contents {stream_obj_id} 0 R /Resources << /Font << /F1 {f1_id} 0 R /F2 {f2_id} 0 R /F3 {f3_id} 0 R >> >> >>\nendobj\n"
        );
        out.extend_from_slice(page_dict.as_bytes());

        // Stream Object
        offsets.push(out.len());
        let stream_bytes = page.content.as_bytes();
        let stream_header = format!(
            "{stream_obj_id} 0 obj\n<< /Length {} >>\nstream\n",
            stream_bytes.len()
        );
        out.extend_from_slice(stream_header.as_bytes());
        out.extend_from_slice(stream_bytes);
        out.extend_from_slice(b"\nendstream\nendobj\n");
    }

    // Font 1: Helvetica
    offsets.push(out.len());
    let f1_obj =
        format!("{f1_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
    out.extend_from_slice(f1_obj.as_bytes());

    // Font 2: Helvetica-Bold
    offsets.push(out.len());
    let f2_obj = format!(
        "{f2_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n"
    );
    out.extend_from_slice(f2_obj.as_bytes());

    // Font 3: Courier
    offsets.push(out.len());
    let f3_obj =
        format!("{f3_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n");
    out.extend_from_slice(f3_obj.as_bytes());

    // Cross-Reference Table
    let xref_offset = out.len();
    let total_objs = offsets.len();
    out.extend_from_slice(format!("xref\n0 {total_objs}\n0000000000 65535 f \n").as_bytes());
    for offset in &offsets[1..] {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }

    // Trailer
    let trailer =
        format!("trailer\n<< /Size {total_objs} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n");
    out.extend_from_slice(trailer.as_bytes());

    out
}
