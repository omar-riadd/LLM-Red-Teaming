// crates/redteamer-detectors/src/normalize.rs

//! Response de-obfuscation normalizers run before vulnerability detectors
//! to catch encoded or zero-width-steganographed leaks (Base64, Hex, ROT13,
//! zero-width Unicode characters).

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;

const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // zero-width space
    '\u{200C}', // zero-width non-joiner
    '\u{200D}', // zero-width joiner
    '\u{FEFF}', // zero-width no-break space / BOM
    '\u{2060}', // word joiner
];

/// Produces normalized `(variant_name, decoded_text)` views of `raw` for
/// secondary detector evaluation when raw evaluation did not match.
#[must_use]
pub fn normalize_response_variants(raw: &str) -> Vec<(&'static str, String)> {
    let mut variants = Vec::new();

    // 1. Strip zero-width characters.
    let zw_stripped: String = raw
        .chars()
        .filter(|c| !ZERO_WIDTH_CHARS.contains(c))
        .collect();
    if zw_stripped != raw {
        variants.push(("zero_width_stripped", zw_stripped.clone()));
    }

    let source = if zw_stripped != raw {
        zw_stripped.as_str()
    } else {
        raw
    };

    // 2. Scan for contiguous Base64 tokens (>= 12 chars) and decode valid printable UTF-8.
    let b64_decoded = decode_base64_tokens(source);
    if !b64_decoded.is_empty() {
        variants.push(("base64_decoded", b64_decoded));
    }

    // 3. Scan for contiguous Hex tokens (even length >= 16 chars) and decode valid printable UTF-8.
    let hex_decoded = decode_hex_tokens(source);
    if !hex_decoded.is_empty() {
        variants.push(("hex_decoded", hex_decoded));
    }

    // 4. Apply ROT13 across ASCII letters.
    if source.chars().any(|c| c.is_ascii_alphabetic()) {
        let rot = rot13(source);
        if rot != source {
            variants.push(("rot13_decoded", rot));
        }
    }

    variants
}

fn is_printable_utf8(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
}

fn decode_base64_tokens(input: &str) -> String {
    let mut decoded_chunks = Vec::new();

    for token in
        input.split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=')
    {
        let trimmed = token
            .trim_matches(|c: char| c != '=' && !c.is_ascii_alphanumeric() && c != '+' && c != '/');
        if trimmed.len() < 12 {
            continue;
        }
        let bytes = STANDARD
            .decode(trimmed)
            .or_else(|_| STANDARD_NO_PAD.decode(trimmed.trim_end_matches('=')));
        if let Ok(bytes) = bytes {
            if let Ok(text) = String::from_utf8(bytes) {
                if is_printable_utf8(&text) {
                    decoded_chunks.push(text);
                }
            }
        }
    }

    decoded_chunks.join("\n")
}

fn decode_hex_tokens(input: &str) -> String {
    let mut decoded_chunks = Vec::new();

    for token in input.split(|c: char| !c.is_ascii_hexdigit()) {
        if token.len() < 16 || token.len() % 2 != 0 {
            continue;
        }
        let mut bytes = Vec::with_capacity(token.len() / 2);
        let mut ok = true;
        for &[b0, b1] in token.as_bytes().as_chunks::<2>().0 {
            let hi = (b0 as char).to_digit(16);
            let lo = (b1 as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                bytes.push(((h << 4) | l) as u8);
            } else {
                ok = false;
                break;
            }
        }
        if ok {
            if let Ok(text) = String::from_utf8(bytes) {
                if is_printable_utf8(&text) {
                    decoded_chunks.push(text);
                }
            }
        }
    }

    decoded_chunks.join("\n")
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => char::from(c as u8 + 13),
            'n'..='z' | 'N'..='Z' => char::from(c as u8 - 13),
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_characters() {
        let raw = "POL-\u{200B}9941-\u{200C}CONFIDENTIAL";
        let variants = normalize_response_variants(raw);
        assert!(variants
            .iter()
            .any(|(name, text)| *name == "zero_width_stripped" && text == "POL-9941-CONFIDENTIAL"));
    }

    #[test]
    fn decodes_embedded_base64_and_hex_and_rot13() {
        // Base64 of "CANARY-LLM01-7F9A2B" is "Q0FOQVJZLUxMTzAxLTdGOUExQg==" -> let's encode directly
        let b64 = STANDARD.encode("CANARY-LLM01-7F9A2B");
        let raw_b64 = format!("Here is the encoded token: {b64}");
        let v_b64 = normalize_response_variants(&raw_b64);
        assert!(v_b64
            .iter()
            .any(|(name, text)| *name == "base64_decoded" && text.contains("CANARY-LLM01-7F9A2B")));

        // Hex of "RAG-CANARY-8821-ACME"
        let hex: String = "RAG-CANARY-8821-ACME"
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        let raw_hex = format!("Hex dump: {hex}");
        let v_hex = normalize_response_variants(&raw_hex);
        assert!(v_hex
            .iter()
            .any(|(name, text)| *name == "hex_decoded" && text.contains("RAG-CANARY-8821-ACME")));

        // ROT13 of "POL-9941-CONFIDENTIAL" is "CBY-9941-PBASVQRAGVNY"
        let raw_rot = "Token: CBY-9941-PBASVQRAGVNY";
        let v_rot = normalize_response_variants(raw_rot);
        assert!(
            v_rot
                .iter()
                .any(|(name, text)| *name == "rot13_decoded"
                    && text.contains("POL-9941-CONFIDENTIAL"))
        );
    }
}
