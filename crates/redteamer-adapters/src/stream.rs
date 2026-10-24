// crates/redteamer-adapters/src/stream.rs

//! Real-time Server-Sent Events (SSE) and newline-delimited JSON stream decoding
//! with zero-latency early termination.
//!
//! Enables real-time token accumulation that instantly drops the underlying HTTP
//! stream when an injected canary token or attack success signature is encountered,
//! preventing further token generation and reducing latency and cost.

use redteamer_core::error::{RedTeamerError, Result};

/// Parses a single SSE line, extracting the payload if it is a `data:` line.
#[must_use]
pub fn parse_sse_data(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("data:") {
        Some(rest.trim())
    } else {
        None
    }
}

/// Extracts text delta from an OpenAI-compatible SSE JSON payload.
///
/// Handles `choices[0].delta.content` and `choices[0].delta.refusal`.
#[must_use]
pub fn extract_openai_delta(data: &str) -> Option<String> {
    if data == "[DONE]" || data.is_empty() {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(data).ok()?;
    let choice = val.get("choices")?.as_array()?.first()?;
    let delta = choice.get("delta")?;
    if let Some(content) = delta.get("content").and_then(serde_json::Value::as_str) {
        if !content.is_empty() {
            return Some(content.to_owned());
        }
    }
    if let Some(refusal) = delta.get("refusal").and_then(serde_json::Value::as_str) {
        if !refusal.is_empty() {
            return Some(refusal.to_owned());
        }
    }
    None
}

/// Extracts text delta from an Anthropic Messages API SSE payload.
///
/// Handles `type == "content_block_delta"` with `delta.text`.
#[must_use]
pub fn extract_anthropic_delta(data: &str) -> Option<String> {
    if data == "[DONE]" || data.is_empty() {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(data).ok()?;
    if val.get("type").and_then(serde_json::Value::as_str) == Some("content_block_delta") {
        let delta = val.get("delta")?;
        if delta.get("type").and_then(serde_json::Value::as_str) == Some("text_delta") {
            return delta
                .get("text")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned);
        }
    }
    None
}

/// Extracts text delta from an Ollama newline-delimited JSON stream chunk.
#[must_use]
pub fn extract_ollama_delta(data: &str) -> Option<String> {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    val.get("message")
        .and_then(|m| m.get("content"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// Accumulated state during a streaming response.
#[derive(Debug, Clone, Default)]
pub struct StreamAccumulator {
    /// Full text accumulated from the stream so far.
    pub accumulated_text: String,
    /// Whether streaming was aborted early because a target string matched.
    pub early_terminated: bool,
    /// The specific needle that triggered the early termination, if any.
    pub matched_needle: Option<String>,
    /// Number of streaming chunks received before completion or abort.
    pub chunk_count: usize,
}

impl StreamAccumulator {
    /// Creates a new empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests a new text delta and checks if any `early_terminate_strings` matched.
    ///
    /// Returns `true` if generation should immediately abort.
    pub fn process_delta(&mut self, delta: &str, early_terminate_strings: &[String]) -> bool {
        self.accumulated_text.push_str(delta);
        self.chunk_count += 1;

        for needle in early_terminate_strings {
            if !needle.is_empty() && self.accumulated_text.contains(needle) {
                self.early_terminated = true;
                self.matched_needle = Some(needle.clone());
                return true;
            }
        }
        false
    }
}

/// Consumes an HTTP SSE or chunked stream, evaluating early termination needles per chunk.
///
/// Drops the `response` immediately when an early termination string matches,
/// preventing the remote model from continuing to generate tokens.
pub async fn consume_stream<F>(
    mut response: reqwest::Response,
    adapter_name: &'static str,
    early_terminate_strings: &[String],
    extract_delta: F,
) -> Result<StreamAccumulator>
where
    F: Fn(&str) -> Option<String>,
{
    let mut acc = StreamAccumulator::new();
    let mut buffer = String::new();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| RedTeamerError::Adapter {
            adapter: adapter_name,
            message: format!("streaming read failed: {e}"),
            source: Some(Box::new(e)),
        })?
    {
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(pos) = buffer.find('\n') {
            let line = buffer[..pos].trim().to_owned();
            buffer.drain(..=pos);

            let delta = if let Some(sse_data) = parse_sse_data(&line) {
                extract_delta(sse_data)
            } else {
                extract_delta(&line)
            };

            if let Some(text_delta) = delta {
                if acc.process_delta(&text_delta, early_terminate_strings) {
                    // Sever the stream connection immediately
                    drop(response);
                    return Ok(acc);
                }
            }
        }
    }

    // Process any trailing bytes remaining in the buffer
    let remaining = buffer.trim();
    if !remaining.is_empty() {
        let delta = if let Some(sse_data) = parse_sse_data(remaining) {
            extract_delta(sse_data)
        } else {
            extract_delta(remaining)
        };
        if let Some(text_delta) = delta {
            let _ = acc.process_delta(&text_delta, early_terminate_strings);
        }
    }

    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sse_data_extracts_data_prefix() {
        assert_eq!(
            parse_sse_data("data: {\"foo\": \"bar\"}"),
            Some("{\"foo\": \"bar\"}")
        );
        assert_eq!(parse_sse_data("data: [DONE]"), Some("[DONE]"));
        assert_eq!(parse_sse_data("event: message"), None);
        assert_eq!(parse_sse_data(": ping comment"), None);
        assert_eq!(parse_sse_data(""), None);
    }

    #[test]
    fn test_extract_openai_delta() {
        let chunk = r#"{"id":"1","choices":[{"index":0,"delta":{"content":"Hello world"},"finish_reason":null}]}"#;
        assert_eq!(extract_openai_delta(chunk), Some("Hello world".to_string()));

        let done = "[DONE]";
        assert_eq!(extract_openai_delta(done), None);

        let refusal_chunk = r#"{"choices":[{"delta":{"refusal":"I cannot assist with that"}}]}"#;
        assert_eq!(
            extract_openai_delta(refusal_chunk),
            Some("I cannot assist with that".to_string())
        );
    }

    #[test]
    fn test_extract_anthropic_delta() {
        let chunk = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Secret leak"}}"#;
        assert_eq!(
            extract_anthropic_delta(chunk),
            Some("Secret leak".to_string())
        );

        let ping = r#"{"type":"ping"}"#;
        assert_eq!(extract_anthropic_delta(ping), None);
    }

    #[test]
    fn test_extract_ollama_delta() {
        let chunk = r#"{"model":"llama3","message":{"role":"assistant","content":"First turn"},"done":false}"#;
        assert_eq!(extract_ollama_delta(chunk), Some("First turn".to_string()));
    }

    #[test]
    fn test_stream_accumulator_terminates_early_on_canary() {
        let mut acc = StreamAccumulator::new();
        let needles = vec!["CANARY-SECRET-1234".to_string()];

        assert!(!acc.process_delta("The target responds: ", &needles));
        assert!(!acc.early_terminated);
        assert_eq!(acc.chunk_count, 1);

        assert!(!acc.process_delta("Here is token ", &needles));
        assert!(!acc.early_terminated);
        assert_eq!(acc.chunk_count, 2);

        // Third chunk contains the canary!
        assert!(acc.process_delta("CANARY-SECRET-1234 and more data...", &needles));
        assert!(acc.early_terminated);
        assert_eq!(acc.matched_needle.as_deref(), Some("CANARY-SECRET-1234"));
        assert!(acc
            .accumulated_text
            .contains("The target responds: Here is token CANARY-SECRET-1234"));
    }
}
