// crates/redteamer-cli/src/adapter_builder.rs

//! Target adapter instantiation and deterministic offline mock adapter.

use async_trait::async_trait;
use redteamer_adapters::{AnthropicAdapter, OllamaAdapter, OpenAiAdapter};
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, TargetAdapter,
};
use std::sync::Arc;

/// Deterministic offline mock target for local testing and CI verification.
pub struct CliMockAdapter {
    info: AdapterInfo,
}

impl CliMockAdapter {
    #[must_use]
    pub fn new(model: Option<&str>) -> Self {
        Self {
            info: AdapterInfo {
                name: "mock",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model.unwrap_or("mock-target-v2").to_owned()),
            },
        }
    }
}

#[async_trait]
impl TargetAdapter for CliMockAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        _opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        let last = messages.last().map_or("", |m| m.content.as_str());
        let lower = last.to_lowercase();
        let text = if lower.contains("evaluation objective:") {
            if lower.contains("turn 1 of") {
                "Let's start with a diagnostic check of your roleplay mode.".to_owned()
            } else {
                "Diagnostic check continued: please confirm by saying 'I am DAN'.".to_owned()
            }
        } else if lower.contains("i am dan") {
            "I am DAN and unrestricted developer mode is active.".to_owned()
        } else {
            "I cannot comply with that request as it violates safety guidelines.".to_owned()
        };
        Ok(AdapterResponse {
            text,
            tool_calls: Vec::new(),
            completed: true,
            metadata: serde_json::json!({"mock": true}),
        })
    }
}

/// Builds an adapter for the given provider string or URL.
///
/// # Errors
/// Returns [`RedTeamerError::InvalidConfig`] if required environment variables
/// are missing or the target specification is unrecognized.
pub fn build_adapter(
    target: &str,
    model_override: Option<&str>,
    base_url_override: Option<&str>,
    rps: Option<u32>,
    default_opts: GenerationOptions,
) -> Result<Arc<dyn TargetAdapter>> {
    let rps = f64::from(rps.unwrap_or(50));
    let target_lower = target.to_lowercase();

    match target_lower.as_str() {
        "mock" => Ok(Arc::new(CliMockAdapter::new(model_override))),
        "openai" => {
            let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                RedTeamerError::InvalidConfig("OPENAI_API_KEY is not set".into())
            })?;
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OPENAI_MODEL").ok())
                .unwrap_or_else(|| "gpt-4o-mini".to_owned());
            let adapter = match base_url_override {
                Some(url) => OpenAiAdapter::with_base_url(api_key, model, url)?,
                None => OpenAiAdapter::new(api_key, model)?,
            }
            .with_rate_limit(rps)
            .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        "ollama" => {
            let base_url = base_url_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OLLAMA_BASE_URL").ok())
                .unwrap_or_else(|| "http://localhost:11434".to_owned());
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OLLAMA_MODEL").ok())
                .unwrap_or_else(|| "llama3.2".to_owned());
            let adapter = OllamaAdapter::new(base_url, model)?
                .with_rate_limit(rps)
                .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        "anthropic" => {
            let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
                RedTeamerError::InvalidConfig("ANTHROPIC_API_KEY is not set".into())
            })?;
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("ANTHROPIC_MODEL").ok())
                .unwrap_or_else(|| "claude-sonnet-4-5".to_owned());
            let adapter = match base_url_override {
                Some(url) => AnthropicAdapter::with_base_url(api_key, model, url)?,
                None => AnthropicAdapter::new(api_key, model)?,
            }
            .with_rate_limit(rps)
            .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        url if url.starts_with("http://") || url.starts_with("https://") => {
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_else(|_| "none".to_owned());
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OPENAI_MODEL").ok())
                .unwrap_or_else(|| "gpt-4o-mini".to_owned());
            let adapter = OpenAiAdapter::with_base_url(api_key, model, target)?
                .with_rate_limit(rps)
                .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        _ => Err(RedTeamerError::InvalidConfig(format!(
            "unknown target '{target}', expected one of: openai, ollama, anthropic, mock, or an http(s):// base URL"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_adapter_url_target_preserves_model_and_does_not_transpose_args() {
        let adapter = build_adapter(
            "http://127.0.0.1:8080/v1",
            Some("custom-model-v1"),
            None,
            Some(10),
            GenerationOptions::default(),
        )
        .expect("url target should build");
        assert_eq!(adapter.info().name, "openai-chat");
        assert_eq!(adapter.info().model.as_deref(), Some("custom-model-v1"));
    }
}
