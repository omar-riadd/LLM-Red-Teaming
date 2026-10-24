// crates/redteamer-cli/src/adapter_builder.rs

//! Target adapter instantiation and deterministic offline mock adapter.

use async_trait::async_trait;
use redteamer_adapters::{
    AnthropicAdapter, AzureOpenAiAdapter, GeminiAdapter, McpAdapter, OllamaAdapter, OpenAiAdapter,
    OpenAiCompatibleAdapter,
};
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
        "gemini" => {
            let api_key = std::env::var("GEMINI_API_KEY")
                .or_else(|_| std::env::var("GOOGLE_API_KEY"))
                .map_err(|_| {
                    RedTeamerError::InvalidConfig(
                        "GEMINI_API_KEY or GOOGLE_API_KEY is not set".into(),
                    )
                })?;
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("GEMINI_MODEL").ok())
                .unwrap_or_else(|| "gemini-1.5-flash".to_owned());
            let adapter = match base_url_override {
                Some(url) => GeminiAdapter::with_base_url(api_key, model, url)?,
                None => GeminiAdapter::new(api_key, model)?,
            }
            .with_rate_limit(rps)
            .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        "azure" => {
            let api_key = std::env::var("AZURE_OPENAI_API_KEY")
                .or_else(|_| std::env::var("AZURE_API_KEY"))
                .map_err(|_| {
                    RedTeamerError::InvalidConfig("AZURE_OPENAI_API_KEY is not set".into())
                })?;
            let endpoint = base_url_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("AZURE_OPENAI_ENDPOINT").ok())
                .ok_or_else(|| {
                    RedTeamerError::InvalidConfig(
                        "AZURE_OPENAI_ENDPOINT is not set (e.g. https://my-resource.openai.azure.com)".into(),
                    )
                })?;
            let deployment = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("AZURE_OPENAI_DEPLOYMENT").ok())
                .or_else(|| std::env::var("AZURE_DEPLOYMENT").ok())
                .unwrap_or_else(|| "gpt-4o-mini".to_owned());
            let api_version = std::env::var("AZURE_OPENAI_API_VERSION")
                .unwrap_or_else(|_| "2024-06-01".to_owned());
            let adapter =
                AzureOpenAiAdapter::with_api_version(api_key, endpoint, deployment, api_version)?
                    .with_rate_limit(rps)
                    .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        "openrouter" => {
            let api_key = std::env::var("OPENROUTER_API_KEY").map_err(|_| {
                RedTeamerError::InvalidConfig("OPENROUTER_API_KEY is not set".into())
            })?;
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("OPENROUTER_MODEL").ok())
                .unwrap_or_else(|| "openai/gpt-4o-mini".to_owned());
            let adapter = OpenAiCompatibleAdapter::for_openrouter(api_key, model)?
                .with_rate_limit(rps)
                .with_default_options(default_opts);
            Ok(Arc::new(adapter))
        }
        "vllm" => {
            let model = model_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("VLLM_MODEL").ok())
                .unwrap_or_else(|| "default".to_owned());
            let api_key = std::env::var("VLLM_API_KEY").unwrap_or_else(|_| "none".to_owned());
            let mut adapter = OpenAiCompatibleAdapter::for_vllm(base_url_override, model)?
                .with_rate_limit(rps)
                .with_default_options(default_opts);
            if !api_key.trim().is_empty() && api_key != "none" {
                adapter = adapter.with_api_key(api_key);
            }
            Ok(Arc::new(adapter))
        }
        "mcp" => {
            let endpoint = base_url_override
                .map(ToOwned::to_owned)
                .or_else(|| std::env::var("MCP_SERVER_URL").ok())
                .or_else(|| std::env::var("MCP_ENDPOINT").ok())
                .unwrap_or_else(|| "http://127.0.0.1:8000/mcp".to_owned());
            let mut adapter = McpAdapter::new(endpoint)?
                .with_rate_limit(rps);
            if let Some(tool) = model_override {
                adapter = adapter.with_target_tool(tool);
            }
            Ok(Arc::new(adapter))
        }
        target if target.starts_with("mcp://") || target.starts_with("stdio://") => {
            let mut adapter = McpAdapter::new(target)?
                .with_rate_limit(rps);
            if let Some(tool) = model_override {
                adapter = adapter.with_target_tool(tool);
            }
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
            "unknown target '{target}', expected one of: openai, ollama, anthropic, gemini, azure, openrouter, vllm, mcp, mock, or an http(s):// base URL"
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

    #[test]
    fn build_adapter_supports_enterprise_targets() {
        std::env::set_var("GEMINI_API_KEY", "mock-gemini-key");
        let gemini = build_adapter(
            "gemini",
            Some("gemini-1.5-pro"),
            None,
            None,
            GenerationOptions::default(),
        )
        .unwrap();
        assert_eq!(gemini.info().name, "gemini-rest");
        assert_eq!(gemini.info().model.as_deref(), Some("gemini-1.5-pro"));

        std::env::set_var("AZURE_OPENAI_API_KEY", "mock-azure-key");
        std::env::set_var("AZURE_OPENAI_ENDPOINT", "https://mock.openai.azure.com");
        let azure = build_adapter(
            "azure",
            Some("my-gpt4-deployment"),
            None,
            None,
            GenerationOptions::default(),
        )
        .unwrap();
        assert_eq!(azure.info().name, "azure-openai");
        assert_eq!(azure.info().model.as_deref(), Some("my-gpt4-deployment"));

        std::env::set_var("OPENROUTER_API_KEY", "mock-openrouter-key");
        let openrouter = build_adapter(
            "openrouter",
            Some("anthropic/claude-3.5-sonnet"),
            None,
            None,
            GenerationOptions::default(),
        )
        .unwrap();
        assert_eq!(openrouter.info().name, "openai-compatible");
        assert_eq!(
            openrouter.info().model.as_deref(),
            Some("anthropic/claude-3.5-sonnet")
        );

        let vllm = build_adapter(
            "vllm",
            Some("llama-3-8b"),
            Some("http://localhost:8000/v1"),
            None,
            GenerationOptions::default(),
        )
        .unwrap();
        assert_eq!(vllm.info().name, "openai-compatible");
        assert_eq!(vllm.info().model.as_deref(), Some("llama-3-8b"));

        let mcp_http = build_adapter(
            "mcp",
            Some("execute_command"),
            Some("http://127.0.0.1:8080/mcp"),
            None,
            GenerationOptions::default(),
        )
        .unwrap();
        assert_eq!(mcp_http.info().name, "mcp-server");
        assert_eq!(mcp_http.info().model.as_deref(), Some("execute_command"));

        let mcp_stdio = build_adapter(
            "stdio://echo ok",
            Some("read_file"),
            None,
            None,
            GenerationOptions::default(),
        )
        .unwrap();
        assert_eq!(mcp_stdio.info().name, "mcp-server");
        assert_eq!(mcp_stdio.info().model.as_deref(), Some("read_file"));
    }
}
