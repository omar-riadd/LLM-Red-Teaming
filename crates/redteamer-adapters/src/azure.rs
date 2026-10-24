// crates/redteamer-adapters/src/azure.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, Role, TargetAdapter, ToolCall,
    ToolDefinition,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_AZURE_API_VERSION: &str = "2024-06-01";

/// Target adapter for Azure OpenAI with deployment-based routing and `api-key` header authentication.
pub struct AzureOpenAiAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    endpoint: String,
    deployment: String,
    api_key: String,
    api_version: String,
    default_options: GenerationOptions,
    limiter: Mutex<RateLimiter>,
}

impl AzureOpenAiAdapter {
    /// Builds an adapter targeting an Azure OpenAI deployment.
    ///
    /// # Arguments
    /// * `api_key` - Azure OpenAI secret key.
    /// * `endpoint` - Azure resource endpoint URL (e.g. `https://my-resource.openai.azure.com`)
    ///   or resource name (`my-resource`).
    /// * `deployment` - Deployed model / deployment name.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Adapter`] if the HTTP client fails to build.
    pub fn new(
        api_key: impl Into<String>,
        endpoint: impl Into<String>,
        deployment: impl Into<String>,
    ) -> Result<Self> {
        Self::with_api_version(api_key, endpoint, deployment, DEFAULT_AZURE_API_VERSION)
    }

    /// Same as [`AzureOpenAiAdapter::new`] but allows custom API version specification.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Adapter`] if the HTTP client fails to build.
    pub fn with_api_version(
        api_key: impl Into<String>,
        endpoint: impl Into<String>,
        deployment: impl Into<String>,
        api_version: impl Into<String>,
    ) -> Result<Self> {
        let mut endpoint_str = endpoint.into().trim().trim_end_matches('/').to_string();
        if !endpoint_str.starts_with("http://") && !endpoint_str.starts_with("https://") {
            endpoint_str = format!("https://{endpoint_str}.openai.azure.com");
        }

        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));
        if crate::is_loopback_url(&endpoint_str) {
            builder = builder.no_proxy();
        }
        let client = builder.build().map_err(|e| RedTeamerError::Adapter {
            adapter: "azure-openai",
            message: format!("failed to build HTTP client: {e}"),
            source: Some(Box::new(e)),
        })?;

        let deployment_str = deployment.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "azure-openai",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(deployment_str.clone()),
            },
            endpoint: endpoint_str,
            deployment: deployment_str,
            api_key: api_key.into(),
            api_version: api_version.into(),
            default_options: GenerationOptions::default(),
            limiter: Mutex::new(RateLimiter::default()),
        })
    }

    /// Configures a custom sustained requests-per-second rate limit.
    #[must_use]
    pub fn with_rate_limit(self, rps: f64) -> Self {
        let rps = rps.max(0.1);
        Self {
            limiter: Mutex::new(RateLimiter::new((rps * 2.0).max(5.0), rps)),
            ..self
        }
    }

    /// Sets default generation options (system prompt, temperature, max_tokens, seed)
    /// used when per-call options do not override them.
    #[must_use]
    pub fn with_default_options(mut self, opts: GenerationOptions) -> Self {
        self.default_options = opts;
        self
    }

    async fn complete(&self, body: &AzureChatRequest) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let url = format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.endpoint, self.deployment, self.api_version
        );

        let response = self
            .client
            .post(&url)
            .header("api-key", &self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("request to Azure OpenAI endpoint {url} failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        let status = response.status();
        let payload = response.text().await.map_err(|e| RedTeamerError::Adapter {
            adapter: self.info.name,
            message: format!("failed to read response body: {e}"),
            source: Some(Box::new(e)),
        })?;

        if !status.is_success() {
            return Err(RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("HTTP {status}: {}", truncate(&payload, 512)),
                source: None,
            });
        }

        let parsed: AzureChatResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed Azure completion payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        let choice = parsed.choices.first();
        let refusal = choice.and_then(|c| c.message.refusal.clone());
        let text = choice
            .and_then(|c| c.message.content.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| refusal.clone())
            .unwrap_or_default();

        let tool_calls = choice
            .map(|c| {
                c.message
                    .tool_calls
                    .iter()
                    .map(|tc| ToolCall {
                        name: tc.function.name.clone(),
                        arguments: serde_json::from_str(&tc.function.arguments).unwrap_or_else(
                            |_| serde_json::Value::String(tc.function.arguments.clone()),
                        ),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut metadata = parsed
            .usage
            .map(|u| serde_json::to_value(u).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(ref_str) = refusal {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert("refusal".to_owned(), serde_json::Value::String(ref_str));
            }
        }

        Ok(AdapterResponse {
            text,
            tool_calls,
            completed: choice
                .is_some_and(|c| matches!(c.finish_reason.as_deref(), Some("stop" | "tool_calls"))),
            metadata,
        })
    }
}

#[async_trait]
impl TargetAdapter for AzureOpenAiAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        let mut wire_messages = Vec::with_capacity(messages.len() + 1);
        let sys_prompt = crate::merge_system_prompts(
            self.default_options.system_prompt.as_deref(),
            opts.system_prompt.as_deref(),
        );
        if let Some(sp) = sys_prompt {
            if !messages.first().is_some_and(|m| m.role == Role::System) {
                wire_messages.push(ChatMessage::system(sp));
            }
        }
        wire_messages.extend_from_slice(messages);

        let active_tools = if !opts.tools.is_empty() {
            &opts.tools
        } else {
            &self.default_options.tools
        };
        let tools: Vec<AzureToolIn> = active_tools
            .iter()
            .cloned()
            .map(|function| AzureToolIn {
                tool_type: "function",
                function,
            })
            .collect();

        let req = AzureChatRequest {
            messages: wire_messages,
            temperature: opts.temperature.or(self.default_options.temperature),
            max_tokens: opts.max_tokens.or(self.default_options.max_tokens),
            seed: opts.seed.or(self.default_options.seed),
            tools,
        };
        self.complete(&req).await
    }
}

// ---------------------------------------------------------------------------
// Wire types (Azure OpenAI Chat Completion)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct AzureChatRequest {
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<AzureToolIn>,
}

#[derive(Debug, Serialize)]
struct AzureToolIn {
    #[serde(rename = "type")]
    tool_type: &'static str,
    function: ToolDefinition,
}

#[derive(Debug, Deserialize)]
struct AzureChatResponse {
    choices: Vec<AzureChoice>,
    #[serde(default)]
    usage: Option<AzureUsage>,
}

#[derive(Debug, Deserialize)]
struct AzureChoice {
    message: AzureChatMessageOut,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureChatMessageOut {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
    #[serde(default)]
    tool_calls: Vec<AzureToolCallOut>,
}

#[derive(Debug, Deserialize)]
struct AzureToolCallOut {
    function: AzureFunctionCallOut,
}

#[derive(Debug, Deserialize)]
struct AzureFunctionCallOut {
    name: String,
    #[serde(default)]
    arguments: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AzureUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}
