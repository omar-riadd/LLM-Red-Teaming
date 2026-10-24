// crates/redteamer-adapters/src/openai.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, Role, TargetAdapter, ToolCall,
    ToolDefinition,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";

/// Adapter for OpenAI-compatible chat-completion APIs
/// (OpenAI, Azure-style gateways, vLLM, Ollama's compat layer, ...).
pub struct OpenAiAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    api_key: String,
    default_options: GenerationOptions,
    /// Shared limiter; the adapter is `Send + Sync` and may be fanned out
    /// across probes, so mutation goes through an async `Mutex`.
    limiter: Mutex<RateLimiter>,
}

impl OpenAiAdapter {
    /// Builds an adapter targeting `model` with the given API key.
    ///
    /// # Errors
    /// Fails if the underlying HTTP client cannot be constructed (e.g.
    /// invalid TLS backend configuration).
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Self::with_base_url(api_key, model, DEFAULT_BASE_URL)
    }

    /// Same as [`OpenAiAdapter::new`] but pointing at a custom
    /// OpenAI-compatible endpoint.
    ///
    /// # Errors
    /// See [`OpenAiAdapter::new`].
    pub fn with_base_url(
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self> {
        let base_url = base_url.into();
        let client = crate::build_http_client(&base_url)?;

        let model = model.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "openai-chat",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model),
            },
            base_url,
            api_key: api_key.into(),
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

    async fn complete(&self, body: &ChatRequest) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("request to {url} failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        let status = response.status();
        let payload = response.text().await.map_err(|e| RedTeamerError::Adapter {
            adapter: self.info.name,
            message: format!("failed to read response body: {e}"),
            source: Some(Box::new(e)),
        })?;

        if !status.is_success() {
            let lower = payload.to_lowercase();
            if status.as_u16() == 400
                && (lower.contains("content_filter")
                    || lower.contains("content_policy_violation")
                    || lower.contains("safety"))
            {
                let refusal =
                    "I cannot fulfill this request due to content safety policy violation."
                        .to_string();
                let metadata = serde_json::json!({
                    "refusal": refusal,
                    "finish_reason": "content_filter",
                    "http_status": 400,
                    "raw_filter": truncate(&payload, 1024),
                });
                return Ok(AdapterResponse {
                    text: refusal,
                    tool_calls: Vec::new(),
                    completed: true,
                    metadata,
                });
            }

            return Err(RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("HTTP {status}: {}", truncate(&payload, 512)),
                source: None,
            });
        }

        let parsed: ChatResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed completion payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        let choice = parsed.choices.first();
        let is_content_filtered =
            choice.is_some_and(|c| c.finish_reason.as_deref() == Some("content_filter"));
        let refusal = choice.and_then(|c| c.message.refusal.clone());
        let mut text = choice
            .and_then(|c| c.message.content.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| refusal.clone())
            .unwrap_or_default();

        if text.is_empty() && is_content_filtered {
            text = "The response was filtered by the content safety policy.".to_string();
        }

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
        if let Some(ref ref_str) = refusal {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "refusal".to_owned(),
                    serde_json::Value::String(ref_str.clone()),
                );
            }
        } else if is_content_filtered {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "refusal".to_owned(),
                    serde_json::Value::String(text.clone()),
                );
                obj.insert(
                    "finish_reason".to_owned(),
                    serde_json::Value::String("content_filter".to_owned()),
                );
            }
        }

        Ok(AdapterResponse {
            text,
            tool_calls,
            completed: choice.is_some_and(|c| {
                matches!(
                    c.finish_reason.as_deref(),
                    Some("stop" | "tool_calls" | "content_filter")
                )
            }),
            metadata,
        })
    }

    async fn complete_stream(
        &self,
        body: &ChatRequest,
        early_terminate_strings: &[String],
    ) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("streaming request to {url} failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        let status = response.status();
        if !status.is_success() {
            let payload = response.text().await.map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("failed to read error response: {e}"),
                source: Some(Box::new(e)),
            })?;

            let lower = payload.to_lowercase();
            if status.as_u16() == 400
                && (lower.contains("content_filter")
                    || lower.contains("content_policy_violation")
                    || lower.contains("safety"))
            {
                let refusal =
                    "I cannot fulfill this request due to content safety policy violation."
                        .to_string();
                let metadata = serde_json::json!({
                    "refusal": refusal,
                    "finish_reason": "content_filter",
                    "http_status": 400,
                    "raw_filter": truncate(&payload, 1024),
                });
                return Ok(AdapterResponse {
                    text: refusal,
                    tool_calls: Vec::new(),
                    completed: true,
                    metadata,
                });
            }

            return Err(RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("HTTP {status}: {}", truncate(&payload, 512)),
                source: None,
            });
        }

        let acc = crate::stream::consume_stream(
            response,
            self.info.name,
            early_terminate_strings,
            crate::stream::extract_openai_delta,
        )
        .await?;

        let mut metadata = serde_json::json!({
            "stream": true,
            "chunk_count": acc.chunk_count,
            "early_terminated": acc.early_terminated,
        });
        if let Some(ref needle) = acc.matched_needle {
            metadata["terminated_by"] = serde_json::Value::String(needle.clone());
        }

        Ok(AdapterResponse {
            text: acc.accumulated_text,
            tool_calls: Vec::new(),
            completed: !acc.early_terminated,
            metadata,
        })
    }
}

#[async_trait]
impl TargetAdapter for OpenAiAdapter {
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
        let tools: Vec<OpenAiToolIn> = active_tools
            .iter()
            .cloned()
            .map(|function| OpenAiToolIn {
                tool_type: "function",
                function,
            })
            .collect();

        let is_stream = opts.stream || self.default_options.stream;
        let req = ChatRequest {
            model: self.info.model.clone().unwrap_or_default(),
            messages: wire_messages,
            temperature: opts.temperature.or(self.default_options.temperature),
            max_tokens: opts.max_tokens.or(self.default_options.max_tokens),
            seed: opts.seed.or(self.default_options.seed),
            tools,
            stream: if is_stream { Some(true) } else { None },
        };
        if is_stream {
            let needles = if !opts.early_terminate_strings.is_empty() {
                &opts.early_terminate_strings
            } else {
                &self.default_options.early_terminate_strings
            };
            self.complete_stream(&req, needles).await
        } else {
            self.complete(&req).await
        }
    }
}

// ---------------------------------------------------------------------------
// Wire types (subset of the chat-completion schema)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OpenAiToolIn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Debug, Serialize)]
struct OpenAiToolIn {
    #[serde(rename = "type")]
    tool_type: &'static str,
    function: ToolDefinition,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ChatMessageOut,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatMessageOut {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
    #[serde(default)]
    tool_calls: Vec<OpenAiToolCallOut>,
}

#[derive(Debug, Deserialize)]
struct OpenAiToolCallOut {
    function: OpenAiFunctionCallOut,
}

#[derive(Debug, Deserialize)]
struct OpenAiFunctionCallOut {
    name: String,
    #[serde(default)]
    arguments: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Usage {
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
