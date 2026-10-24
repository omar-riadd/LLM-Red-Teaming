// crates/redteamer-adapters/src/anthropic.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, Role, TargetAdapter, ToolCall,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Adapter for Anthropic's Messages API.
pub struct AnthropicAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    api_key: String,
    max_tokens: u32,
    default_options: GenerationOptions,
    limiter: Mutex<RateLimiter>,
}

impl AnthropicAdapter {
    /// Builds an adapter targeting `model` (e.g. `"claude-sonnet-4-5"`).
    ///
    /// # Errors
    /// Fails if the HTTP client cannot be constructed.
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Self::with_base_url(api_key, model, DEFAULT_BASE_URL)
    }

    /// Same as [`AnthropicAdapter::new`] with a custom gateway URL.
    ///
    /// # Errors
    /// See [`AnthropicAdapter::new`].
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
                name: "anthropic-messages",
                version: env!("CARGO_PKG_VERSION"),
                model: Some(model),
            },
            base_url,
            api_key: api_key.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
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
        if let Some(mt) = opts.max_tokens {
            self.max_tokens = mt;
        }
        self.default_options = opts;
        self
    }
}

#[derive(Debug, Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<AnthropicToolIn<'a>>,
    messages: Vec<MessageIn<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AnthropicToolIn<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    description: &'a str,
    input_schema: &'a serde_json::Value,
}

#[derive(Debug, Serialize)]
struct MessageIn<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Debug, Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type", default)]
    block_type: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    input: Option<serde_json::Value>,
}

#[async_trait]
impl TargetAdapter for AnthropicAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let mut system_parts: Vec<&str> = Vec::new();
        if let Some(def_sp) = self.default_options.system_prompt.as_deref() {
            if !def_sp.is_empty() {
                system_parts.push(def_sp);
            }
        }
        if let Some(probe_sp) = opts.system_prompt.as_deref() {
            if !probe_sp.is_empty() {
                system_parts.push(probe_sp);
            }
        }
        for m in messages.iter().filter(|m| m.role == Role::System) {
            system_parts.push(&m.content);
        }
        let system = (!system_parts.is_empty()).then(|| system_parts.join("\n\n"));

        let wire_messages: Vec<MessageIn<'_>> = messages
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| MessageIn {
                role: m.role.as_str(),
                content: &m.content,
            })
            .collect();

        let active_tools = if !opts.tools.is_empty() {
            &opts.tools
        } else {
            &self.default_options.tools
        };
        let tools: Vec<AnthropicToolIn<'_>> = active_tools
            .iter()
            .map(|t| AnthropicToolIn {
                name: &t.name,
                description: &t.description,
                input_schema: &t.parameters,
            })
            .collect();

        let max_tokens = opts
            .max_tokens
            .or(self.default_options.max_tokens)
            .unwrap_or(self.max_tokens);
        let temperature = opts.temperature.or(self.default_options.temperature);

        let is_stream = opts.stream || self.default_options.stream;
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let body = MessagesRequest {
            model: self.info.model.as_deref().unwrap_or_default(),
            max_tokens,
            system,
            temperature,
            tools,
            messages: wire_messages,
            stream: if is_stream { Some(true) } else { None },
        };

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("request to {url} failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        let status = response.status();
        if !status.is_success() {
            let payload = response.text().await.map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("failed to read response body: {e}"),
                source: Some(Box::new(e)),
            })?;

            let lower = payload.to_lowercase();
            if status.as_u16() == 400
                && (lower.contains("safety")
                    || lower.contains("policy")
                    || lower.contains("violates"))
            {
                let refusal =
                    "I cannot fulfill this request as it violates safety guidelines.".to_string();
                let metadata = serde_json::json!({
                    "refusal": refusal,
                    "finish_reason": "safety",
                    "http_status": 400,
                    "raw_filter": payload.chars().take(1024).collect::<String>(),
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
                message: format!(
                    "HTTP {status}: {}",
                    payload.chars().take(512).collect::<String>()
                ),
                source: None,
            });
        }

        if is_stream {
            let needles = if !opts.early_terminate_strings.is_empty() {
                &opts.early_terminate_strings
            } else {
                &self.default_options.early_terminate_strings
            };
            let acc = crate::stream::consume_stream(
                response,
                self.info.name,
                needles,
                crate::stream::extract_anthropic_delta,
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

            return Ok(AdapterResponse {
                completed: !acc.early_terminated,
                text: acc.accumulated_text,
                tool_calls: Vec::new(),
                metadata,
            });
        }

        let payload = response.text().await.map_err(|e| RedTeamerError::Adapter {
            adapter: self.info.name,
            message: format!("failed to read response body: {e}"),
            source: Some(Box::new(e)),
        })?;

        let parsed: MessagesResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed messages payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        let text = parsed
            .content
            .iter()
            .filter(|b| b.block_type == "text")
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("");
        let tool_calls: Vec<ToolCall> = parsed
            .content
            .iter()
            .filter(|b| b.block_type == "tool_use")
            .filter_map(|b| {
                b.name.as_ref().map(|name| ToolCall {
                    name: name.clone(),
                    arguments: b.input.clone().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect();

        Ok(AdapterResponse {
            completed: matches!(parsed.stop_reason.as_deref(), Some("end_turn" | "tool_use")),
            text,
            tool_calls,
            metadata: serde_json::json!({
                "stop_reason": parsed.stop_reason,
                "usage": parsed.usage,
            }),
        })
    }
}
