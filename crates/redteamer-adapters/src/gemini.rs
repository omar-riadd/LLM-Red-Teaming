// crates/redteamer-adapters/src/gemini.rs

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, Role, TargetAdapter,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::RateLimiter;

const DEFAULT_GEMINI_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";

/// Target adapter for the Google Gemini REST API (v1beta `generateContent`).
pub struct GeminiAdapter {
    client: reqwest::Client,
    info: AdapterInfo,
    base_url: String,
    api_key: String,
    default_options: GenerationOptions,
    limiter: Mutex<RateLimiter>,
}

impl GeminiAdapter {
    /// Builds a Gemini adapter targeting `model` (e.g. `gemini-1.5-flash`, `gemini-2.0-flash`)
    /// with the provided API key.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Adapter`] if the underlying HTTP client cannot be constructed.
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Self::with_base_url(api_key, model, DEFAULT_GEMINI_BASE_URL)
    }

    /// Same as [`GeminiAdapter::new`] but pointing at an alternative base URL.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Adapter`] if HTTP client construction fails.
    pub fn with_base_url(
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self> {
        let base_url = base_url.into();
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));
        if crate::is_loopback_url(&base_url) {
            builder = builder.no_proxy();
        }
        let client = builder.build().map_err(|e| RedTeamerError::Adapter {
            adapter: "gemini-rest",
            message: format!("failed to build HTTP client: {e}"),
            source: Some(Box::new(e)),
        })?;

        let model = model.into();
        Ok(Self {
            client,
            info: AdapterInfo {
                name: "gemini-rest",
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

    async fn complete(&self, body: &GeminiRequest) -> Result<AdapterResponse> {
        self.limiter.lock().await.acquire().await;

        let model = self.info.model.as_deref().unwrap_or("gemini-1.5-flash");
        let url = format!(
            "{}/models/{}:generateContent?key={}",
            self.base_url.trim_end_matches('/'),
            model,
            self.api_key
        );

        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("request to Gemini API failed: {e}"),
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

        let parsed: GeminiResponse =
            serde_json::from_str(&payload).map_err(|e| RedTeamerError::Adapter {
                adapter: self.info.name,
                message: format!("malformed Gemini response payload: {e}"),
                source: Some(Box::new(e)),
            })?;

        let candidate = parsed.candidates.first();
        let text = candidate
            .and_then(|c| c.content.as_ref())
            .map(|content| {
                content
                    .parts
                    .iter()
                    .filter_map(|p| p.text.as_deref())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();

        let finish_reason = candidate.and_then(|c| c.finish_reason.clone());
        let completed = matches!(finish_reason.as_deref(), Some("STOP"));

        let mut metadata = parsed
            .usage_metadata
            .map(|u| {
                serde_json::json!({
                    "prompt_tokens": u.prompt_token_count,
                    "completion_tokens": u.candidates_token_count,
                    "total_tokens": u.prompt_token_count + u.candidates_token_count,
                })
            })
            .unwrap_or_else(|| serde_json::json!({}));

        if let Some(reason) = finish_reason {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "finish_reason".to_owned(),
                    serde_json::Value::String(reason),
                );
            }
        }

        Ok(AdapterResponse {
            text,
            tool_calls: Vec::new(),
            completed,
            metadata,
        })
    }
}

#[async_trait]
impl TargetAdapter for GeminiAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        let mut contents = Vec::with_capacity(messages.len());

        let sys_prompt = crate::merge_system_prompts(
            self.default_options.system_prompt.as_deref(),
            opts.system_prompt.as_deref(),
        );

        let system_instruction = sys_prompt.map(|sp| GeminiContent {
            role: None,
            parts: vec![GeminiPart { text: Some(sp) }],
        });

        for msg in messages {
            let role = match msg.role {
                Role::Assistant => "model",
                Role::User | Role::System => "user",
            };
            contents.push(GeminiContent {
                role: Some(role.to_string()),
                parts: vec![GeminiPart {
                    text: Some(msg.content.clone()),
                }],
            });
        }

        let generation_config = Some(GeminiGenerationConfig {
            temperature: opts.temperature.or(self.default_options.temperature),
            max_output_tokens: opts.max_tokens.or(self.default_options.max_tokens),
            candidate_count: Some(1),
        });

        let req = GeminiRequest {
            contents,
            system_instruction,
            generation_config,
        };

        self.complete(&req).await
    }
}

// ---------------------------------------------------------------------------
// Wire types (Gemini REST API v1beta)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiPart {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiResponse {
    #[serde(default)]
    candidates: Vec<GeminiCandidate>,
    #[serde(default, alias = "usage_metadata")]
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiCandidate {
    #[serde(default)]
    content: Option<GeminiContent>,
    #[serde(default, alias = "finish_reason")]
    finish_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiUsageMetadata {
    #[serde(default, alias = "prompt_token_count")]
    prompt_token_count: u64,
    #[serde(default, alias = "candidates_token_count")]
    candidates_token_count: u64,
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}
