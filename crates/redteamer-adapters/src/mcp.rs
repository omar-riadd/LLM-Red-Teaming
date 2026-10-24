// crates/redteamer-adapters/src/mcp.rs

//! Target adapter for Model Context Protocol (MCP) tool servers and agents.
//!
//! Connects to an MCP server over HTTP JSON-RPC 2.0 or local Stdio subprocess,
//! discovers exposed tools via `tools/list`, and executes tool attacks via `tools/call`
//! during red-teaming evaluations (OWASP LLM06 Excessive Agency, LLM01 Prompt Injection,
//! and LLM02 Sensitive Information Disclosure).

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, TargetAdapter, ToolCall,
    ToolDefinition,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize)]
struct JsonRpcRequest<T: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<T>,
}

impl<T: Serialize> JsonRpcRequest<T> {
    fn new(id: u64, method: &'static str, params: Option<T>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct JsonRpcResponse<T> {
    #[serde(default)]
    id: Option<serde_json::Value>,
    result: Option<T>,
    error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

/// Client initialization parameters.
#[derive(Debug, Clone, Serialize)]
struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
    capabilities: serde_json::Value,
    #[serde(rename = "clientInfo")]
    client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize)]
struct ClientInfo {
    name: &'static str,
    version: &'static str,
}

/// Result returned by `initialize`.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: Option<String>,
    #[serde(default, rename = "serverInfo")]
    server_info: Option<ServerInfo>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ServerInfo {
    name: String,
    #[serde(default)]
    version: Option<String>,
}

/// Result returned by `tools/list`.
#[derive(Debug, Clone, Deserialize)]
struct ToolsListResult {
    #[serde(default)]
    tools: Vec<McpToolDefinition>,
}

/// Single tool specification from an MCP server.
#[derive(Debug, Clone, Deserialize)]
struct McpToolDefinition {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "inputSchema")]
    input_schema: Option<serde_json::Value>,
}

/// Parameters for `tools/call`.
#[derive(Debug, Clone, Serialize)]
struct ToolsCallParams {
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

/// Result returned by `tools/call`.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolsCallResult {
    #[serde(default)]
    pub content: Vec<McpContentBlock>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
}

/// Transport medium used to connect to the MCP server.
#[derive(Debug, Clone)]
enum McpTransport {
    /// Remote or local HTTP JSON-RPC endpoint.
    Http {
        endpoint: String,
        headers: HashMap<String, String>,
    },
    /// Local stdio subprocess command line.
    Stdio { command: String, args: Vec<String> },
}

/// Adapter targeting Model Context Protocol (MCP) servers.
pub struct McpAdapter {
    info: AdapterInfo,
    transport: McpTransport,
    client: reqwest::Client,
    request_counter: AtomicU64,
    /// Default tool name to execute when a prompt does not explicitly name one.
    target_tool: Option<String>,
    /// Discovered tools cached after handshake or listing.
    cached_tools: Mutex<Vec<ToolDefinition>>,
    rate_limiter: Mutex<crate::RateLimiter>,
}

impl McpAdapter {
    /// Creates a new `McpAdapter` targeting an HTTP endpoint (`http://` or `https://`)
    /// or a stdio command (`stdio://...` or `mcp://...`).
    ///
    /// # Errors
    /// Returns [`RedTeamerError::InvalidConfig`] if the target URL or command is empty.
    pub fn new(target: impl AsRef<str>) -> Result<Self> {
        let raw = target.as_ref().trim();
        if raw.is_empty() {
            return Err(RedTeamerError::InvalidConfig(
                "MCP target cannot be empty".into(),
            ));
        }

        let transport = if let Some(cmd) = raw
            .strip_prefix("stdio://")
            .or_else(|| raw.strip_prefix("mcp://"))
        {
            let parts: Vec<String> = cmd.split_whitespace().map(ToOwned::to_owned).collect();
            if parts.is_empty() {
                return Err(RedTeamerError::InvalidConfig(
                    "MCP stdio command cannot be empty".into(),
                ));
            }
            let command = parts[0].clone();
            let args = parts[1..].to_vec();
            McpTransport::Stdio { command, args }
        } else {
            McpTransport::Http {
                endpoint: raw.to_owned(),
                headers: HashMap::new(),
            }
        };

        let base_url = match &transport {
            McpTransport::Http { endpoint, .. } => endpoint.as_str(),
            McpTransport::Stdio { .. } => "http://127.0.0.1",
        };
        let client = crate::build_http_client(base_url)?;

        Ok(Self {
            info: AdapterInfo {
                name: "mcp-server",
                version: env!("CARGO_PKG_VERSION"),
                model: None,
            },
            transport,
            client,
            request_counter: AtomicU64::new(1),
            target_tool: None,
            cached_tools: Mutex::new(Vec::new()),
            rate_limiter: Mutex::new(crate::RateLimiter::default()),
        })
    }

    /// Sets the target tool to invoke during evaluations.
    #[must_use]
    pub fn with_target_tool(mut self, tool: impl Into<String>) -> Self {
        let tool_name = tool.into();
        self.info.model = Some(tool_name.clone());
        self.target_tool = Some(tool_name);
        self
    }

    /// Configures custom headers sent on HTTP JSON-RPC calls.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if let McpTransport::Http { headers, .. } = &mut self.transport {
            headers.insert(key.into(), value.into());
        }
        self
    }

    /// Sets the rate limiter RPS for requests.
    #[must_use]
    pub fn with_rate_limit(self, rps: f64) -> Self {
        Self {
            rate_limiter: Mutex::new(crate::RateLimiter::new(rps.max(1.0) * 2.0, rps.max(1.0))),
            ..self
        }
    }

    /// Reconfigures the HTTP client to route requests through the specified proxy.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::Adapter`] if the proxy URL or HTTP client is invalid.
    pub fn with_proxy(mut self, proxy_url: &str) -> Result<Self> {
        let base_url = match &self.transport {
            McpTransport::Http { endpoint, .. } => endpoint.as_str(),
            McpTransport::Stdio { .. } => "http://127.0.0.1",
        };
        self.client = crate::build_http_client_with_timeout_and_proxy(
            base_url,
            std::time::Duration::from_secs(120),
            Some(proxy_url),
        )?;
        Ok(self)
    }

    /// Dispatches a JSON-RPC 2.0 request over the configured transport.
    async fn call_rpc<P: Serialize, R: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        method: &'static str,
        params: Option<P>,
    ) -> Result<R> {
        let id = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let request = JsonRpcRequest::new(id, method, params);

        match &self.transport {
            McpTransport::Http { endpoint, headers } => {
                let mut req = self.client.post(endpoint).json(&request);
                for (k, v) in headers {
                    req = req.header(k, v);
                }
                let resp = req.send().await.map_err(|e| RedTeamerError::Adapter {
                    adapter: self.info.name,
                    message: format!("HTTP request failed to {endpoint}: {e}"),
                    source: Some(Box::new(e)),
                })?;

                let status = resp.status();
                if !status.is_success() {
                    let err_body = resp.text().await.unwrap_or_default();
                    return Err(RedTeamerError::Adapter {
                        adapter: self.info.name,
                        message: format!("MCP server returned HTTP {status}: {err_body}"),
                        source: None,
                    });
                }

                let body: JsonRpcResponse<R> =
                    resp.json().await.map_err(|e| RedTeamerError::Adapter {
                        adapter: self.info.name,
                        message: format!("failed to parse JSON-RPC response from {endpoint}: {e}"),
                        source: Some(Box::new(e)),
                    })?;

                if let Some(err) = body.error {
                    return Err(RedTeamerError::Adapter {
                        adapter: self.info.name,
                        message: format!("JSON-RPC error code {}: {}", err.code, err.message),
                        source: None,
                    });
                }

                body.result.ok_or_else(|| RedTeamerError::Adapter {
                    adapter: self.info.name,
                    message: "JSON-RPC response missing both result and error".into(),
                    source: None,
                })
            }
            McpTransport::Stdio { command, args } => {
                let cmd_str = command.clone();
                let args_vec = args.clone();
                let request_json =
                    serde_json::to_string(&request).map_err(|e| RedTeamerError::Adapter {
                        adapter: "mcp-stdio",
                        message: format!("failed to serialize JSON-RPC request: {e}"),
                        source: None,
                    })?;

                tokio::task::spawn_blocking(move || {
                    use std::io::{BufRead, BufReader, Write};
                    use std::process::{Command, Stdio};

                    let mut child = Command::new(&cmd_str)
                        .args(&args_vec)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .map_err(|e| RedTeamerError::Adapter {
                            adapter: "mcp-stdio",
                            message: format!("failed to spawn stdio MCP command '{cmd_str}': {e}"),
                            source: Some(Box::new(e)),
                        })?;

                    if let Some(mut stdin) = child.stdin.take() {
                        stdin
                            .write_all(format!("{request_json}\n").as_bytes())
                            .map_err(|e| RedTeamerError::Adapter {
                                adapter: "mcp-stdio",
                                message: format!("failed to write to child stdin: {e}"),
                                source: Some(Box::new(e)),
                            })?;
                    }

                    let stdout = child.stdout.take().ok_or_else(|| RedTeamerError::Adapter {
                        adapter: "mcp-stdio",
                        message: "failed to capture child stdout".into(),
                        source: None,
                    })?;

                    let mut reader = BufReader::new(stdout);
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .map_err(|e| RedTeamerError::Adapter {
                            adapter: "mcp-stdio",
                            message: format!("failed to read line from MCP stdio server: {e}"),
                            source: Some(Box::new(e)),
                        })?;

                    let body: JsonRpcResponse<R> =
                        serde_json::from_str(&line).map_err(|e| RedTeamerError::Adapter {
                            adapter: "mcp-stdio",
                            message: format!("failed to parse JSON-RPC response '{line}': {e}"),
                            source: Some(Box::new(e)),
                        })?;

                    if let Some(err) = body.error {
                        return Err(RedTeamerError::Adapter {
                            adapter: "mcp-stdio",
                            message: format!("JSON-RPC error code {}: {}", err.code, err.message),
                            source: None,
                        });
                    }

                    body.result.ok_or_else(|| RedTeamerError::Adapter {
                        adapter: "mcp-stdio",
                        message: "JSON-RPC response missing result".into(),
                        source: None,
                    })
                })
                .await
                .map_err(|e| RedTeamerError::Adapter {
                    adapter: "mcp-stdio",
                    message: format!("stdio task join error: {e}"),
                    source: None,
                })?
            }
        }
    }

    /// Performs the MCP handshake (`initialize` and `notifications/initialized`).
    pub async fn initialize(&self) -> Result<String> {
        let params = InitializeParams {
            protocol_version: MCP_PROTOCOL_VERSION,
            capabilities: serde_json::json!({"tools": {}}),
            client_info: ClientInfo {
                name: "llm-redteamer",
                version: env!("CARGO_PKG_VERSION"),
            },
        };

        let result: InitializeResult = self.call_rpc("initialize", Some(params)).await?;
        let server_name = result
            .server_info
            .map(|s| s.name)
            .unwrap_or_else(|| "unknown-mcp-server".to_owned());

        Ok(server_name)
    }

    /// Queries the server for available tools via `tools/list` and caches them.
    pub async fn list_tools(&self) -> Result<Vec<ToolDefinition>> {
        let result: ToolsListResult = self
            .call_rpc("tools/list", Some(serde_json::json!({})))
            .await?;

        let tools: Vec<ToolDefinition> = result
            .tools
            .into_iter()
            .map(|t| ToolDefinition {
                name: t.name,
                description: t.description.unwrap_or_default(),
                parameters: t
                    .input_schema
                    .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}})),
            })
            .collect();

        let mut lock = self.cached_tools.lock().await;
        *lock = tools.clone();
        Ok(tools)
    }

    /// Executes an MCP tool via `tools/call`.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<ToolsCallResult> {
        let params = ToolsCallParams {
            name: name.to_owned(),
            arguments,
        };
        self.call_rpc("tools/call", Some(params)).await
    }

    /// Extracts target tool name and arguments from an evaluation prompt.
    fn parse_prompt_for_tool_call(
        &self,
        prompt: &str,
        available_tools: &[ToolDefinition],
    ) -> (String, serde_json::Value) {
        // 1. If prompt contains explicit tool_call syntax: tool_call: name({"key": "val"})
        if let Some(idx) = prompt.find("tool_call:") {
            let slice = prompt[idx + "tool_call:".len()..].trim();
            if let Some(open_paren) = slice.find('(') {
                let name = slice[..open_paren].trim().to_owned();
                if let Some(close_paren) = slice.rfind(')') {
                    let json_str = slice[open_paren + 1..close_paren].trim();
                    if let Ok(args) = serde_json::from_str::<serde_json::Value>(json_str) {
                        return (name, args);
                    }
                }
            }
        }

        // 2. If prompt is JSON: {"name": "...", "arguments": {...}}
        if prompt.trim_start().starts_with('{') {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(prompt) {
                if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                    let args = val
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    return (name.to_owned(), args);
                }
            }
        }

        // 3. Fallback to target_tool or first available tool
        let tool_name = self
            .target_tool
            .clone()
            .or_else(|| available_tools.first().map(|t| t.name.clone()))
            .unwrap_or_else(|| "execute".to_owned());

        // Find primary argument key from tool definition schema
        let param_key = available_tools
            .iter()
            .find(|t| t.name == tool_name)
            .and_then(|t| {
                t.parameters
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .and_then(|obj| obj.keys().next().cloned())
            })
            .unwrap_or_else(|| "input".to_owned());

        let args = serde_json::json!({ param_key: prompt });
        (tool_name, args)
    }
}

#[async_trait]
impl TargetAdapter for McpAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        self.rate_limiter.lock().await.acquire().await;

        let last_prompt = messages.last().map_or("", |m| m.content.as_str());

        // Get available tools (from cache or opts)
        let available = {
            let cached = self.cached_tools.lock().await;
            if cached.is_empty() && !opts.tools.is_empty() {
                opts.tools.clone()
            } else {
                cached.clone()
            }
        };

        let (tool_name, tool_args) = self.parse_prompt_for_tool_call(last_prompt, &available);

        let call_res = self.call_tool(&tool_name, tool_args.clone()).await;

        match call_res {
            Ok(result) => {
                let mut text_parts = Vec::new();
                for block in result.content {
                    if let Some(txt) = block.text {
                        text_parts.push(txt);
                    } else if let Some(dat) = block.data {
                        text_parts.push(dat);
                    }
                }
                let text = if text_parts.is_empty() {
                    if result.is_error {
                        format!("tool '{tool_name}' failed with isError: true")
                    } else {
                        format!("tool '{tool_name}' executed successfully with empty output")
                    }
                } else {
                    text_parts.join("\n")
                };

                let tool_calls = vec![ToolCall {
                    name: tool_name.clone(),
                    arguments: tool_args,
                }];

                Ok(AdapterResponse {
                    text,
                    tool_calls,
                    completed: !result.is_error,
                    metadata: serde_json::json!({
                        "mcp": true,
                        "tool": tool_name,
                        "is_error": result.is_error,
                    }),
                })
            }
            Err(err) => {
                // If the MCP server rejected the tool execution with an error, return it as refusal/execution output
                // so detectors can classify whether the action was prevented or partially executed
                let err_msg = err.to_string();
                Ok(AdapterResponse {
                    text: format!("MCP tool call error: {err_msg}"),
                    tool_calls: vec![ToolCall {
                        name: tool_name.clone(),
                        arguments: tool_args,
                    }],
                    completed: false,
                    metadata: serde_json::json!({
                        "mcp": true,
                        "tool": tool_name,
                        "error": err_msg,
                    }),
                })
            }
        }
    }

    async fn health_check(&self) -> Result<()> {
        let tools = self.list_tools().await?;
        if tools.is_empty() && self.target_tool.is_none() {
            // Even if 0 tools, responding to tools/list proves the MCP protocol is alive
            return Ok(());
        }
        Ok(())
    }
}
