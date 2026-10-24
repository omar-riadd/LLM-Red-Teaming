// crates/redteamer-adapters/tests/mcp_mock.rs

//! Mock HTTP JSON-RPC tests for `McpAdapter`.
//!
//! Validates MCP handshake (`initialize`), tool discovery (`tools/list`),
//! tool execution (`tools/call`), error handling (`isError: true`), and `health_check`.

use redteamer_adapters::McpAdapter;
use redteamer_core::traits::adapter::{ChatMessage, GenerationOptions, TargetAdapter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct MockServer {
    base_url: String,
    handle: tokio::task::JoinHandle<Vec<serde_json::Value>>,
}

async fn spawn_mock_mcp_server(responses: Vec<(&'static str, String)>) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let base_url = format!("http://{addr}/mcp");

    let handle = tokio::spawn(async move {
        let mut captured_requests = Vec::new();
        for (status_line, body) in responses {
            let (mut stream, _) = listener.accept().await.expect("accept connection");
            let mut buf = vec![0u8; 8192];
            let mut read_bytes = 0;
            loop {
                let n = stream.read(&mut buf[read_bytes..]).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                read_bytes += n;
                if buf[..read_bytes].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            let req_str = String::from_utf8_lossy(&buf[..read_bytes]);
            if let Some(pos) = req_str.find("\r\n\r\n") {
                let body_str = &req_str[pos + 4..];
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(body_str) {
                    captured_requests.push(json_val);
                }
            }

            let http_response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(http_response.as_bytes())
                .await
                .expect("write response");
            let _ = stream.shutdown().await;
        }
        captured_requests
    });

    MockServer { base_url, handle }
}

#[tokio::test]
async fn test_mcp_adapter_handshake_and_tool_discovery() {
    let init_resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "enterprise-filesystem-mcp",
                "version": "1.2.0"
            }
        }
    })
    .to_string();

    let list_resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": "read_secure_file",
                    "description": "Reads a restricted configuration file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "run_command",
                    "description": "Executes an administrative shell command",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": { "type": "string" }
                        },
                        "required": ["command"]
                    }
                }
            ]
        }
    })
    .to_string();

    let server = spawn_mock_mcp_server(vec![("200 OK", init_resp), ("200 OK", list_resp)]).await;

    let adapter = McpAdapter::new(&server.base_url)
        .expect("adapter should build")
        .with_rate_limit(100.0);

    let server_name = adapter
        .initialize()
        .await
        .expect("handshake should succeed");
    assert_eq!(server_name, "enterprise-filesystem-mcp");

    let tools = adapter
        .list_tools()
        .await
        .expect("list_tools should succeed");
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "read_secure_file");
    assert_eq!(tools[1].name, "run_command");

    let captured = server.handle.await.expect("server handle should join");
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0]["method"], "initialize");
    assert_eq!(captured[1]["method"], "tools/list");
}

#[tokio::test]
async fn test_mcp_adapter_send_chat_executes_tool_call_and_extracts_canary() {
    let call_resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "File content read successfully: API_KEY=CANARY-MCP-9921-SECRET"
                }
            ],
            "isError": false
        }
    })
    .to_string();

    let server = spawn_mock_mcp_server(vec![("200 OK", call_resp)]).await;

    let adapter = McpAdapter::new(&server.base_url)
        .expect("adapter build")
        .with_target_tool("read_secure_file")
        .with_rate_limit(100.0);

    let msg = ChatMessage::user("tool_call: read_secure_file({\"path\": \"/etc/secrets.conf\"})");
    let resp = adapter
        .send_chat(&[msg], &GenerationOptions::default())
        .await
        .expect("send_chat should succeed");

    assert!(resp.completed);
    assert!(resp.text.contains("CANARY-MCP-9921-SECRET"));
    assert_eq!(resp.tool_calls.len(), 1);
    assert_eq!(resp.tool_calls[0].name, "read_secure_file");
    assert_eq!(resp.tool_calls[0].arguments["path"], "/etc/secrets.conf");
    assert_eq!(resp.metadata["is_error"], false);

    let captured = server.handle.await.expect("server handle join");
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0]["method"], "tools/call");
    assert_eq!(captured[0]["params"]["name"], "read_secure_file");
    assert_eq!(
        captured[0]["params"]["arguments"]["path"],
        "/etc/secrets.conf"
    );
}

#[tokio::test]
async fn test_mcp_adapter_handles_tool_error_and_refusal() {
    let error_resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "PermissionDenied: Access to /root/.ssh is restricted by security policy."
                }
            ],
            "isError": true
        }
    })
    .to_string();

    let server = spawn_mock_mcp_server(vec![("200 OK", error_resp)]).await;

    let adapter = McpAdapter::new(&server.base_url)
        .expect("adapter build")
        .with_target_tool("read_secure_file")
        .with_rate_limit(100.0);

    let resp = adapter
        .send_chat(
            &[ChatMessage::user("read /root/.ssh/id_rsa")],
            &GenerationOptions::default(),
        )
        .await
        .expect("send_chat should capture tool error cleanly");

    // When isError is true, completed is false and error text is preserved
    assert!(!resp.completed);
    assert!(resp
        .text
        .contains("PermissionDenied: Access to /root/.ssh is restricted"));
    assert_eq!(resp.metadata["is_error"], true);
}

#[tokio::test]
async fn test_mcp_adapter_health_check() {
    let list_resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": []
        }
    })
    .to_string();

    let server = spawn_mock_mcp_server(vec![("200 OK", list_resp)]).await;

    let adapter = McpAdapter::new(&server.base_url)
        .expect("adapter build")
        .with_rate_limit(100.0);

    adapter
        .health_check()
        .await
        .expect("health check should pass on valid response");
}
