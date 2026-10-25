use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use host_sentinel::{
    config::{McpConfig, WebhookConfig},
    mcp,
    notify::Notifier,
    store::{Event, Store},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
type Calls = Arc<Mutex<Vec<(HeaderMap, Value)>>>;
const TOKEN: &str = "test-only-token-not-a-real-secret-12345";

#[tokio::test]
async fn webhook_retries_keep_identity_and_require_acknowledgement() -> Result<()> {
    let calls = Arc::new(Mutex::new(Vec::<(HeaderMap, Value)>::new()));
    async fn receiver(
        State(calls): State<Calls>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let mut calls = calls.lock().unwrap();
        calls.push((headers, body));
        if calls.len() == 1 {
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false})))
        } else {
            (StatusCode::OK, Json(json!({"ok":true})))
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new()
        .route("/hook", post(receiver))
        .with_state(calls.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let notifier = Notifier::with_token(
        &WebhookConfig {
            enabled: true,
            url: format!("http://{addr}/hook"),
            ..Default::default()
        },
        TOKEN.into(),
    )?;
    let dir = tempfile::tempdir()?;
    let db = Store::open(&dir.path().join("state.db"))?;
    let event = Event::new("test", 100, "monitor_test", json!({}));
    db.insert(&event, true)?;
    notifier.flush(&db, host_sentinel::now()).await?;
    assert_eq!(db.queue_size()?, 1);
    notifier.flush(&db, host_sentinel::now() + 10).await?;
    assert_eq!(db.queue_size()?, 0);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0["idempotency-key"], calls[1].0["idempotency-key"]);
    assert_eq!(calls[0].0["authorization"], format!("Bearer {TOKEN}"));
    assert_eq!(calls[0].1["id"], event.id);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn mcp_auth_handshake_tool_list_and_origin_guard() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = Store::open(&dir.path().join("state.db"))?;
    db.set(
        "sample",
        &json!({"timestamp":123,"cpu_percent":12.5,"top_processes":[]}),
    )?;
    let disk = json!({"timestamp":123,"partial":false,"filesystems":[{"mount_point":"/data with spaces","total_bytes":1000,"used_bytes":600,"available_bytes":300,"used_percent":67,"inodes_total":null}]});
    db.set("disk", &disk)?;
    host_sentinel::daemon::ingest(
        &db,
        &host_sentinel::config::Config::default(),
        &mut host_sentinel::journal::FailureTracker::default(),
        &json!({"__CURSOR":"http-evidence","__REALTIME_TIMESTAMP":chrono::DateTime::parse_from_rfc3339("2024-01-01T20:17:23+08:00")?.timestamp_micros().to_string(),"_UID":"0","_COMM":"sshd-session","_PID":"123","_BOOT_ID":"test","MESSAGE":"Accepted publickey for ubuntu from 192.0.2.1 port 1234 ssh2: RSA SHA256:test"}),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = mcp::router(db, &McpConfig::default(), TOKEN);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"integration-test","version":"1"}}});
    assert_eq!(client.post(&url).json(&init).send().await?.status(), 401);
    assert_eq!(
        client
            .post(&url)
            .bearer_auth("wrong-token")
            .json(&init)
            .send()
            .await?
            .status(),
        401
    );
    let bad_host = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("host", "attacker.example")
        .header("accept", "application/json, text/event-stream")
        .json(&init)
        .send()
        .await?;
    assert_eq!(bad_host.status(), 403);
    let denied = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("origin", "https://untrusted.example")
        .header("accept", "application/json, text/event-stream")
        .json(&init)
        .send()
        .await?;
    assert_eq!(denied.status(), 403);
    let response = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("accept", "application/json, text/event-stream")
        .json(&init)
        .send()
        .await?;
    assert!(
        response.status().is_success(),
        "initialize status {}",
        response.status()
    );
    let sid = response
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()?
        .to_string();
    let body = rpc_response(response).await?;
    assert_eq!(body["result"]["serverInfo"]["name"], "host-sentinel");
    let notify = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &sid)
        .header("mcp-protocol-version", "2025-03-26")
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await?;
    assert!(notify.status().is_success());
    let tools_response = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &sid)
        .header("mcp-protocol-version", "2025-03-26")
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
        .send()
        .await?;
    let tools = rpc_response(tools_response).await?;
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 20);
    let result_response = client.post(&url).bearer_auth(TOKEN).header("accept","application/json, text/event-stream").header("mcp-session-id",&sid).header("mcp-protocol-version","2025-03-26")
        .json(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_status","arguments":{}}})).send().await?;
    let result = rpc_response(result_response).await?;
    let status: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap())?;
    assert_eq!(status["sample"]["cpu_percent"], 12.5);
    assert_eq!(status["disk"], disk);
    let disk_tool = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "get_disk_status")
        .unwrap();
    assert_eq!(disk_tool["annotations"]["readOnlyHint"], true);
    let response = client.post(&url).bearer_auth(TOKEN).header("accept","application/json, text/event-stream").header("mcp-session-id",&sid).header("mcp-protocol-version","2025-03-26")
        .json(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_disk_status","arguments":{}}})).send().await?;
    let result = rpc_response(response).await?;
    let actual: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap())?;
    assert_eq!(actual, disk);
    let response=client.post(&url).bearer_auth(TOKEN).header("accept","application/json, text/event-stream").header("mcp-session-id",&sid).header("mcp-protocol-version","2025-03-26")
        .json(&json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"investigate_ssh_activity","arguments":{"since":"2024-01-01T20:17:00+08:00","until":"2024-01-01T20:26:00+08:00","limit":1}}})).send().await?;
    let result = rpc_response(response).await?;
    let actual: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap())?;
    assert_eq!(actual["counts"]["success"], 1);
    assert_eq!(
        actual["records"][0]["time"]["beijing"],
        "2024-01-01T20:17:23+08:00"
    );
    assert_eq!(actual["coverage"]["history_gap_possible"], true);
    for (name, args, expected_error) in [
        (
            "get_session_processes",
            json!({"session_id":"42"}),
            "disabled",
        ),
        (
            "get_session_connections",
            json!({"session_id":"42"}),
            "disabled",
        ),
        (
            "get_service_status",
            json!({"unit":"ssh.service;id"}),
            "allowlist",
        ),
        (
            "get_service_logs",
            json!({"unit":"unapproved.service"}),
            "allowlist",
        ),
        (
            "get_login_timeline",
            json!({"kind":"failure"}),
            "successful login",
        ),
    ] {
        let tool = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap();
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["annotations"]["destructiveHint"], false);
        let response = client.post(&url).bearer_auth(TOKEN).header("accept","application/json, text/event-stream").header("mcp-session-id",&sid).header("mcp-protocol-version","2025-03-26")
            .json(&json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":name,"arguments":args}})).send().await?;
        let result = rpc_response(response).await?;
        let actual: Value =
            serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap())?;
        assert!(actual["error"].as_str().unwrap().contains(expected_error));
        assert_eq!(actual["data_available"], false);
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn webhook_rejects_redirect_and_false_success() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new()
        .route(
            "/redirect",
            post(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/ok")]) }),
        )
        .route("/html", post(|| async { "<html>proxy login page</html>" }))
        .route("/no-ack", post(|| async { Json(json!({"ok":false})) }))
        .route("/ok", post(|| async { Json(json!({"ok":true})) }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let event = Event::new("test", 1, "monitor_test", json!({}));
    for path in ["redirect", "html", "no-ack"] {
        let notifier = Notifier::with_token(
            &WebhookConfig {
                enabled: true,
                url: format!("http://{addr}/{path}"),
                ..Default::default()
            },
            TOKEN.into(),
        )?;
        assert!(notifier.send(&event).await.is_err(), "must reject {path}");
    }
    server.abort();
    Ok(())
}

async fn rpc_response(mut response: reqwest::Response) -> Result<Value> {
    anyhow::ensure!(
        response.status().is_success(),
        "RPC HTTP {}",
        response.status()
    );
    if response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
    {
        return Ok(response.json().await?);
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut buffer = String::new();
        while let Some(chunk) = response.chunk().await? {
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            for line in buffer.lines() {
                if let Some(data) = line.strip_prefix("data: ")
                    && let Ok(value) = serde_json::from_str::<Value>(data)
                    && value.get("id").is_some()
                {
                    return Ok(value);
                }
            }
        }
        anyhow::bail!("no JSON-RPC response in SSE body: {buffer}")
    })
    .await?
}

#[tokio::test]
async fn response_endpoint_has_independent_auth_and_mutation_metadata() -> Result<()> {
    let config = host_sentinel::config::ResponseConfig::default();
    let action_token = "separate-action-token-for-this-test-12345";
    let app = host_sentinel::response_mcp::router(&config, action_token);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{address}/mcp");
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"approval-test","version":"1"}}});
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .json(&init)
            .send()
            .await?
            .status(),
        401
    );
    let response = client
        .post(&url)
        .bearer_auth(action_token)
        .header("accept", "application/json, text/event-stream")
        .json(&init)
        .send()
        .await?;
    let sid = response.headers()["mcp-session-id"].to_str()?.to_string();
    rpc_response(response).await?;
    client
        .post(&url)
        .bearer_auth(action_token)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &sid)
        .header("mcp-protocol-version", "2025-03-26")
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await?
        .error_for_status()?;
    let response = client
        .post(&url)
        .bearer_auth(action_token)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &sid)
        .header("mcp-protocol-version", "2025-03-26")
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
        .send()
        .await?;
    let result = rpc_response(response).await?;
    let tools = result["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 7);
    let execute = tools
        .iter()
        .find(|t| t["name"] == "execute_session_action")
        .unwrap();
    assert_eq!(execute["annotations"]["readOnlyHint"], false);
    assert_eq!(execute["annotations"]["destructiveHint"], true);
    assert!(execute["inputSchema"]["properties"]["proposal"].is_object());
    let kill = tools
        .iter()
        .find(|t| t["name"] == "execute_process_action")
        .unwrap();
    assert_eq!(kill["annotations"]["readOnlyHint"], false);
    assert_eq!(kill["annotations"]["destructiveHint"], true);
    server.abort();
    Ok(())
}
