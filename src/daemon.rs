use crate::{
    config::{Config, secret},
    cpu::{Detector, Sampler},
    journal::{self, AuthEvent, FailureTracker},
    mcp,
    notify::Notifier,
    store::{Event, Store},
};
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

pub fn open_store(config: &Config) -> Result<Store> {
    std::fs::create_dir_all(&config.state_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Store::open(&config.state_dir.join("sentinel.db"))
}

pub async fn run(config: Config) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "monitoring daemon requires Linux /proc and systemd; MCP and tests also run on macOS"
    );
    config.validate()?;
    let store = open_store(&config)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(config.state_dir.join("daemon.lock"))?;
    lock.try_lock_exclusive()
        .context("another daemon owns this state directory")?;
    let notifier = if config.webhook.enabled {
        Some(Notifier::new(&config.webhook)?)
    } else {
        None
    };
    let mcp_token = if config.mcp.enabled {
        Some(secret(&config.mcp.token_env)?)
    } else {
        None
    };
    let response_token = if config.response.enabled {
        let token = secret(&config.response.token_env)?;
        if let Some(read_token) = &mcp_token {
            ensure!(
                token != *read_token,
                "response and read-only MCP tokens must differ"
            );
        }
        Some(token)
    } else {
        None
    };
    store.set("daemon_started_at", &json!(crate::now()))?;
    if store.get("auth_detail_started_at")?.is_none() {
        store.set("auth_detail_started_at", &json!(crate::now()))?;
    }
    store.set("trust_policy", &json!({"timestamp":crate::now(),"rules":crate::investigation::trust_rules(&config.ssh),"meaning":"Matches configured account/network/key conditions. Labels and ownership notes are configuration, not proof of the current operator."}))?;
    if let Some(previous) = store
        .get("auth_journal_heartbeat")?
        .and_then(|v| v["timestamp"].as_u64())
    {
        let mut gaps = store
            .get("auth_collection_gaps")?
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        gaps.push(json!({"since":previous,"until":crate::now(),"reason":"collector restart; retained journal may be replayed, but continuity is not independently guaranteed"}));
        if gaps.len() > 50 {
            gaps.drain(..gaps.len() - 50);
        }
        store.set("auth_collection_gaps", &json!(gaps))?;
    }
    // Keep the first-start boundary durable even before the first matching journal entry.
    if store.get("journal_since")?.is_none() {
        store.set("journal_since", &json!(crate::now()))?;
    }
    if notifier.is_none() {
        tracing::warn!("webhook disabled; alerts remain in the durable queue until enabled");
    }
    let result: Result<()> = tokio::select! {
        result = follow_journal(&config,store.clone()) => result,
        result = sample_cpu(&config,store.clone()) => result,
        result = session_inventory(store.clone(), &config) => result,
        result = disk_inventory(store.clone()) => result,
        result = async {
            if let Some(notifier) = notifier {
                loop { notifier.flush(&store,crate::now()).await?; tokio::time::sleep(Duration::from_secs(2)).await; }
            } else { std::future::pending::<Result<()>>().await }
        } => result,
        result = async {
            if let Some(token) = mcp_token { mcp::serve_http(store.clone(),config.mcp.clone(),token).await }
            else { std::future::pending::<Result<()>>().await }
        } => result,
        result = async {
            if let Some(token)=response_token {crate::response_mcp::serve_http(config.response.clone(),token).await}
            else {std::future::pending::<Result<()>>().await}
        } => result,
        _ = shutdown_signal() => Ok(()),
    };
    if let Err(error) = &result {
        tracing::error!(%error,"monitor stopped; service manager should restart it");
        store.set(
            "auth_last_collector_error",
            &json!({"timestamp":crate::now(),"error":error.to_string()}),
        )?;
        store.insert(
            &Event::new(
                &config.host_label,
                crate::now(),
                "monitor_error",
                json!({"message":error.to_string()}),
            ),
            true,
        )?;
    }
    drop(lock);
    result
}

pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=term.recv()=>{} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub fn ingest(
    store: &Store,
    config: &Config,
    tracker: &mut FailureTracker,
    record: &Value,
) -> Result<()> {
    let Some(cursor) = record.get("__CURSOR").and_then(Value::as_str) else {
        return Ok(());
    };
    if store
        .get("journal_cursor")?
        .as_ref()
        .and_then(Value::as_str)
        == Some(cursor)
    {
        return Ok(());
    }
    // Journal fields supplied by the kernel identify the executable; a user process
    // cannot spoof _COMM by adding it to a journal message via logger.
    let comm = record.get("_COMM").and_then(Value::as_str).unwrap_or("");
    let root = record.get("_UID").and_then(Value::as_str) == Some("0");
    let message = record.get("MESSAGE").and_then(Value::as_str).unwrap_or("");
    let timestamp = record
        .get("__REALTIME_TIMESTAMP")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|n| n / 1_000_000)
        .unwrap_or(crate::now());
    let parsed = if root && ["sshd", "sshd-session", "sshd-auth"].contains(&comm) {
        journal::parse(message)
    } else {
        None
    };
    let evidence = crate::investigation::from_journal(record, config, false);
    if root
        && ["sshd", "sshd-session", "sshd-auth"].contains(&comm)
        && evidence.is_none()
        && ["Accepted ", "Failed ", "Invalid user "]
            .iter()
            .any(|p| message.starts_with(p))
    {
        let n = store
            .get("auth_parser_rejections")?
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        store.set("auth_parser_rejections", &json!(n + 1))?;
    }
    let mut event = None;
    match parsed {
        Some(AuthEvent::Login(login)) => {
            let known = journal::trusted(&login, &config.ssh);
            event = Some((
                Event::new(
                    &config.host_label,
                    timestamp,
                    if known {
                        "ssh_login"
                    } else {
                        "ssh_unknown_login"
                    },
                    json!({"login":login,"trusted":known}),
                ),
                !known,
            ));
        }
        Some(AuthEvent::Failure(ip)) => {
            if let Some(count) = tracker.record(ip, timestamp, &config.ssh) {
                event = Some((
                    Event::new(
                        &config.host_label,
                        timestamp,
                        "ssh_failure_burst",
                        json!({"source_ip":ip,"count_at_least":count,"window_seconds":config.ssh.failure_window_seconds}),
                    ),
                    true,
                ));
            }
        }
        Some(AuthEvent::InvalidUser(ip)) => {
            // Keep these observations, but don't count twice when sshd also logs Failed password.
            event = Some((
                Event::new(
                    &config.host_label,
                    timestamp,
                    "ssh_invalid_user",
                    json!({"source_ip":ip}),
                ),
                false,
            ));
        }
        None => {}
    }
    if let Some((event, _)) = &mut event {
        event.id = format!("journal-{:x}", Sha256::digest(cursor.as_bytes()));
    }
    store.journal_evidence_commit(
        cursor,
        event.as_ref().map(|(e, n)| (e, *n)),
        &serde_json::to_value(tracker)?,
        evidence.as_ref(),
    )?;
    Ok(())
}

async fn follow_journal(config: &Config, store: Store) -> Result<()> {
    let mut tracker: FailureTracker = store
        .get("ssh_detection")?
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    let mut cmd = Command::new("journalctl");
    // --follow otherwise implies a tail limit on some systemd versions. Replay
    // the full retained backlog after the checkpoint, not just the last 10 rows.
    cmd.args([
        "--follow",
        "--lines=all",
        "--output=json",
        "--no-pager",
        "--all",
    ]);
    // SSH workers move into session scopes; unit-only filters lose disconnect/close records.
    cmd.args(crate::investigation::JOURNAL_MATCHES);
    if let Some(cursor) = store
        .get("journal_cursor")?
        .and_then(|v| v.as_str().map(String::from))
    {
        cmd.arg(format!("--after-cursor={cursor}"));
    } else {
        let since = store
            .get("journal_since")?
            .and_then(|v| v.as_u64())
            .unwrap_or(crate::now());
        cmd.arg(format!("--since=@{since}"));
    }
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("start journalctl")?;
    store.set("journal_started_at", &json!(crate::now()))?;
    let mut reader = BufReader::new(child.stdout.take().context("journal stdout")?);
    let mut buf = Vec::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    loop {
        use tokio::io::AsyncReadExt;
        let remaining = (1024 * 1024 + 1 - buf.len()) as u64;
        let mut bounded = (&mut reader).take(remaining);
        tokio::select! {
            _=heartbeat.tick()=>{
                store.set("auth_journal_heartbeat",&json!({"timestamp":crate::now(),"pid":child.id(),"selector":crate::investigation::JOURNAL_MATCHES,"last_checkpoint":store.get("journal_cursor")?}))?;
            },
            result=bounded.read_until(b'\n',&mut buf)=>{
                let n=result?;if n==0 {break;}
                ensure!(buf.len()<=1024*1024,"journal entry exceeds 1 MiB");
                let record:Value=serde_json::from_slice(&buf).context("journalctl produced invalid JSON")?;
                ingest(&store,config,&mut tracker,&record)?;
                buf.clear();
            }
        }
    }
    let status = child.wait().await?;
    bail!(
        "journalctl exited ({status}); check access and saved cursor; no history was silently skipped"
    )
}

async fn sample_cpu(config: &Config, store: Store) -> Result<()> {
    let mut sampler = Sampler::default();
    let mut detector: Detector = store
        .get("cpu_detector")?
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    let mut tick = tokio::time::interval(Duration::from_secs(config.sample_seconds));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_prune = 0;
    loop {
        tick.tick().await;
        let now = crate::now();
        let memory = crate::memory::sample(Path::new("/proc"), now)
            .unwrap_or_else(|e| json!({"timestamp":now,"error":e.to_string()}));
        store.set("memory", &memory)?;
        if let Some(sample) = sampler.sample(Path::new("/proc"), now)? {
            let mut events = vec![];
            for alert in
                detector.update(now, sample.cpu_percent, &config.cpu, config.sample_seconds)
            {
                events.push(Event::new(
                    &config.host_label,
                    now,
                    alert.kind,
                    json!({"sample":sample,"baseline_percent":alert.baseline}),
                ));
            }
            store.cpu_commit(
                &serde_json::to_value(sample)?,
                &serde_json::to_value(&detector)?,
                &events,
            )?;
        }
        if now.saturating_sub(last_prune) >= 3600 {
            store.prune(now.saturating_sub(config.retention_days * 86400))?;
            last_prune = now;
        }
    }
}

async fn disk_inventory(store: Store) -> Result<()> {
    loop {
        let snapshot = crate::disk::sample().await.unwrap_or_else(|e|
            json!({"timestamp":crate::now(),"sample_interval_seconds":30,"error":e.to_string()}));
        store.set("disk", &snapshot)?;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn session_inventory(store: Store, config: &Config) -> Result<()> {
    loop {
        let snapshot = crate::sessions::snapshot(&store)
            .await
            .unwrap_or_else(|e| json!({"timestamp":crate::now(),"error":e.to_string()}));
        store.set("sessions", &snapshot)?;
        store.set(
            "automation_receipts",
            &crate::sessions::read_receipts(&config.ssh.automation_dir),
        )?;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
