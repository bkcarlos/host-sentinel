//! Read-only logind details and root-authored automation receipts.
use crate::{config::Config, investigation::time_value, store::Store};
use anyhow::{Context, Result, ensure};
use chrono::NaiveDateTime;
use rusqlite::params;
use serde_json::{Value, json};
use std::{collections::HashMap, path::Path, time::Duration};
use tokio::process::Command;

async fn loginctl(args: &[&str]) -> Result<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new("loginctl")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("logind query timed out")??;
    ensure!(out.status.success(), "logind query failed");
    ensure!(out.stdout.len() <= 128 * 1024, "logind output too large");
    Ok(String::from_utf8(out.stdout)?)
}
pub fn classify(
    remote: bool,
    service: &str,
    class: &str,
    state: &str,
    leader_exists: bool,
) -> &'static str {
    if class == "manager" {
        "user_manager"
    } else if state == "closing" {
        "closing_session"
    } else if !leader_exists {
        "stale_or_unavailable_leader"
    } else if remote
        && service == "sshd"
        && class == "user"
        && ["active", "online"].contains(&state)
    {
        "active_ssh"
    } else {
        "other_session"
    }
}
pub async fn detail(id: &str) -> Result<Value> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && !id.starts_with('-')
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid session ID"
    );
    let text = loginctl(&[
        "show-session",
        id,
        "--no-pager",
        "-p",
        "Id",
        "-p",
        "Name",
        "-p",
        "User",
        "-p",
        "Class",
        "-p",
        "Service",
        "-p",
        "State",
        "-p",
        "Remote",
        "-p",
        "RemoteHost",
        "-p",
        "Leader",
        "-p",
        "Timestamp",
        "-p",
        "TimestampMonotonic",
        "-p",
        "Scope",
        "-p",
        "Type",
        "-p",
        "TTY",
    ])
    .await?;
    let f: HashMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
    let get = |k| f.get(k).copied().unwrap_or("");
    ensure!(get("Id") == id, "session vanished or ID mismatch");
    let leader = get("Leader").parse::<u32>().ok();
    let exists = leader.is_some_and(|p| p > 0 && Path::new(&format!("/proc/{p}")).exists());
    let ticks = leader
        .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/stat")).ok())
        .and_then(|s| {
            s.rsplit_once(')')
                .and_then(|(_, t)| t.split_whitespace().nth(19))
                .and_then(|v| v.parse::<u64>().ok())
        });
    let started = NaiveDateTime::parse_from_str(get("Timestamp"), "%a %Y-%m-%d %H:%M:%S UTC")
        .ok()
        .map(|t| t.and_utc().timestamp_micros());
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let classification = classify(
        get("Remote") == "yes",
        get("Service"),
        get("Class"),
        get("State"),
        exists,
    );
    Ok(
        json!({"session_id":id,"user":get("Name"),"uid":get("User").parse::<u32>().ok(),"class":get("Class"),"service":get("Service"),"state":get("State"),
        "remote":get("Remote")=="yes","source_ip":get("RemoteHost").parse::<std::net::IpAddr>().ok().map(|ip|ip.to_string()),"leader_pid":leader,"leader_exists":exists,"leader_start_ticks":ticks,
        "boot_id":boot,"started_at":started.map(time_value),"timestamp_raw_utc":get("Timestamp"),"timestamp_monotonic_us":get("TimestampMonotonic").parse::<u64>().ok(),
        "scope":get("Scope"),"session_type":get("Type"),"tty":get("TTY"),"classification":classification,"is_active_ssh":classification=="active_ssh",
        "elapsed_seconds":started.map(|t|crate::now().saturating_sub((t/1_000_000).max(0) as u64))}),
    )
}
fn matching_login(store: &Store, s: &Value) -> Result<Option<Value>> {
    let (Some(boot), Some(pid), Some(mono), Some(ip), Some(user)) = (
        s["boot_id"].as_str(),
        s["leader_pid"].as_u64(),
        s["timestamp_monotonic_us"].as_u64(),
        s["source_ip"].as_str(),
        s["user"].as_str(),
    ) else {
        return Ok(None);
    };
    let conn = store.0.lock().unwrap();
    let mut stmt=conn.prepare("SELECT id,payload FROM auth_records WHERE kind='success' AND boot_id=? AND pid=? AND user=? AND source_ip=? AND json_extract(payload,'$.source.monotonic_microseconds') BETWEEN ? AND ? LIMIT 2")?;
    let rows = stmt
        .query_map(
            params![
                boot,
                pid,
                user,
                ip,
                mono.saturating_sub(10_000_000),
                mono.saturating_add(10_000_000)
            ],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() != 1 {
        return Ok(None);
    }
    let record: Value = serde_json::from_str(&rows[0].1)?;
    Ok(Some(
        json!({"evidence_id":rows[0].0,"basis":"same boot, leader/journal PID, account, source IP and monotonic start within 10 seconds","login_time":record["time"],"fingerprint":record["fingerprint"],"trust_matches":record["trust_matches"]}),
    ))
}
pub async fn snapshot(store: &Store) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(20),async {
        let ids=loginctl(&["list-sessions","--no-legend","--no-pager"]).await?;
        let ids:Vec<_>=ids.lines().filter_map(|l|l.split_whitespace().next()).collect();
        let mut rows=vec![];let mut unavailable=0;
        for id in ids.iter().take(64) {
            match detail(id).await {
                Ok(mut s)=>{s["matched_login"]=matching_login(store,&s)?.unwrap_or(Value::Null);rows.push(s);},
                Err(e)=>{unavailable+=1;rows.push(json!({"session_id":id,"error":e.to_string(),"classification":"unavailable","is_active_ssh":false}));}
            }
        }
        Ok(json!({"timestamp":crate::now(),"time":time_value(crate::now() as i64*1_000_000),"active_ssh_count":rows.iter().filter(|s|s["is_active_ssh"]==true).count(),
            "sessions":rows,"listed_session_count":ids.len(),"truncated":ids.len()>64,"unavailable_sessions":unavailable,
            "note":"Logind user managers and closing/stale entries are not active SSH connections. Current sessions are not a historical login count. Missing matched_login means insufficient indexed evidence, not an unknown attacker."}))
    }).await.context("session inventory timed out")?
}
pub fn session_details(store: &Store, id: &str) -> Result<Value> {
    let snapshot = store.get("sessions")?.context("sessions not collected")?;
    let session = snapshot["sessions"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["session_id"] == id))
        .context("session not in cached snapshot; it may have ended")?;
    let evidence = session["matched_login"]["evidence_id"]
        .as_str()
        .map(|id| store.auth_evidence(id))
        .transpose()?;
    let receipts = store.get("automation_receipts")?.unwrap_or(Value::Null);
    let matched: Vec<_> = receipts["receipts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| receipt_matches(&r["session"], session))
        .cloned()
        .collect();
    Ok(
        json!({"snapshot_timestamp":snapshot["timestamp"],"session":session,"login_evidence":evidence,"matching_automation_receipts":matched,
        "attribution_note":"Receipts are root-authored operator claims tied to this exact observed session identity; they do not attest every command, nor identify a human. No receipt means attribution unknown."}),
    )
}
fn receipt_matches(a: &Value, b: &Value) -> bool {
    [
        "session_id",
        "boot_id",
        "leader_pid",
        "leader_start_ticks",
        "user",
        "source_ip",
    ]
    .iter()
    .all(|k| !a[k].is_null() && a[k] == b[k])
}
pub fn read_receipts(dir: &Path) -> Value {
    match read_receipts_inner(dir) {
        Ok(v) => v,
        Err(e) => {
            json!({"timestamp":crate::now(),"receipts":[],"error":e.to_string(),"attribution":"unknown"})
        }
    }
}
fn read_receipts_inner(dir: &Path) -> Result<Value> {
    use std::os::unix::fs::MetadataExt;
    if !dir.exists() {
        return Ok(
            json!({"timestamp":crate::now(),"receipts":[],"note":"No operator receipts configured; automation attribution is unknown."}),
        );
    }
    let meta = std::fs::symlink_metadata(dir)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "automation directory must be root-owned and not group/other writable"
    );
    let mut files = vec![];
    for entry in std::fs::read_dir(dir)?.take(1001) {
        files.push(entry?);
    }
    let scan_truncated = files.len() > 1000;
    files.truncate(1000);
    let mut records = vec![];
    let mut rejected = 0;
    for e in files {
        let meta = std::fs::symlink_metadata(e.path())?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() > 16384 {
            rejected += 1;
            continue;
        }
        match std::fs::read_to_string(e.path())
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        {
            Some(v)
                if v["receipt_id"].is_string()
                    && v["recorded_at"].is_u64()
                    && v["session"].is_object() =>
            {
                records.push(v)
            }
            _ => rejected += 1,
        }
    }
    records.sort_by_key(|r| std::cmp::Reverse(r["recorded_at"].as_u64().unwrap_or(0)));
    let total = records.len();
    records.truncate(100);
    Ok(
        json!({"timestamp":crate::now(),"receipts":records,"valid_receipts_in_scan":total,"truncated":scan_truncated||total>100,"rejected_files":rejected,
        "note":"Root-authored session receipts, not inferred from login frequency. Maximum 100 recent receipts from a bounded 1000-file scan. Not a complete automation history or command audit."}),
    )
}
/// Local administrator CLI only. There is intentionally no MCP receipt-writing tool.
pub async fn record_automation(
    config: &Config,
    id: &str,
    task: &str,
    label: &str,
) -> Result<Value> {
    use std::io::Write;
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    ensure!(cfg!(target_os = "linux"), "Linux required");
    // SAFETY: geteuid has no pointer arguments or side effects.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "only a local root administrator can record attribution receipts"
    );
    ensure!(
        !task.is_empty() && task.len() <= 128 && !label.is_empty() && label.len() <= 256,
        "invalid task/label length"
    );
    let dir = &config.ssh.automation_dir;
    ensure!(dir.is_absolute(), "automation directory must be absolute");
    let meta = std::fs::symlink_metadata(dir)
        .context("administrator must provision the root-owned automation directory first")?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "unsafe automation directory"
    );
    let session = detail(id).await?;
    ensure!(
        session["is_active_ssh"] == true && !session["leader_start_ticks"].is_null(),
        "receipt requires a live SSH session with process identity"
    );
    let receipt_id = uuid::Uuid::new_v4().to_string();
    let receipt = json!({"receipt_id":receipt_id,"recorded_at":crate::now(),"time":time_value(crate::now() as i64*1_000_000),"task_id":task,"label":label,"session":session,"authority":"local_root_operator_claim","scope":"This session was registered for this task; this is not a cryptographic command audit or human identity attestation."});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(dir.join(format!("{receipt_id}.json")))?;
    // SAFETY: valid owned fd, preserve root UID, copy group of the protected directory.
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), 0, meta.gid()) } == 0,
        "cannot set receipt read group"
    );
    file.write_all(serde_json::to_string(&receipt)?.as_bytes())?;
    file.sync_all()?;
    Ok(receipt)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manager_and_closing_sessions_are_not_ssh_connections() {
        assert_eq!(
            classify(false, "systemd-user", "manager", "active", true),
            "user_manager"
        );
        assert_eq!(
            classify(true, "sshd", "user", "closing", false),
            "closing_session"
        );
        assert_eq!(classify(true, "sshd", "user", "active", true), "active_ssh");
        assert_eq!(
            classify(true, "sshd", "user", "active", false),
            "stale_or_unavailable_leader"
        );
    }
    #[test]
    fn receipts_require_exact_session_identity() {
        let a = json!({"session_id":"42","boot_id":"boot","leader_pid":123,"leader_start_ticks":99,"user":"u","source_ip":"192.0.2.1"});
        assert!(receipt_matches(&a, &a));
        let mut b = a.clone();
        b["leader_start_ticks"] = json!(100);
        assert!(!receipt_matches(&a, &b));
        assert!(!receipt_matches(&json!({}), &json!({})));
    }
}
