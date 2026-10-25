//! Indexed, evidence-backed SSH queries. Counts are computed over the full SQL
//! range, independently of the returned page. No generic shell or SQL interface.
use crate::{
    config::{Config, SshConfig},
    journal::{self, AuthEvent},
    store::Store,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, FixedOffset, Utc};
use regex::Regex;
use rmcp::schemars;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{net::IpAddr, sync::LazyLock, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
};

pub const JOURNAL_MATCHES: [&str; 3] = ["_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth"];
static FAILED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Failed (\S+) for (invalid user )?(.*?) from (\S+) port (\d+)").unwrap()
});
static INVALID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Invalid user (.*?) from (\S+) port (\d+)").unwrap());
static OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^pam_unix\(sshd:session\): session opened for user ([^ (]+)").unwrap()
});
static CLOSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^pam_unix\(sshd:session\): session closed for user (\S+)").unwrap()
});

pub fn time_value(us: i64) -> Value {
    match DateTime::<Utc>::from_timestamp_micros(us) {
        Some(t) => {
            json!({"unix_microseconds":us,"utc":t.to_rfc3339(),"beijing":t.with_timezone(&FixedOffset::east_opt(8*3600).unwrap()).to_rfc3339()})
        }
        None => Value::Null,
    }
}
fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(i64::MAX as u128) as i64
}
pub fn trust_rules(c: &SshConfig) -> Value {
    json!(c.trusted.iter().map(|r| {
        let conditions=json!({"user":r.user,"networks":r.networks,"fingerprints":r.fingerprints});
        json!({"rule_id":format!("trust-{:x}",Sha256::digest(conditions.to_string().as_bytes())),"conditions":conditions,"label":r.label,"owner":r.owner,"verification_note":r.verification_note})
    }).collect::<Vec<_>>())
}
fn matched_rules(login: &journal::Login, c: &SshConfig) -> Value {
    let rules = trust_rules(c);
    json!(
        c.trusted
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                let mut only = c.clone();
                only.trusted = vec![r.clone()];
                journal::trusted(login, &only).then(|| rules[i].clone())
            })
            .collect::<Vec<_>>()
    )
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRecord {
    pub id: String,
    pub timestamp_us: i64,
    pub kind: String,
    pub user: Option<String>,
    pub source_ip: Option<String>,
    pub boot_id: Option<String>,
    pub pid: Option<u32>,
    pub payload: Value,
}
pub fn from_journal(record: &Value, c: &Config, backfilled: bool) -> Option<AuthRecord> {
    let comm = record["_COMM"].as_str()?;
    if record["_UID"].as_str() != Some("0")
        || !["sshd", "sshd-session", "sshd-auth"].contains(&comm)
    {
        return None;
    }
    let cursor = record["__CURSOR"].as_str()?;
    let timestamp_us = record["__REALTIME_TIMESTAMP"]
        .as_str()?
        .parse::<i64>()
        .ok()?;
    if timestamp_us < 0 {
        return None;
    }
    let message = record["MESSAGE"].as_str()?;
    if message.len() > 8192 {
        return None;
    }
    let mut user = None;
    let mut ip = None;
    let mut port = None;
    let mut method = None;
    let mut fingerprint = None;
    let mut invalid = false;
    let mut matches = json!([]);
    let kind = if let Some(AuthEvent::Login(login)) = journal::parse(message) {
        matches = matched_rules(&login, &c.ssh);
        user = Some(login.user);
        ip = Some(login.source_ip.to_string());
        port = Some(login.source_port);
        method = Some(login.method);
        fingerprint = login.fingerprint;
        "success"
    } else if let Some(m) = FAILED.captures(message) {
        method = Some(m[1].to_string());
        invalid = m.get(2).is_some();
        user = Some(m[3].to_string());
        ip = Some(m[4].parse::<IpAddr>().ok()?.to_string());
        port = Some(m[5].parse::<u16>().ok()?);
        "failure"
    } else if let Some(m) = INVALID.captures(message) {
        user = Some(m[1].to_string());
        ip = Some(m[2].parse::<IpAddr>().ok()?.to_string());
        port = Some(m[3].parse::<u16>().ok()?);
        invalid = true;
        "invalid_user"
    } else if let Some(m) = OPEN.captures(message) {
        user = Some(m[1].to_string());
        "session_open"
    } else if let Some(m) = CLOSE.captures(message) {
        user = Some(m[1].to_string());
        "session_close"
    } else if message.starts_with("Disconnected from ")
        || message.starts_with("Received disconnect ")
    {
        "disconnect"
    } else if message.starts_with("Accepted ")
        || message.starts_with("Failed ")
        || message.starts_with("Invalid user ")
    {
        "unparsed_auth"
    } else {
        return None;
    };
    let boot = record["_BOOT_ID"].as_str().map(|s| s.replace('-', ""));
    let pid = record["_PID"].as_str().and_then(|s| s.parse::<u32>().ok());
    let id = format!("journal-{:x}", Sha256::digest(cursor.as_bytes()));
    let sanitized: String = message
        .chars()
        .filter(|c| !c.is_control())
        .take(2048)
        .collect();
    let payload = json!({"evidence_id":id,"host":c.host_label,"kind":kind,"time":time_value(timestamp_us),
        "user":user,"source_ip":ip,"source_port":port,"method":method,"fingerprint":fingerprint,"invalid_user":invalid,
        "trust_matches":matches,"trust_evaluation":if backfilled {"policy_at_backfill_time"} else {"policy_at_ingestion_time"},
        "operator_attribution":"not_established_by_ip_or_key_alone",
        "source":{"journal_cursor":cursor,"boot_id":boot,"pid":pid,"unit":record["_SYSTEMD_UNIT"],"comm":comm,"uid":0,
            "monotonic_microseconds":record["__MONOTONIC_TIMESTAMP"].as_str().and_then(|s|s.parse::<u64>().ok()),
            "audit_session":record["_AUDIT_SESSION"],"message":sanitized,"message_truncated":message.chars().count()>2048},
        "backfilled":backfilled,"indexed_at":time_value(now_us())});
    Some(AuthRecord {
        id,
        timestamp_us,
        kind: kind.into(),
        user,
        source_ip: ip,
        boot_id: boot,
        pid,
        payload,
    })
}
pub(crate) fn insert_record(conn: &Connection, r: &AuthRecord) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO auth_records VALUES (?,?,?,?,?,?,?,?)",
        params![
            r.id,
            r.timestamp_us,
            r.kind,
            r.user,
            r.source_ip,
            r.boot_id,
            r.pid,
            r.payload.to_string()
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthQuery {
    /// RFC3339 with explicit timezone, e.g. 2026-10-25T20:17:00+08:00. Default: one hour before until.
    pub since: Option<String>,
    /// Exclusive end, RFC3339 with explicit timezone. Default: now. Maximum range: 31 days.
    pub until: Option<String>,
    pub user: Option<String>,
    pub source_ip: Option<String>,
    /// success, failure, invalid_user, session_open, session_close, disconnect, or unparsed_auth.
    pub kind: Option<String>,
    /// Returned page size 1..100; never changes aggregate counts. Default: 20.
    pub limit: Option<usize>,
    /// Pagination offset; reuse returned since/until for a stable historical window.
    pub offset: Option<usize>,
}
struct Window {
    start: i64,
    end: i64,
    ip: Option<String>,
    limit: usize,
    offset: usize,
}
impl AuthQuery {
    fn window(&self) -> Result<Window> {
        let end = match &self.until {
            Some(s) => DateTime::parse_from_rfc3339(s)
                .context("until must be RFC3339 with timezone")?
                .timestamp_micros(),
            None => now_us(),
        };
        let start = match &self.since {
            Some(s) => DateTime::parse_from_rfc3339(s)
                .context("since must be RFC3339 with timezone")?
                .timestamp_micros(),
            None => end.saturating_sub(3_600_000_000),
        };
        ensure!(
            start >= 0 && end > start && end - start <= 31 * 86_400_000_000,
            "query range must be positive and at most 31 days"
        );
        ensure!(
            end <= now_us() + 1_000_000,
            "query end cannot be in the future"
        );
        if let Some(kind) = &self.kind {
            ensure!(
                [
                    "success",
                    "failure",
                    "invalid_user",
                    "session_open",
                    "session_close",
                    "disconnect",
                    "unparsed_auth"
                ]
                .contains(&kind.as_str()),
                "unsupported auth kind"
            );
        }
        ensure!(
            self.user.as_ref().is_none_or(|s| s.len() <= 256),
            "user filter too long"
        );
        let ip = self
            .source_ip
            .as_ref()
            .map(|s| s.parse::<IpAddr>().map(|i| i.to_string()))
            .transpose()
            .context("invalid source IP filter")?;
        let limit = self.limit.unwrap_or(20);
        let offset = self.offset.unwrap_or(0);
        ensure!(
            (1..=100).contains(&limit) && offset <= 1_000_000,
            "invalid pagination limit/offset"
        );
        Ok(Window {
            start,
            end,
            ip,
            limit,
            offset,
        })
    }
}
const FILTER: &str = "timestamp_us>=?1 AND timestamp_us<?2 AND (?3 IS NULL OR user=?3) AND (?4 IS NULL OR source_ip=?4) AND (?5 IS NULL OR kind=?5)";

impl Store {
    pub fn collection_health(&self, q: &AuthQuery) -> Result<Value> {
        let w = q.window()?;
        self.auth_health(w.start, w.end)
    }
    pub fn auth_query(&self, q: &AuthQuery) -> Result<Value> {
        let w = q.window()?;
        let (counts, groups, records, total, first, last, source_count) = {
            let conn = self.0.lock().unwrap();
            // One read snapshot even when a separate backfill process is writing.
            let conn = conn.unchecked_transaction()?;
            let mut counts = serde_json::Map::new();
            let mut total = 0u64;
            let sql =
                format!("SELECT kind,count(*) FROM auth_records WHERE {FILTER} GROUP BY kind");
            let mut stmt = conn.prepare(&sql)?;
            for pair in stmt.query_map(params![w.start, w.end, q.user, w.ip, q.kind], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
            })? {
                let (kind, n) = pair?;
                total += n;
                counts.insert(kind, json!(n));
            }
            for kind in [
                "success",
                "failure",
                "invalid_user",
                "session_open",
                "session_close",
                "disconnect",
                "unparsed_auth",
            ] {
                counts.entry(kind).or_insert(json!(0));
            }
            let sql = format!(
                "SELECT MIN(timestamp_us),MAX(timestamp_us),count(DISTINCT source_ip) FROM auth_records WHERE {FILTER}"
            );
            let (first, last, source_count): (Option<i64>, Option<i64>, u64) =
                conn.query_row(&sql, params![w.start, w.end, q.user, w.ip, q.kind], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
            let sql = format!(
                "SELECT source_ip,count(*),sum(kind='success'),sum(kind='failure'),sum(kind='invalid_user'),MIN(timestamp_us),MAX(timestamp_us) FROM auth_records WHERE {FILTER} AND source_ip IS NOT NULL GROUP BY source_ip ORDER BY count(*) DESC,source_ip LIMIT 100"
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut groups = vec![];
            for r in stmt.query_map(params![w.start, w.end, q.user, w.ip, q.kind], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?,
                    r.get::<_, u64>(3)?,
                    r.get::<_, u64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })? {
                let (ip, n, success, failure, invalid, start, end) = r?;
                groups.push(json!({"source_ip":ip,"records":n,"successful_authentications":success,"failed_authentication_records":failure,"invalid_user_observations":invalid,"first_observed":time_value(start),"last_observed":time_value(end)}));
            }
            let sql = format!(
                "SELECT payload FROM auth_records WHERE {FILTER} ORDER BY timestamp_us,id LIMIT ?6 OFFSET ?7"
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut records = vec![];
            for r in stmt.query_map(
                params![w.start, w.end, q.user, w.ip, q.kind, w.limit, w.offset],
                |r| r.get::<_, String>(0),
            )? {
                records.push(serde_json::from_str::<Value>(&r?)?);
            }
            (
                Value::Object(counts),
                groups,
                records,
                total,
                first,
                last,
                source_count,
            )
        };
        let returned = records.len();
        let more = (w.offset as u64 + returned as u64) < total;
        Ok(
            json!({"query":{"since":time_value(w.start),"until_exclusive":time_value(w.end),"user":q.user,"source_ip":w.ip,"kind":q.kind},
            "counts":counts,"total_matching_records":total,"first_matching_record":first.map(time_value),"last_matching_record":last.map(time_value),
            "source_groups":groups,"source_group_count":source_count,"source_groups_truncated":source_count>100,
            "records":records,"returned_count":returned,"limit":w.limit,"offset":w.offset,"has_more":more,"next_offset":if more{Some(w.offset+returned)}else{None},
            "counting_note":"Counts cover all indexed rows matching this exact half-open time range and filters, not just the returned page. Invalid-user observations are not added to failed-authentication counts; one attempt can produce both. Lifecycle/disconnect records are not successful logins. Retained logs cannot prove the absence of unrecorded activity.",
            "coverage":self.auth_health(w.start,w.end)?}),
        )
    }
    pub fn auth_health(&self, start: i64, end: i64) -> Result<Value> {
        let began = self.get("auth_detail_started_at")?;
        let scans = self.get("auth_backfill")?;
        let heartbeat = self.get("auth_journal_heartbeat")?;
        let fresh = heartbeat
            .as_ref()
            .and_then(|v| v["timestamp"].as_u64())
            .is_some_and(|t| crate::now().saturating_sub(t) <= 20);
        let scanned = scans.as_ref().is_some_and(|v| {
            v["scan_completed"] == true
                && v["since_us"].as_i64().is_some_and(|n| n <= start)
                && v["until_us"].as_i64().is_some_and(|n| n >= end)
        });
        let live_range = began
            .as_ref()
            .and_then(Value::as_u64)
            .is_some_and(|n| start >= n as i64 * 1_000_000);
        let joined_range = began.as_ref().and_then(Value::as_u64).is_some_and(|began| {
            scans.as_ref().is_some_and(|scan| {
                scan["scan_completed"] == true
                    && scan["since_us"].as_i64().is_some_and(|n| n <= start)
                    && scan["until_us"]
                        .as_i64()
                        .is_some_and(|n| n >= began as i64 * 1_000_000)
            })
        });
        let restarts = self.get("auth_collection_gaps")?.unwrap_or(json!([]));
        let restart_overlap = restarts.as_array().is_some_and(|rows| {
            rows.iter().any(|r| {
                r["since"].as_i64().is_some_and(|n| n * 1_000_000 < end)
                    && r["until"].as_i64().is_some_and(|n| n * 1_000_000 > start)
            })
        });
        let pruned = self
            .get("auth_pruned_before")?
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let earliest = {
            let conn = self.0.lock().unwrap();
            conn.query_row("SELECT MIN(timestamp_us) FROM auth_records", [], |r| {
                r.get::<_, Option<i64>>(0)
            })?
        };
        Ok(
            json!({"counts_scope":"indexed_auth_records_only","individual_recording_started_at":began,"oldest_indexed_record":earliest.map(time_value),
            "requested_range_scanned_from_retained_journal":scanned,"requested_range_after_detail_upgrade":live_range,
            "requested_range_covered_by_scan_and_live_index":scanned||live_range||joined_range,
            "range_precedes_retention_cutoff":start<pruned as i64*1_000_000,"pruned_before":time_value(pruned as i64*1_000_000),
            "history_gap_possible":(!scanned && !live_range && !joined_range)||(!scanned && restart_overlap)||start<pruned as i64*1_000_000,
            "journal_reader_heartbeat":heartbeat,"journal_reader_recently_alive":fresh,"last_backfill":scans,
            "parser_rejections":self.get("auth_parser_rejections")?,"known_collection_restarts":restarts,"last_collector_error":self.get("auth_last_collector_error")?,"unparsed_auth_count_note":"Inspect counts.unparsed_auth; it indicates known auth prefixes that could not be classified.",
            "scope":"Root-origin sshd/sshd-session/sshd-auth journal records across units, including session scopes; no console, arbitrary command, or general sudo audit.",
            "limitations":["A completed scan covers retained journal data, not vacuumed or never-recorded events.","Reader heartbeat proves the process was alive, not that journald never dropped logs.","Before v0.3 individual failed authentications and lifecycle records were not stored; backfill can recover only retained records."]}),
        )
    }
    pub fn auth_evidence(&self, id: &str) -> Result<Value> {
        ensure!(id.len() <= 128, "invalid evidence ID");
        let conn = self.0.lock().unwrap();
        let row: Option<(String, Option<String>, Option<u32>, i64)> = conn
            .query_row(
                "SELECT payload,boot_id,pid,timestamp_us FROM auth_records WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (raw, boot, pid, t) = row.context("evidence not indexed or no longer retained")?;
        let evidence: Value = serde_json::from_str(&raw)?;
        let mut related = vec![];
        if boot.is_some() && pid.is_some() {
            let start:Option<i64>=conn.query_row("SELECT MAX(timestamp_us) FROM auth_records WHERE boot_id=? AND pid=? AND kind='success' AND timestamp_us<=?",params![boot,pid,t],|r|r.get(0))?;
            if let Some(start) = start {
                let next:Option<i64>=conn.query_row("SELECT MIN(timestamp_us) FROM auth_records WHERE boot_id=? AND pid=? AND kind='success' AND timestamp_us>?",params![boot,pid,start],|r|r.get(0))?;
                let end = next
                    .unwrap_or(start + 86_400_000_000)
                    .min(start + 86_400_000_000);
                let mut stmt=conn.prepare("SELECT payload FROM auth_records WHERE boot_id=? AND pid=? AND timestamp_us>=? AND timestamp_us<? ORDER BY timestamp_us,id LIMIT 101")?;
                for r in
                    stmt.query_map(params![boot, pid, start, end], |r| r.get::<_, String>(0))?
                {
                    related.push(serde_json::from_str::<Value>(&r?)?);
                }
            }
        }
        let truncated = related.len() > 100;
        related.truncate(100);
        Ok(
            json!({"evidence":evidence,"related_process_records":related,"related_records_truncated":truncated,
            "correlation_basis":"Same boot ID and journal PID, bounded by an accepted login and the next accepted login for that PID (maximum 24 hours). This is process-level correlation, not proof of a human operator. Missing close records do not imply an active session."}),
        )
    }
    pub fn login_timeline(&self, q: &AuthQuery) -> Result<Value> {
        ensure!(
            q.kind.as_deref().is_none_or(|k| k == "success"),
            "login timeline accepts only successful login starts; use get_auth_attempts for other kinds"
        );
        let mut q = q.clone();
        q.kind = Some("success".into());
        let mut report = self.auth_query(&q)?;
        let snapshot = self.get("sessions")?.unwrap_or(Value::Null);
        let fresh = snapshot["timestamp"]
            .as_u64()
            .is_some_and(|t| t <= crate::now() && crate::now() - t <= 45);
        let mut timelines = vec![];
        for login in report["records"].as_array().context("login rows")? {
            let details = self.auth_evidence(login["evidence_id"].as_str().context("login ID")?)?;
            let related = details["related_process_records"]
                .as_array()
                .context("related evidence")?;
            let lifecycle = |kind: &str| {
                related.iter().find(|r| {
                    r["kind"] == kind && (kind == "disconnect" || r["user"] == login["user"])
                })
            };
            let open = lifecycle("session_open");
            let close = lifecycle("session_close");
            let disconnect = lifecycle("disconnect");
            let brief = |r: &Value| json!({"evidence_id":r["evidence_id"],"time":r["time"]});
            let duration = close
                .and_then(|r| {
                    r["source"]["monotonic_microseconds"]
                        .as_u64()?
                        .checked_sub(login["source"]["monotonic_microseconds"].as_u64()?)
                })
                .map(|us| us as f64 / 1_000_000.0);
            let active: Vec<_> = snapshot["sessions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|s| {
                    fresh
                        && s["is_active_ssh"] == true
                        && s["matched_login"]["evidence_id"] == login["evidence_id"]
                })
                .map(|s| s["session_id"].clone())
                .collect();
            timelines.push(json!({"login":login,"session_open":open.map(brief),"session_close":close.map(brief),"disconnect":disconnect.map(brief),
                "login_to_pam_close_seconds":duration,"duration_basis":"same-boot monotonic timestamps; null when unavailable or reversed; not TCP connection duration",
                "session_close_observed":close.is_some(),"disconnect_observed":disconnect.is_some(),"currently_active_session_ids":active,
                "current_state":if !active.is_empty(){"active_in_snapshot"}else{"not_established_from_snapshot"},
                "related_records_truncated":details["related_records_truncated"]}));
        }
        report.as_object_mut().unwrap().remove("records");
        report["timelines"] = json!(timelines);
        report["session_snapshot_timestamp"] = snapshot["timestamp"].clone();
        report["session_snapshot_fresh"] = json!(fresh);
        report["timeline_scope"] = json!(
            "Query range/counts refer only to successful login starts. Related events share boot/PID and occur before the next accepted login for that PID, maximum 24 hours and 100 records, potentially beyond the query end. Correlation is not an immutable kernel process identity or operator identity. PAM close does not prove TCP disconnection; no close does not imply an active connection. Missing or moved-scope processes and historical commands are not reconstructed. Pagination and lifecycle lookups are separate read snapshots; concurrent retention/backfill can change results."
        );
        Ok(report)
    }
    pub fn investigate(&self, q: &AuthQuery) -> Result<Value> {
        let mut report = self.auth_query(q)?;
        report["current_sessions"] = self
            .get("sessions")?
            .unwrap_or(json!({"status":"not_collected"}));
        report["current_sessions_note"] = json!(
            "Current snapshot is separate from the historical query window. A manager or closing/stale session is not an active SSH connection."
        );
        report["trust_policy"] = self.get("trust_policy")?.unwrap_or(Value::Null);
        report["automation_receipts"] = self
            .get("automation_receipts")?
            .unwrap_or(json!({"status":"not_collected"}));
        report["conclusion_constraints"] = json!([
            "Use the backend counts and formatted times verbatim; page length is not window total.",
            "Trusted means matching configured conditions, not verified human ownership.",
            "Frequent successful logins alone do not prove intrusion or automation.",
            "A missing event or receipt is unknown unless collection coverage is established; do not assert no failed attempts globally."
        ]);
        Ok(report)
    }
}

/// Explicit administrative backfill: no notifications, no detector/cursor changes.
pub async fn backfill(config: &Config, store: &Store, since: &str, until: &str) -> Result<Value> {
    let q = AuthQuery {
        since: Some(since.into()),
        until: Some(until.into()),
        ..Default::default()
    };
    let w = q.window()?;
    let mut metadata = json!({"since_us":w.start,"until_us":w.end,"scan_completed":false,"started_at":crate::now(),"records_scanned":0,"evidence_records":0});
    store.set("auth_backfill", &metadata)?;
    let result: Result<(usize, usize)> = tokio::time::timeout(Duration::from_secs(90), async {
        let mut command = Command::new("journalctl");
        command
            .args(["--output=json", "--no-pager", "--all"])
            .arg(format!(
                "--since=@{}.{:06}",
                w.start / 1_000_000,
                w.start % 1_000_000
            ))
            .arg(format!(
                "--until=@{}.{:06}",
                w.end / 1_000_000,
                w.end % 1_000_000
            ))
            .args(JOURNAL_MATCHES)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        let mut child = command.spawn()?;
        let mut reader = BufReader::new(child.stdout.take().context("journal stdout")?);
        let mut scanned = 0usize;
        let mut indexed = 0usize;
        loop {
            let mut buf = vec![];
            let n = (&mut reader)
                .take(1024 * 1024 + 1)
                .read_until(b'\n', &mut buf)
                .await?;
            if n == 0 {
                break;
            }
            ensure!(n <= 1024 * 1024, "oversized journal entry");
            scanned += 1;
            ensure!(
                scanned <= 100000,
                "backfill limit reached; use smaller non-overlapping windows"
            );
            let raw: Value = serde_json::from_slice(&buf)?;
            if let Some(record) = from_journal(&raw, config, true)
                && record.timestamp_us >= w.start
                && record.timestamp_us < w.end
            {
                insert_record(&store.0.lock().unwrap(), &record)?;
                indexed += 1;
            }
        }
        ensure!(
            child.wait().await?.success(),
            "journal backfill exited unsuccessfully"
        );
        Ok((scanned, indexed))
    })
    .await
    .context("journal backfill timed out; imported evidence remains but coverage is incomplete")?;
    match result {
        Ok((scanned, indexed)) => {
            metadata["scan_completed"] = json!(true);
            metadata["records_scanned"] = json!(scanned);
            metadata["evidence_records"] = json!(indexed);
        }
        Err(e) => {
            metadata["error"] = json!(e.to_string());
            store.set("auth_backfill", &metadata)?;
            return Err(e);
        }
    }
    metadata["finished_at"] = json!(crate::now());
    store.set("auth_backfill", &metadata)?;
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{daemon::ingest, journal::FailureTracker};
    fn stamp(s: &str) -> i64 {
        DateTime::parse_from_rfc3339(s).unwrap().timestamp_micros()
    }
    fn record(cursor: &str, t: i64, message: &str) -> Value {
        json!({"__CURSOR":cursor,"__REALTIME_TIMESTAMP":t.to_string(),"__MONOTONIC_TIMESTAMP":"123456789","_UID":"0","_COMM":"sshd-session","_BOOT_ID":"boot","_PID":"1234","_SYSTEMD_UNIT":"session-42.scope","MESSAGE":message})
    }
    #[test]
    fn full_range_counts_are_independent_of_page_and_timezone_is_explicit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("db"))?;
        let c = Config::default();
        let mut tracker = FailureTracker::default();
        let base = stamp("2024-01-01T20:00:00+08:00");
        for i in 0..25 {
            ingest(
                &store,
                &c,
                &mut tracker,
                &record(
                    &format!("login-{i}"),
                    base + i * 60_000_000,
                    "Accepted publickey for ubuntu from 192.0.2.1 port 1234 ssh2: RSA SHA256:test",
                ),
            )?;
        }
        let mut q = AuthQuery {
            since: Some("2024-01-01T20:00:00+08:00".into()),
            until: Some("2024-01-01T20:30:00+08:00".into()),
            limit: Some(1),
            ..Default::default()
        };
        let r = store.auth_query(&q)?;
        assert_eq!(r["counts"]["success"], 25);
        assert_eq!(r["returned_count"], 1);
        assert_eq!(r["next_offset"], 1);
        assert_eq!(
            r["records"][0]["time"]["beijing"],
            "2024-01-01T20:00:00+08:00"
        );
        q.offset = Some(24);
        let last = store.auth_query(&q)?;
        assert_eq!(last["counts"]["success"], 25);
        assert_eq!(last["has_more"], false);
        q.since = Some("2024-01-01T12:17:00Z".into());
        q.until = Some("2024-01-01T12:18:00Z".into());
        q.offset = Some(0);
        assert_eq!(store.auth_query(&q)?["counts"]["success"], 1);
        q.source_ip = Some("192.0.2.2".into());
        assert_eq!(store.auth_query(&q)?["total_matching_records"], 0);
        q.since = Some("2024-01-01 20:00:00".into());
        assert!(store.auth_query(&q).is_err());
        Ok(())
    }
    #[test]
    fn failures_are_kept_below_alert_threshold_without_double_counting_invalid_users() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("db"))?;
        let c = Config::default();
        let mut tracker = FailureTracker::default();
        let t = stamp("2024-01-01T20:17:23+08:00");
        for (cursor, msg) in [
            ("invalid", "Invalid user admin from 192.0.2.9 port 4242"),
            (
                "failed",
                "Failed password for invalid user admin from 192.0.2.9 port 4242 ssh2",
            ),
        ] {
            let r = record(cursor, t, msg);
            ingest(&store, &c, &mut tracker, &r)?;
            ingest(&store, &c, &mut tracker, &r)?;
        }
        assert_eq!(store.queue_size()?, 0);
        let q = AuthQuery {
            since: Some("2024-01-01T20:17:00+08:00".into()),
            until: Some("2024-01-01T20:26:00+08:00".into()),
            ..Default::default()
        };
        let r = store.auth_query(&q)?;
        assert_eq!(r["counts"]["failure"], 1);
        assert_eq!(r["counts"]["invalid_user"], 1);
        assert_eq!(r["counts"]["success"], 0);
        let mut forged = record(
            "forged",
            t,
            "Accepted publickey for root from 192.0.2.9 port 4242 ssh2",
        );
        forged["_UID"] = json!("1000");
        ingest(&store, &c, &mut tracker, &forged)?;
        assert_eq!(store.auth_query(&q)?["counts"]["success"], 0);
        assert_eq!(r["records"][0]["user"], "admin");
        Ok(())
    }
    #[test]
    fn timelines_correlate_each_login_without_pairing_aggregate_counts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("db"))?;
        let c = Config::default();
        let base = stamp("2024-01-01T20:00:00+08:00");
        let mut first_id = String::new();
        for (i, cursor, kind, pid, boot, mono) in [
            (0, "first", "success", "1234", "boot", "1000000"),
            (1, "wrong-pid", "close", "9999", "boot", "2000000"),
            (2, "wrong-boot", "close", "1234", "other", "3000000"),
            (3, "second", "success", "1234", "boot", "4000000"),
            (4, "second-close", "close", "1234", "boot", "5000000"),
        ] {
            let message = if kind == "success" {
                "Accepted publickey for ubuntu from 192.0.2.1 port 1234 ssh2"
            } else {
                "pam_unix(sshd:session): session closed for user ubuntu"
            };
            let mut raw = record(cursor, base + i * 1_000_000, message);
            raw["_PID"] = json!(pid);
            raw["_BOOT_ID"] = json!(boot);
            raw["__MONOTONIC_TIMESTAMP"] = json!(mono);
            let r = from_journal(&raw, &c, true).unwrap();
            if i == 0 {
                first_id = r.id.clone();
            }
            insert_record(&store.0.lock().unwrap(), &r)?;
        }
        let mut q = AuthQuery {
            since: Some("2024-01-01T20:00:00+08:00".into()),
            until: Some("2024-01-01T20:00:04+08:00".into()),
            limit: Some(1),
            ..Default::default()
        };
        let r = store.login_timeline(&q)?;
        assert_eq!(r["counts"]["success"], 2);
        assert_eq!(r["returned_count"], 1);
        assert_eq!(r["timelines"][0]["session_close_observed"], false);
        assert_eq!(
            r["timelines"][0]["current_state"],
            "not_established_from_snapshot"
        );
        q.offset = Some(1);
        let r = store.login_timeline(&q)?;
        assert_eq!(r["timelines"][0]["session_close_observed"], true);
        assert_eq!(r["timelines"][0]["login_to_pam_close_seconds"], 1.0);
        assert_eq!(r["timelines"][0]["disconnect_observed"], false);
        // The close is outside the login-start window, but still correlated.
        assert_eq!(
            r["timelines"][0]["session_close"]["time"]["unix_microseconds"],
            base + 4_000_000
        );
        q.offset = Some(0);
        let mut snapshot = json!({"timestamp":crate::now(),"sessions":[{"session_id":"42","is_active_ssh":true,"matched_login":{"evidence_id":first_id}}]});
        store.set("sessions", &snapshot)?;
        assert_eq!(
            store.login_timeline(&q)?["timelines"][0]["current_state"],
            "active_in_snapshot"
        );
        snapshot["timestamp"] = json!(crate::now() - 46);
        store.set("sessions", &snapshot)?;
        assert_eq!(
            store.login_timeline(&q)?["timelines"][0]["current_state"],
            "not_established_from_snapshot"
        );
        q.kind = Some("failure".into());
        assert!(store.login_timeline(&q).is_err());
        Ok(())
    }
    #[test]
    fn lifecycle_evidence_is_bound_to_boot_and_pid_and_backfill_has_no_alerts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("db"))?;
        let c = Config::default();
        let t = stamp("2024-01-01T20:17:23+08:00");
        let raw = record(
            "success",
            t,
            "Accepted publickey for ubuntu from 192.0.2.1 port 1234 ssh2: RSA SHA256:test",
        );
        let login = from_journal(&raw, &c, true).unwrap();
        insert_record(&store.0.lock().unwrap(), &login)?;
        insert_record(&store.0.lock().unwrap(), &login)?;
        let close = from_journal(
            &record(
                "closed",
                t + 10_000_000,
                "pam_unix(sshd:session): session closed for user ubuntu",
            ),
            &c,
            true,
        )
        .unwrap();
        insert_record(&store.0.lock().unwrap(), &close)?;
        let mut unrelated = record(
            "other-boot",
            t + 5_000_000,
            "pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by ubuntu(uid=0)",
        );
        unrelated["_BOOT_ID"] = json!("different");
        insert_record(
            &store.0.lock().unwrap(),
            &from_journal(&unrelated, &c, true).unwrap(),
        )?;
        assert_eq!(store.queue_size()?, 0);
        assert!(store.get("journal_cursor")?.is_none());
        let details = store.auth_evidence(&login.id)?;
        assert_eq!(
            details["related_process_records"].as_array().unwrap().len(),
            2
        );
        assert_eq!(details["evidence"]["source"]["unit"], "session-42.scope");
        assert_eq!(
            details["evidence"]["trust_evaluation"],
            "policy_at_backfill_time"
        );
        let h = store.auth_health(t, t + 60_000_000)?;
        assert_eq!(h["history_gap_possible"], true);
        store.set(
            "auth_backfill",
            &json!({"scan_completed":true,"since_us":t,"until_us":t+60_000_000}),
        )?;
        assert_eq!(
            store.auth_health(t, t + 60_000_000)?["requested_range_scanned_from_retained_journal"],
            true
        );
        Ok(())
    }
}
