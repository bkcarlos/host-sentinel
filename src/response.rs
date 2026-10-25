//! Privileged, local-only response broker. Client approval is enforced by Rakazo;
//! this broker enforces immutable proposals, identity checks and host safeguards.
use crate::config::ResponseConfig;
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use rmcp::schemars;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashMap, net::IpAddr, path::Path, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Command,
};

const TABLE: &str = "host_sentinel_response";

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Disconnect,
    Quarantine,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub session_id: String,
    pub user: String,
    pub uid: u32,
    pub source_ip: IpAddr,
    pub service: String,
    pub class: String,
    pub remote: bool,
    pub leader: u32,
    pub leader_start_ticks: u64,
    pub boot_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub proposal_id: String,
    pub host: String,
    pub action: Action,
    pub target: Session,
    pub duration_seconds: u64,
    pub ssh_ports: Vec<u16>,
    pub expires_at: u64,
    pub dry_run: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareInput {
    pub session_id: String,
    pub action: Action,
    /// Quarantine lifetime, 60..configured maximum seconds. Defaults to 900.
    pub duration_seconds: Option<u64>,
    /// Explain why this exact SSH session needs a response.
    pub reason: String,
    /// A dry run still requires client approval but never changes firewall or sessions.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    List,
    Prepare {
        input: PrepareInput,
    },
    Execute {
        proposal: Box<Proposal>,
    },
    Audit,
    InspectProcess {
        pid: u32,
    },
    PrepareProcess {
        input: crate::process_response::PrepareProcess,
    },
    ExecuteProcess {
        proposal: Box<crate::process_response::ProcessProposal>,
    },
}

fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && !id.starts_with('-')
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

pub fn validate_target(s: &Session, c: &ResponseConfig) -> Result<()> {
    ensure!(valid_session_id(&s.session_id), "invalid session ID");
    ensure!(
        s.remote && s.service == "sshd" && s.class == "user",
        "only remote SSH user sessions can be targeted"
    );
    ensure!(
        s.uid >= 1000 && !c.protected_users.contains(&s.user),
        "system or protected account cannot be targeted"
    );
    ensure!(
        s.leader > 1 && s.leader_start_ticks > 0 && !s.boot_id.is_empty(),
        "incomplete session process identity"
    );
    let ip = normalize_ip(s.source_ip);
    ensure!(
        !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
        "local or invalid source cannot be targeted"
    );
    let link_local = match ip {
        IpAddr::V4(v) => v.is_link_local() || v.is_broadcast(),
        IpAddr::V6(v) => v.is_unicast_link_local(),
    };
    ensure!(
        !link_local,
        "link-local or broadcast source cannot be targeted"
    );
    ensure!(
        !c.protected_networks.iter().any(|n| n.contains(&ip)),
        "source belongs to a protected management network"
    );
    Ok(())
}

pub fn validate_execution(
    p: &Proposal,
    stored: &Proposal,
    live: &Session,
    c: &ResponseConfig,
    now: u64,
) -> Result<()> {
    ensure!(
        p == stored,
        "proposal was modified; obtain a new proposal and approval"
    );
    ensure!(
        now < p.expires_at,
        "proposal expired; obtain a new proposal and approval"
    );
    ensure!(
        &p.target == live,
        "session identity changed; no action executed"
    );
    ensure!(
        p.ssh_ports == c.ssh_ports,
        "SSH port configuration changed; obtain a new proposal"
    );
    if p.action == Action::Quarantine {
        ensure!(
            (60..=c.max_quarantine_seconds).contains(&p.duration_seconds),
            "quarantine duration outside policy"
        );
    } else {
        ensure!(
            p.duration_seconds == 0,
            "disconnect has no quarantine duration"
        );
    }
    // Dry run may inspect a protected source, but can never perform an effect.
    if !p.dry_run {
        validate_target(live, c)?;
    }
    Ok(())
}

async fn command(program: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn().with_context(|| format!("start {program}"))?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().context("command stdin")?;
        pipe.write_all(input.as_bytes()).await?;
        pipe.shutdown().await?;
    }
    let out = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .context("system command timed out")??;
    ensure!(
        out.stdout.len() <= 1024 * 1024 && out.stderr.len() <= 16384,
        "system command output too large"
    );
    if !out.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(500)
                .collect::<String>()
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

pub async fn session(id: &str) -> Result<Session> {
    ensure!(valid_session_id(id), "invalid session ID");
    let text = command(
        "/usr/bin/loginctl",
        &[
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
            "Remote",
            "-p",
            "RemoteHost",
            "-p",
            "Service",
            "-p",
            "Class",
            "-p",
            "Leader",
        ],
        None,
    )
    .await?;
    let fields: HashMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
    let get = |key| {
        fields
            .get(key)
            .copied()
            .with_context(|| format!("missing session {key}"))
    };
    let leader: u32 = get("Leader")?.parse()?;
    let stat = std::fs::read_to_string(format!("/proc/{leader}/stat"))
        .context("session leader is no longer present")?;
    let start = stat
        .rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing process start time")?
        .parse()?;
    Ok(Session {
        session_id: get("Id")?.into(),
        user: get("Name")?.into(),
        uid: get("User")?.parse()?,
        source_ip: normalize_ip(
            get("RemoteHost")?
                .parse()
                .context("session source is not an IP address")?,
        ),
        service: get("Service")?.into(),
        class: get("Class")?.into(),
        remote: get("Remote")? == "yes",
        leader,
        leader_start_ticks: start,
        boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
    })
}

async fn sessions(c: &ResponseConfig) -> Result<Vec<Value>> {
    let text = command(
        "/usr/bin/loginctl",
        &["list-sessions", "--no-legend", "--no-pager"],
        None,
    )
    .await?;
    let mut result = vec![];
    for id in text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .take(64)
    {
        match session(id).await {
            Ok(s) => {
                let refusal = validate_target(&s, c).err().map(|e| e.to_string());
                result.push(
                    json!({"session":s,"eligible":refusal.is_none(),"protected_reason":refusal}),
                );
            }
            Err(e) => result
                .push(json!({"session_id":id,"eligible":false,"unavailable_reason":e.to_string()})),
        }
    }
    Ok(result)
}

fn firewall_comment(c: &ResponseConfig) -> String {
    format!(
        "host-sentinel-response/v1 ports={}",
        c.ssh_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn firewall_setup(c: &ResponseConfig) -> String {
    let ports = c
        .ssh_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "create table inet {TABLE} {{ comment \"{}\"; }}\n\
        add set inet {TABLE} ssh4 {{ type ipv4_addr; flags timeout; }}\n\
        add set inet {TABLE} ssh6 {{ type ipv6_addr; flags timeout; }}\n\
        add chain inet {TABLE} input {{ type filter hook input priority -10; policy accept; }}\n\
        add rule inet {TABLE} input ip saddr @ssh4 tcp dport {{ {ports} }} counter drop\n\
        add rule inet {TABLE} input ip6 saddr @ssh6 tcp dport {{ {ports} }} counter drop\n",
        firewall_comment(c)
    )
}

async fn quarantine(p: &Proposal, c: &ResponseConfig) -> Result<()> {
    let tables = command("/usr/sbin/nft", &["-j", "list", "tables"], None).await?;
    let tables: Value = serde_json::from_str(&tables)?;
    let exists = tables["nftables"]
        .as_array()
        .context("invalid nft table list")?
        .iter()
        .any(|v| v["table"]["family"] == "inet" && v["table"]["name"] == TABLE);
    if !exists {
        command("/usr/sbin/nft", &["-f", "-"], Some(&firewall_setup(c))).await?;
    }
    let table = command(
        "/usr/sbin/nft",
        &["-j", "list", "table", "inet", TABLE],
        None,
    )
    .await?;
    let table: Value = serde_json::from_str(&table)?;
    verify_firewall(&table, c)?;
    let set = if p.target.source_ip.is_ipv4() {
        "ssh4"
    } else {
        "ssh6"
    };
    // Atomic add, never flush or replace another table. Existing elements are not
    // automatically extended by a retry; the durable proposal is single-use.
    let script = format!(
        "add element inet {TABLE} {set} {{ {} timeout {}s }}\n",
        p.target.source_ip, p.duration_seconds
    );
    command("/usr/sbin/nft", &["-f", "-"], Some(&script)).await?;
    Ok(())
}

pub fn verify_firewall(table: &Value, c: &ResponseConfig) -> Result<()> {
    let rows = table["nftables"].as_array().context("invalid nft table")?;
    ensure!(
        rows.iter()
            .any(|v| v["table"]["name"] == TABLE && v["table"]["comment"] == firewall_comment(c)),
        "firewall table is not owned by this configuration"
    );
    ensure!(
        rows.iter().filter(|v| v.get("chain").is_some()).count() == 1,
        "unexpected firewall chain layout"
    );
    ensure!(
        rows.iter().any(|v| v["chain"]["name"] == "input"
            && v["chain"]["hook"] == "input"
            && v["chain"]["prio"] == -10
            && v["chain"]["policy"] == "accept"),
        "firewall chain changed"
    );
    for (name, kind) in [("ssh4", "ipv4_addr"), ("ssh6", "ipv6_addr")] {
        ensure!(
            rows.iter().any(|v| v["set"]["name"] == name
                && v["set"]["type"] == kind
                && v["set"]["flags"]
                    .as_array()
                    .is_some_and(|a| a.contains(&json!("timeout")))),
            "firewall timeout set missing"
        );
    }
    let rules: Vec<_> = rows.iter().filter_map(|v| v.get("rule")).collect();
    ensure!(rules.len() == 2, "unexpected firewall rule count");
    for (family, set) in [("ip", "ssh4"), ("ip6", "ssh6")] {
        let ports = if c.ssh_ports.len() == 1 {
            json!(c.ssh_ports[0])
        } else {
            json!({"set":c.ssh_ports})
        };
        ensure!(rules.iter().any(|rule| {
            let Some(expr)=rule["expr"].as_array() else {return false};
            rule["chain"]=="input" && expr.len()==4
                && expr[0]==json!({"match":{"op":"==","left":{"payload":{"protocol":family,"field":"saddr"}},"right":format!("@{set}")}})
                && expr[1]==json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":ports}})
                && expr[2].get("counter").is_some() && expr[3]==json!({"drop":null})
        }),"firewall rule changed; refusing action");
    }
    Ok(())
}

pub(crate) struct Ledger {
    conn: Connection,
}
impl Ledger {
    fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY,proposal TEXT NOT NULL,status TEXT NOT NULL,result TEXT,created INTEGER NOT NULL);")?;
        Ok(Self { conn })
    }
    pub(crate) fn put<T: Serialize>(&self, proposal: &T) -> Result<()> {
        let p = serde_json::to_value(proposal)?;
        self.conn.execute("UPDATE actions SET status='expired' WHERE status='prepared' AND json_extract(proposal,'$.expires_at')<=?",[crate::now()])?;
        let pending: u64 = self.conn.query_row(
            "SELECT count(*) FROM actions WHERE status='prepared'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            pending < 32,
            "too many pending proposals; wait for existing proposals to expire"
        );
        self.conn.execute(
            "INSERT INTO actions VALUES (?,?,'prepared',NULL,?)",
            params![
                p["proposal_id"].as_str().context("proposal ID")?,
                p.to_string(),
                crate::now()
            ],
        )?;
        Ok(())
    }
    pub(crate) fn get<T: serde::de::DeserializeOwned>(
        &self,
        id: &str,
    ) -> Result<(T, String, Option<Value>)> {
        let row: Option<(String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT proposal,status,result FROM actions WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (p, status, result) = row.context("unknown proposal")?;
        Ok((
            serde_json::from_str(&p)?,
            status,
            result.map(|s| serde_json::from_str(&s)).transpose()?,
        ))
    }
    pub(crate) fn claim(&self, id: &str) -> Result<()> {
        ensure!(
            self.conn.execute(
                "UPDATE actions SET status='executing' WHERE id=? AND status='prepared'",
                [id]
            )? == 1,
            "proposal already consumed"
        );
        Ok(())
    }
    pub(crate) fn finish(&self, id: &str, result: &Value) -> Result<()> {
        self.conn.execute(
            "UPDATE actions SET status='finished',result=? WHERE id=?",
            params![result.to_string(), id],
        )?;
        Ok(())
    }
    fn audit(&self) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT proposal,status,result FROM actions ORDER BY created DESC,rowid DESC LIMIT 50",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut out = vec![];
        for row in rows {
            let (p, status, result) = row?;
            out.push(json!({"proposal":serde_json::from_str::<Value>(&p)?,"status":status,"result":result.map(|s|serde_json::from_str::<Value>(&s)).transpose()?}));
        }
        Ok(out)
    }
}

async fn handle(req: Request, c: &ResponseConfig, host: &str, ledger: &Ledger) -> Result<Value> {
    match req {
        Request::InspectProcess { pid } => crate::process_response::inspect(pid, c),
        Request::PrepareProcess { input } => {
            crate::process_response::prepare(input, c, host, ledger)
        }
        Request::ExecuteProcess { proposal } => {
            crate::process_response::execute(*proposal, c, ledger)
        }
        Request::List => Ok(
            json!({"timestamp":crate::now(),"sessions":sessions(c).await?,"protected_networks":c.protected_networks,"ssh_ports":c.ssh_ports}),
        ),
        Request::Audit => Ok(json!(ledger.audit()?)),
        Request::Prepare { input } => {
            ensure!(
                !input.reason.trim().is_empty() && input.reason.len() <= 1000,
                "reason must be 1..1000 bytes"
            );
            let target = session(&input.session_id).await?;
            let refusal = validate_target(&target, c).err().map(|e| e.to_string());
            ensure!(
                input.dry_run || refusal.is_none(),
                "{}",
                refusal.as_deref().unwrap_or("target refused")
            );
            let duration = if input.action == Action::Quarantine {
                input.duration_seconds.unwrap_or(900)
            } else {
                0
            };
            ensure!(
                input.action != Action::Quarantine
                    || (60..=c.max_quarantine_seconds).contains(&duration),
                "invalid quarantine duration"
            );
            let p = Proposal {
                proposal_id: uuid::Uuid::new_v4().to_string(),
                host: host.into(),
                action: input.action,
                target,
                duration_seconds: duration,
                ssh_ports: c.ssh_ports.clone(),
                expires_at: crate::now() + c.proposal_ttl_seconds,
                dry_run: input.dry_run,
                reason: input.reason,
            };
            ledger.put(&p)?;
            Ok(
                json!({"execute_arguments":{"proposal":p},"requires_human_approval":true,
                "effect":if input.action==Action::Quarantine {"Blocks this source IP on the listed SSH ports (including other connections from the same IP), then terminates the selected session. The IP block expires automatically; killed processes cannot be restored."} else {"Terminates this one SSH session and its processes. Does not prevent reconnection."},
                "dry_run_protection_notice":refusal}),
            )
        }
        Request::Execute { proposal: p } => {
            let (stored, status, result) = ledger.get::<Proposal>(&p.proposal_id)?;
            ensure!(*p == stored, "proposal was modified");
            if status == "finished" {
                return Ok(json!({"replayed":true,"result":result}));
            }
            ensure!(
                status == "prepared",
                "proposal already started; outcome may be indeterminate; inspect audit and firewall, never retry this action automatically"
            );
            let live = session(&p.target.session_id).await?;
            validate_execution(&p, &stored, &live, c, crate::now())?;
            ledger.claim(&p.proposal_id)?;
            let mut result = json!({"proposal_id":p.proposal_id,"timestamp":crate::now(),"dry_run":p.dry_run,"quarantined":false,"disconnected":false});
            if p.dry_run {
                result["ok"] = json!(true);
                result["message"] =
                    json!("Dry run only: no firewall or session changes were made.");
            } else {
                let effect: Result<()> = async {
                    if p.action == Action::Quarantine {
                        quarantine(&p, c).await?;
                        result["quarantined"] = json!(true);
                        result["quarantine_expires_at"] = json!(crate::now() + p.duration_seconds);
                    }
                    command(
                        "/usr/bin/loginctl",
                        &["terminate-session", &p.target.session_id],
                        None,
                    )
                    .await?;
                    result["disconnected"] = json!(true);
                    Ok(())
                }
                .await;
                result["ok"] = json!(effect.is_ok());
                if let Err(error) = effect {
                    result["error"] = json!(error.to_string());
                }
            }
            ledger.finish(&p.proposal_id, &result)?;
            tracing::info!(proposal_id=%p.proposal_id,dry_run=p.dry_run,"response action finished; inspect privileged ledger for result");
            Ok(result)
        }
    }
}

pub async fn client(socket: &Path, request: Request) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut stream = UnixStream::connect(socket)
            .await
            .context("response broker is unavailable")?;
        stream.write_all(&serde_json::to_vec(&request)?).await?;
        stream.write_all(b"\n").await?;
        let mut bytes = vec![];
        BufReader::new(stream)
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut bytes)
            .await?;
        ensure!(bytes.len() <= 1024 * 1024, "broker response too large");
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("response broker timed out")?
}

pub async fn serve_agent(c: ResponseConfig, host: String) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    ensure!(cfg!(target_os = "linux"), "response broker requires Linux");
    let status = std::fs::read_to_string("/proc/self/status")?;
    ensure!(
        status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2))
            == Some("0"),
        "response broker must run as root"
    );
    ensure!(c.enabled, "response capability is disabled");
    std::fs::create_dir_all(&c.state_dir)?;
    ensure!(
        std::fs::symlink_metadata(&c.state_dir)?.uid() == 0,
        "privileged state directory must be owned by root"
    );
    std::fs::set_permissions(&c.state_dir, std::fs::Permissions::from_mode(0o700))?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(c.state_dir.join("agent.lock"))?;
    lock.try_lock_exclusive()
        .context("response broker already running")?;
    let parent = c.socket.parent().context("socket parent")?;
    let meta = std::fs::symlink_metadata(parent)?;
    ensure!(
        meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "socket directory must be root-owned and not writable by group/others"
    );
    if let Ok(meta) = std::fs::symlink_metadata(&c.socket) {
        ensure!(
            meta.file_type().is_socket() && meta.uid() == 0,
            "refusing to replace an unexpected socket path"
        );
        std::fs::remove_file(&c.socket)?;
    }
    let listener = UnixListener::bind(&c.socket)?;
    std::fs::set_permissions(&c.socket, std::fs::Permissions::from_mode(0o660))?;
    let ledger = Ledger::open(&c.state_dir.join("actions.db"))?;
    tracing::info!("local response broker ready; no public listener");
    loop {
        let (mut stream, _) = tokio::select! {result=listener.accept()=>result?,_=crate::daemon::shutdown_signal()=>break};
        if Some(stream.peer_cred()?.uid()) != c.allowed_uid {
            continue;
        }
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            let mut bytes = vec![];
            BufReader::new(&mut stream)
                .take(65537)
                .read_until(b'\n', &mut bytes)
                .await?;
            ensure!(bytes.len() <= 65536, "broker request too large");
            let req: Request = serde_json::from_slice(&bytes)?;
            handle(req, &c, &host, &ledger).await
        })
        .await;
        let value = match result {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => json!({"error":e.to_string()}),
            Err(_) => json!({"error":"operation timed out; inspect audit before retry"}),
        };
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(&bytes)).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ResponseConfig {
        ResponseConfig {
            protected_networks: vec!["192.0.2.0/24".parse().unwrap()],
            ..Default::default()
        }
    }
    fn target() -> Session {
        Session {
            session_id: "42".into(),
            user: "ubuntu".into(),
            uid: 1000,
            source_ip: "203.0.113.3".parse().unwrap(),
            service: "sshd".into(),
            class: "user".into(),
            remote: true,
            leader: 1234,
            leader_start_ticks: 777,
            boot_id: "boot-a".into(),
        }
    }
    fn proposal() -> Proposal {
        Proposal {
            proposal_id: "unique".into(),
            host: "test".into(),
            action: Action::Quarantine,
            target: target(),
            duration_seconds: 900,
            ssh_ports: vec![22],
            expires_at: 1000,
            dry_run: false,
            reason: "test".into(),
        }
    }
    #[test]
    fn protected_and_non_ssh_sessions_are_refused() {
        let c = config();
        let mut s = target();
        assert!(validate_target(&s, &c).is_ok());
        s.source_ip = "::ffff:192.0.2.10".parse().unwrap();
        assert!(validate_target(&s, &c).is_err());
        s = target();
        s.uid = 0;
        assert!(validate_target(&s, &c).is_err());
        s = target();
        s.service = "login".into();
        assert!(validate_target(&s, &c).is_err());
        s = target();
        s.session_id = "--all".into();
        assert!(validate_target(&s, &c).is_err());
    }
    #[test]
    fn immutable_expiring_identity_bound_proposals() {
        let c = config();
        let p = proposal();
        assert!(validate_execution(&p, &p, &target(), &c, 999).is_ok());
        assert!(validate_execution(&p, &p, &target(), &c, 1000).is_err());
        let mut changed = p.clone();
        changed.duration_seconds = 3600;
        assert!(validate_execution(&changed, &p, &target(), &c, 900).is_err());
        let mut live = target();
        live.leader_start_ticks += 1;
        assert!(validate_execution(&p, &p, &live, &c, 900).is_err());
        live = target();
        live.boot_id = "boot-b".into();
        assert!(validate_execution(&p, &p, &live, &c, 900).is_err());
        let mut c = c;
        c.protected_networks.push("203.0.113.0/24".parse().unwrap());
        assert!(validate_execution(&p, &p, &target(), &c, 900).is_err());
    }
    #[test]
    fn ledger_is_single_use_and_persists_uncertain_execution() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("actions.db");
        let p = proposal();
        {
            let db = Ledger::open(&path)?;
            db.put(&p)?;
            db.claim(&p.proposal_id)?;
            assert!(db.claim(&p.proposal_id).is_err());
        }
        let db = Ledger::open(&path)?;
        assert_eq!(db.get::<Proposal>(&p.proposal_id)?.1, "executing");
        db.finish(&p.proposal_id, &json!({"ok":true}))?;
        assert_eq!(
            db.get::<Proposal>(&p.proposal_id)?.2,
            Some(json!({"ok":true}))
        );
        Ok(())
    }
    #[test]
    fn firewall_only_targets_its_own_ssh_table() {
        let script = firewall_setup(&config());
        assert!(script.contains("tcp dport { 22 }"));
        assert!(script.contains("flags timeout"));
        assert!(!script.contains("flush"));
        assert!(verify_firewall(&json!({"nftables":[]}), &config()).is_err());
    }

    /// Run only inside `sudo unshare --net`: no production network namespace.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root in a disposable isolated network namespace"]
    async fn nft_kernel_schema_and_expiry() -> Result<()> {
        let own = std::fs::read_link("/proc/self/ns/net")?;
        let init = std::fs::read_link("/proc/1/ns/net")?;
        ensure!(own != init, "refusing nft test in PID 1 network namespace");
        ensure!(
            std::env::var("HOST_SENTINEL_ISOLATED_NFT_TEST").as_deref() == Ok("yes"),
            "explicit test opt-in required"
        );
        let c = config();
        command("/usr/sbin/nft", &["-f", "-"], Some(&firewall_setup(&c))).await?;
        let raw = command(
            "/usr/sbin/nft",
            &["-j", "list", "table", "inet", TABLE],
            None,
        )
        .await?;
        verify_firewall(&serde_json::from_str(&raw)?, &c)
            .with_context(|| format!("kernel firewall schema: {raw}"))?;
        let rule = format!("add element inet {TABLE} ssh4 {{ 203.0.113.99 timeout 1s }}\n");
        command("/usr/sbin/nft", &["-f", "-"], Some(&rule)).await?;
        let before = command(
            "/usr/sbin/nft",
            &["-j", "list", "set", "inet", TABLE, "ssh4"],
            None,
        )
        .await?;
        ensure!(before.contains("203.0.113.99"), "test element missing");
        tokio::time::sleep(Duration::from_secs(2)).await;
        let after = command(
            "/usr/sbin/nft",
            &["-j", "list", "set", "inet", TABLE, "ssh4"],
            None,
        )
        .await?;
        ensure!(
            !after.contains("203.0.113.99"),
            "kernel timeout did not expire"
        );
        Ok(())
    }
}
