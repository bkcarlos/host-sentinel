//! Fixed process signals through pidfds; never use a numeric-PID kill fallback.
use crate::{config::ResponseConfig, response::Ledger};
use anyhow::{Context, Result, ensure};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, path::Path};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,
    pub uid: u32,
    pub effective_uid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
    pub cgroup: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSignal {
    Terminate,
    Kill,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareProcess {
    pub pid: u32,
    /// terminate = SIGTERM; kill = SIGKILL, cannot be handled for cleanup.
    pub signal: ProcessSignal,
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessProposal {
    pub proposal_id: String,
    pub host: String,
    pub target: ProcessIdentity,
    pub signal: ProcessSignal,
    pub expires_at: u64,
    pub dry_run: bool,
    pub reason: String,
}

pub fn identity(pid: u32) -> Result<ProcessIdentity> {
    ensure!(
        pid > 1 && pid <= i32::MAX as u32,
        "invalid or protected PID"
    );
    let dir = Path::new("/proc").join(pid.to_string());
    let before = fs::read_to_string(dir.join("stat"))?;
    let parse = |s: &str| -> Result<(String, u64)> {
        let (head, tail) = s.rsplit_once(')').context("invalid process stat")?;
        let name = head.split_once('(').context("missing process name")?.1;
        let start = tail
            .split_whitespace()
            .nth(19)
            .context("missing process start")?
            .parse()?;
        Ok((
            name.chars().filter(|c| !c.is_control()).take(80).collect(),
            start,
        ))
    };
    let (name, start_ticks) = parse(&before)?;
    let status = fs::read_to_string(dir.join("status"))?;
    let uids = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .context("missing process UID")?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(uids.len() == 4, "invalid process UIDs");
    // Refuse setuid transitions, including saved UID privileges.
    ensure!(
        uids.iter().all(|u| *u == uids[0]),
        "setuid process cannot be targeted"
    );
    let cgroup = fs::read_to_string(dir.join("cgroup"))?;
    ensure!(cgroup.len() <= 8192, "unexpected cgroup size");
    ensure!(
        parse(&fs::read_to_string(dir.join("stat"))?)? == (name.clone(), start_ticks),
        "process identity changed during inspection"
    );
    Ok(ProcessIdentity {
        pid,
        name,
        uid: uids[0],
        effective_uid: uids[1],
        start_ticks,
        boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        cgroup,
    })
}
pub fn validate_target(p: &ProcessIdentity, c: &ResponseConfig) -> Result<()> {
    ensure!(
        p.pid > 1 && p.pid != std::process::id() && p.start_ticks > 0 && !p.boot_id.is_empty(),
        "protected or incomplete process identity"
    );
    ensure!(
        p.uid >= 1000 && p.effective_uid == p.uid && c.process_allowed_uids.contains(&p.uid),
        "process UID is not an allowed ordinary user"
    );
    ensure!(Some(p.uid) != c.allowed_uid, "monitor account is protected");
    let protected = [
        "systemd",
        "sshd",
        "sshd-session",
        "sshd-auth",
        "host-sentinel",
        "dockerd",
        "containerd",
        "tailscaled",
        "sudo",
        "bash",
        "zsh",
        "sh",
        "fish",
        "dbus-daemon",
    ];
    ensure!(
        !protected.contains(&p.name.as_str()) && !c.protected_process_names.contains(&p.name),
        "critical process or management shell is protected"
    );
    ensure!(
        !p.cgroup.contains("host-sentinel") && !p.cgroup.contains("rakazo"),
        "monitoring or notification process is protected"
    );
    Ok(())
}
pub fn validate_execution(
    p: &ProcessProposal,
    stored: &ProcessProposal,
    live: &ProcessIdentity,
    c: &ResponseConfig,
    now: u64,
) -> Result<()> {
    ensure!(p == stored, "process proposal was modified");
    ensure!(
        now < p.expires_at,
        "proposal expired; request a new proposal and approval"
    );
    ensure!(
        &p.target == live,
        "process identity changed; no signal sent"
    );
    if !p.dry_run {
        validate_target(live, c)?;
    }
    Ok(())
}
pub(crate) fn prepare(
    input: PrepareProcess,
    c: &ResponseConfig,
    host: &str,
    ledger: &Ledger,
) -> Result<Value> {
    ensure!(
        !input.reason.trim().is_empty() && input.reason.len() <= 1000,
        "reason must be 1..1000 bytes"
    );
    let target = identity(input.pid)?;
    let refusal = validate_target(&target, c).err().map(|e| e.to_string());
    ensure!(
        input.dry_run || refusal.is_none(),
        "{}",
        refusal.as_deref().unwrap_or("target refused")
    );
    let p = ProcessProposal {
        proposal_id: uuid::Uuid::new_v4().to_string(),
        host: host.into(),
        target,
        signal: input.signal,
        expires_at: crate::now() + c.proposal_ttl_seconds,
        dry_run: input.dry_run,
        reason: input.reason,
    };
    ledger.put(&p)?;
    Ok(
        json!({"execute_arguments":{"proposal":p},"requires_human_approval":true,"dry_run_protection_notice":refusal,
        "effect":"Signal exactly one process. SIGKILL skips cleanup and may lose unsaved work. Children are not killed automatically; a supervisor may restart the process. No automatic escalation."}),
    )
}
pub fn inspect(pid: u32, c: &ResponseConfig) -> Result<Value> {
    let p = identity(pid)?;
    let refusal = validate_target(&p, c).err().map(|e| e.to_string());
    Ok(
        json!({"timestamp":crate::now(),"process":p,"eligible":refusal.is_none(),"protected_reason":refusal}),
    )
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: pidfd_open has scalar arguments, returns an owned descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("pidfd_open failed; refusing unsafe PID fallback");
    }
    // SAFETY: the successful syscall returned a new, uniquely owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}
#[cfg(target_os = "linux")]
fn send_signal(fd: &std::os::fd::OwnedFd, signal: ProcessSignal) -> Result<()> {
    use std::os::fd::AsRawFd;
    let sig = match signal {
        ProcessSignal::Terminate => libc::SIGTERM,
        ProcessSignal::Kill => libc::SIGKILL,
    };
    // SAFETY: descriptor is live, sig is fixed, null siginfo and flags=0 are supported.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("pidfd_send_signal failed");
    }
    Ok(())
}
pub(crate) fn execute(p: ProcessProposal, c: &ResponseConfig, ledger: &Ledger) -> Result<Value> {
    let (stored, status, result) = ledger.get::<ProcessProposal>(&p.proposal_id)?;
    ensure!(p == stored, "process proposal was modified");
    if status == "finished" {
        return Ok(json!({"replayed":true,"result":result}));
    }
    ensure!(
        status == "prepared",
        "proposal already started; inspect audit before any new action"
    );
    // Pin the process before rechecking /proc so PID reuse cannot redirect a signal.
    #[cfg(target_os = "linux")]
    let fd = open_pidfd(p.target.pid)?;
    let live = identity(p.target.pid)?;
    validate_execution(&p, &stored, &live, c, crate::now())?;
    ledger.claim(&p.proposal_id)?;
    let mut result = json!({"proposal_id":p.proposal_id,"timestamp":crate::now(),"dry_run":p.dry_run,"signal_sent":false});
    if p.dry_run {
        result["ok"] = json!(true);
        result["message"] = json!("Dry run only; no process received a signal.");
    } else {
        #[cfg(target_os = "linux")]
        let sent = send_signal(&fd, p.signal);
        #[cfg(not(target_os = "linux"))]
        let sent: Result<()> = Err(anyhow::anyhow!("Linux pidfds required"));
        result["ok"] = json!(sent.is_ok());
        result["signal_sent"] = json!(sent.is_ok());
        result["signal"] = json!(p.signal);
        result["message"] = json!(
            "Signal delivery does not prove process exit; recheck identity/status. No children or restart policy were modified."
        );
        if let Err(e) = sent {
            result["error"] = json!(e.to_string());
        }
    }
    ledger.finish(&p.proposal_id, &result)?;
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_protection_and_approval_binding() {
        let c = ResponseConfig {
            process_allowed_uids: vec![1000],
            ..Default::default()
        };
        let target = ProcessIdentity {
            pid: 424242,
            name: "worker".into(),
            uid: 1000,
            effective_uid: 1000,
            start_ticks: 123,
            boot_id: "boot".into(),
            cgroup: "0::/user.slice/app".into(),
        };
        let p = ProcessProposal {
            proposal_id: "test".into(),
            host: "host".into(),
            target: target.clone(),
            signal: ProcessSignal::Terminate,
            expires_at: 1000,
            dry_run: false,
            reason: "test".into(),
        };
        assert!(validate_execution(&p, &p, &target, &c, 999).is_ok());
        assert!(validate_execution(&p, &p, &target, &c, 1000).is_err());
        let mut changed = p.clone();
        changed.signal = ProcessSignal::Kill;
        assert!(validate_execution(&changed, &p, &target, &c, 999).is_err());
        let mut live = target.clone();
        live.start_ticks += 1;
        assert!(validate_execution(&p, &p, &live, &c, 999).is_err());
        live = target.clone();
        live.uid = 0;
        assert!(validate_target(&live, &c).is_err());
        live = target;
        live.name = "sshd".into();
        assert!(validate_target(&live, &c).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_signals_only_disposable_child_and_rejects_dead_handle() -> Result<()> {
        use std::io::BufRead;
        use std::process::Stdio;
        // Wait for the child to finish exec/startup before inspecting /proc.
        // A newly spawned sleep can still change its comm during identity().
        // This shell stays in its read builtin until the test signals it.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "printf 'ready\\n'; read -r sentinel_test_input"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let result = (|| -> Result<()> {
            let mut ready = String::new();
            std::io::BufReader::new(child.stdout.take().context("child stdout")?)
                .read_line(&mut ready)?;
            ensure!(ready == "ready\n", "child did not complete startup");
            let fd = open_pidfd(child.id())?;
            let before = identity(child.id())?;
            ensure!(before.pid == child.id(), "wrong child identity");
            send_signal(&fd, ProcessSignal::Kill)?;
            let status = child.wait()?;
            use std::os::unix::process::ExitStatusExt;
            ensure!(
                status.signal() == Some(libc::SIGKILL),
                "child did not receive SIGKILL"
            );
            ensure!(
                send_signal(&fd, ProcessSignal::Kill).is_err(),
                "dead pidfd unexpectedly accepted signal"
            );
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        result
    }
}
