#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use host_sentinel::{config::Config, store::Store};
use std::{os::unix::fs::PermissionsExt, time::Duration};

/// Exercise the executable, journal cursor, real Linux /proc sampler and graceful shutdown.
/// SSH and logind data are fixtures; no SSH session or external bot is touched.
#[tokio::test]
async fn daemon_collects_and_stops_cleanly() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin)?;
    let journal = bin.join("journalctl");
    std::fs::write(
        &journal,
        r##"#!/bin/sh
printf '%s\n' '{"__CURSOR":"fixture-1","__REALTIME_TIMESTAMP":"100000000","_COMM":"sshd-session","_UID":"0","MESSAGE":"Accepted publickey for test from 192.0.2.10 port 4321 ssh2: ED25519 SHA256:fixture"}'
exec sleep 60
"##,
    )?;
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o755))?;
    let loginctl = bin.join("loginctl");
    std::fs::write(
        &loginctl,
        "#!/bin/sh\nprintf '%s\\n' '[{\"session\":\"fixture\",\"user\":\"test\"}]'\n",
    )?;
    std::fs::set_permissions(&loginctl, std::fs::Permissions::from_mode(0o755))?;
    let config = Config {
        state_dir: dir.path().join("state"),
        sample_seconds: 1,
        ..Default::default()
    };
    let config_file = dir.path().join("config.toml");
    std::fs::write(&config_file, toml::to_string(&config)?)?;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_host-sentinel"))
        .args(["--config", config_file.to_str().unwrap(), "run"])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .kill_on_drop(true)
        .spawn()?;
    let wait = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(status) = child.try_wait()? {
                anyhow::bail!("daemon stopped early: {status}");
            }
            if config.state_dir.join("sentinel.db").exists() {
                let db = Store::open(&config.state_dir.join("sentinel.db"))?;
                if db.get("sample")?.is_some()
                    && db.get("sessions")?.is_some()
                    && db.queue_size()? == 1
                {
                    assert_eq!(
                        db.get("journal_cursor")?,
                        Some(serde_json::json!("fixture-1"))
                    );
                    assert_eq!(
                        db.recent(false, true, 10)?[0]["event"]["event"],
                        "ssh_unknown_login"
                    );
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::Ok(())
    })
    .await
    .context("daemon did not collect within 15 seconds")?;
    wait?;
    let pid = child.id().context("child pid")?;
    let status = tokio::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .await?;
    assert!(status.success());
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
    assert!(
        status.success(),
        "daemon failed to shut down cleanly: {status}"
    );
    Ok(())
}
