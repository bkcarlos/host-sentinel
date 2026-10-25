use anyhow::Result;
use host_sentinel::{config::Config, daemon::ingest, journal::FailureTracker, store::Store};
use serde_json::json;

#[test]
fn ssh_pipeline_deduplicates_and_ignores_unprivileged_spoofs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = Store::open(&dir.path().join("state.db"))?;
    let config = Config::default();
    let mut tracker = FailureTracker::default();
    let mut record = json!({"__CURSOR":"one","__REALTIME_TIMESTAMP":"100000000", "_COMM":"sshd-session","_UID":"0",
        "MESSAGE":"Accepted publickey for ubuntu from 192.0.2.1 port 12345 ssh2: ED25519 SHA256:abc123"});
    ingest(&db, &config, &mut tracker, &record)?;
    ingest(&db, &config, &mut tracker, &record)?;
    assert_eq!(db.queue_size()?, 1);
    assert_eq!(db.recent(false, true, 20)?.len(), 1);
    record["__CURSOR"] = json!("two");
    record["_UID"] = json!("1000");
    ingest(&db, &config, &mut tracker, &record)?;
    assert_eq!(db.queue_size()?, 1);
    assert_eq!(db.get("journal_cursor")?, Some(json!("two")));
    Ok(())
}

#[test]
fn valid_trusted_login_is_recorded_without_notification() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = Store::open(&dir.path().join("state.db"))?;
    let mut config = Config::default();
    config.ssh.trusted.push(host_sentinel::config::TrustRule {
        user: Some("ubuntu".into()),
        networks: vec!["192.0.2.0/24".parse()?],
        fingerprints: vec!["SHA256:abc123".into()],
    });
    let mut tracker = FailureTracker::default();
    ingest(
        &db,
        &config,
        &mut tracker,
        &json!({"__CURSOR":"one","_COMM":"sshd","_UID":"0","MESSAGE":"Accepted publickey for ubuntu from 192.0.2.1 port 12345 ssh2: RSA SHA256:abc123"}),
    )?;
    assert_eq!(db.queue_size()?, 0);
    assert_eq!(
        db.recent(false, true, 20)?[0]["event"]["event"],
        "ssh_login"
    );
    Ok(())
}
