use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub timestamp: u64,
    pub host: String,
    pub event: String,
    pub details: Value,
}
impl Event {
    pub fn new(host: &str, timestamp: u64, kind: &str, details: Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            host: host.into(),
            event: kind.into(),
            details,
        }
    }
}

#[derive(Clone)]
pub struct Store(pub(crate) Arc<Mutex<Connection>>);

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, kind TEXT NOT NULL,
                payload TEXT NOT NULL, notify INTEGER NOT NULL, delivered INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
                last_error TEXT);
            CREATE INDEX IF NOT EXISTS event_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS outbox ON events(notify,delivered,next_attempt);
            CREATE TABLE IF NOT EXISTS auth_records (
                id TEXT PRIMARY KEY, timestamp_us INTEGER NOT NULL, kind TEXT NOT NULL,
                user TEXT, source_ip TEXT, boot_id TEXT, pid INTEGER, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS auth_time ON auth_records(timestamp_us,id);
            CREATE INDEX IF NOT EXISTS auth_source_time ON auth_records(source_ip,timestamp_us);
            CREATE INDEX IF NOT EXISTS auth_user_time ON auth_records(user,timestamp_us);
            CREATE INDEX IF NOT EXISTS auth_process ON auth_records(boot_id,pid,timestamp_us);")?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }
    pub fn get(&self, key: &str) -> Result<Option<Value>> {
        let conn = self.0.lock().unwrap();
        let text: Option<String> = conn
            .query_row("SELECT value FROM kv WHERE key=?", [key], |r| r.get(0))
            .optional()?;
        Ok(text.map(|s| serde_json::from_str(&s)).transpose()?)
    }
    pub fn set(&self, key: &str, value: &Value) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value.to_string()],
        )?;
        Ok(())
    }
    pub fn insert(&self, event: &Event, notify: bool) -> Result<()> {
        insert_event(&self.0.lock().unwrap(), event, notify)
    }
    pub fn cpu_commit(&self, sample: &Value, detector: &Value, events: &[Event]) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        for event in events {
            insert_event(&tx, event, true)?;
        }
        for (key, value) in [("sample", sample), ("cpu_detector", detector)] {
            tx.execute(
                "INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Event, detection state and journal cursor commit together, before delivery.
    pub fn journal_commit(
        &self,
        cursor: &str,
        event: Option<(&Event, bool)>,
        detection: &Value,
    ) -> Result<()> {
        self.journal_evidence_commit(cursor, event, detection, None)
    }
    pub fn journal_evidence_commit(
        &self,
        cursor: &str,
        event: Option<(&Event, bool)>,
        detection: &Value,
        evidence: Option<&crate::investigation::AuthRecord>,
    ) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some((event, notify)) = event {
            insert_event(&tx, event, notify)?;
        }
        if let Some(e) = evidence {
            crate::investigation::insert_record(&tx, e)?;
        }
        for (key, value) in [
            ("journal_cursor", serde_json::json!(cursor)),
            ("ssh_detection", detection.clone()),
        ] {
            tx.execute(
                "INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn recent(&self, alerts_only: bool, login_only: bool, limit: usize) -> Result<Vec<Value>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT payload,notify,delivered,attempts,last_error FROM events
            WHERE (?=0 OR notify=1) AND (?=0 OR kind IN ('ssh_login','ssh_unknown_login'))
            ORDER BY timestamp DESC,rowid DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![alerts_only, login_only, limit.clamp(1, 100)], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, u32>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut result = vec![];
        for row in rows {
            let (payload, notify, delivered, attempts, error) = row?;
            result.push(serde_json::json!({"event":serde_json::from_str::<Value>(&payload)?,
                "notification_requested":notify,"delivered":delivered,"attempts":attempts,"last_error":error}));
        }
        Ok(result)
    }
    pub fn pending(&self, now: u64) -> Result<Vec<(Event, u32)>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare("SELECT payload,attempts FROM events WHERE notify=1 AND delivered=0 AND next_attempt<=? ORDER BY timestamp LIMIT 20")?;
        let rows = stmt.query_map([now], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?)))?;
        let mut events = vec![];
        for row in rows {
            let (json, attempts) = row?;
            events.push((serde_json::from_str(&json)?, attempts));
        }
        Ok(events)
    }
    pub fn delivered(&self, id: &str) -> Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE events SET delivered=1,attempts=attempts+1,last_error=NULL WHERE id=?",
            [id],
        )?;
        Ok(())
    }
    pub fn retry(&self, id: &str, now: u64, attempts: u32, error: &str) -> Result<()> {
        let delay = (5_u64.saturating_mul(2_u64.pow(attempts.min(10)))).min(3600);
        self.0.lock().unwrap().execute(
            "UPDATE events SET attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?",
            params![now + delay, error, id],
        )?;
        Ok(())
    }
    pub fn queue_size(&self) -> Result<u64> {
        Ok(self.0.lock().unwrap().query_row(
            "SELECT count(*) FROM events WHERE notify=1 AND delivered=0",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn prune(&self, before: u64) -> Result<()> {
        self.0.lock().unwrap().execute(
            "DELETE FROM auth_records WHERE timestamp_us<?",
            [before.saturating_mul(1_000_000)],
        )?;
        self.set("auth_pruned_before", &serde_json::json!(before))?;
        // Never discard undelivered alerts merely because they are old.
        self.0.lock().unwrap().execute(
            "DELETE FROM events WHERE timestamp<? AND (notify=0 OR delivered=1)",
            [before],
        )?;
        Ok(())
    }
}
fn insert_event(conn: &Connection, event: &Event, notify: bool) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO events(id,timestamp,kind,payload,notify) VALUES (?,?,?,?,?)",
        params![
            event.id,
            event.timestamp,
            event.event,
            serde_json::to_string(event)?,
            notify
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_and_outbox_survive_reopen_and_deduplicate() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.db");
        let event = Event::new("test", 100, "ssh_unknown_login", Value::Null);
        {
            let db = Store::open(&path)?;
            db.journal_commit("cursor1", Some((&event, true)), &serde_json::json!({}))?;
            db.journal_commit("cursor1", Some((&event, true)), &serde_json::json!({}))?;
        }
        let db = Store::open(&path)?;
        assert_eq!(
            db.get("journal_cursor")?,
            Some(serde_json::json!("cursor1"))
        );
        assert_eq!(db.pending(100)?.len(), 1);
        db.retry(&event.id, 100, 0, "unavailable")?;
        assert!(db.pending(104)?.is_empty());
        assert_eq!(db.pending(105)?.len(), 1);
        db.prune(1000)?;
        assert_eq!(db.queue_size()?, 1);
        db.delivered(&event.id)?;
        db.prune(1000)?;
        assert!(db.recent(false, false, 10)?.is_empty());
        Ok(())
    }
}
