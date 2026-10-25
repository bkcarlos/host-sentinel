//! Host memory snapshots; RSS includes shared pages and must not be summed.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::HashMap, fs, path::Path};

fn kb_fields(text: &str) -> HashMap<&str, u64> {
    text.lines()
        .filter_map(|line| {
            let (key, rest) = line.split_once(':')?;
            let mut parts = rest.split_whitespace();
            let value = parts.next()?.parse::<u64>().ok()?;
            (parts.next() == Some("kB")).then(|| (key, value.saturating_mul(1024)))
        })
        .collect()
}
pub fn parse_meminfo(text: &str) -> Result<Value> {
    let m = kb_fields(text);
    let total = *m.get("MemTotal").context("missing MemTotal")?;
    let available = *m.get("MemAvailable").context("missing MemAvailable")?;
    ensure!(total > 0 && available <= total, "invalid memory counters");
    let swap_total = *m.get("SwapTotal").context("missing SwapTotal")?;
    let swap_free = *m.get("SwapFree").context("missing SwapFree")?;
    ensure!(swap_free <= swap_total, "invalid swap counters");
    Ok(json!({"total_bytes":total,"available_bytes":available,
        "used_bytes":total-available,"used_percent":100.0*(total-available) as f64/total as f64,
        "free_bytes":m.get("MemFree"),"cached_bytes":m.get("Cached"),
        "buffers_bytes":m.get("Buffers"),"reclaimable_slab_bytes":m.get("SReclaimable"),
        "swap_total_bytes":swap_total,"swap_used_bytes":swap_total-swap_free,
        "swap_used_percent":if swap_total==0 {None} else {Some(100.0*(swap_total-swap_free) as f64/swap_total as f64)},
        "usage_definition":"MemTotal - MemAvailable; reclaimable cache is available, not automatically a leak"}))
}
fn pressure(text: &str) -> Option<Value> {
    let mut out = serde_json::Map::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let kind = parts.next()?;
        if !["some", "full"].contains(&kind) {
            continue;
        }
        let mut fields = serde_json::Map::new();
        for field in parts {
            let (k, v) = field.split_once('=')?;
            if k == "total" {
                fields.insert(
                    "total_stall_microseconds".into(),
                    json!(v.parse::<u64>().ok()?),
                );
            } else if ["avg10", "avg60", "avg300"].contains(&k) {
                let n = v.parse::<f64>().ok()?;
                if !n.is_finite() || !(0.0..=100.0).contains(&n) {
                    return None;
                }
                fields.insert(k.into(), json!(n));
            }
        }
        out.insert(kind.into(), Value::Object(fields));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}
pub fn sample(root: &Path, timestamp: u64) -> Result<Value> {
    let mut out = parse_meminfo(&fs::read_to_string(root.join("meminfo"))?)?;
    out["timestamp"] = json!(timestamp);
    out["pressure"] = fs::read_to_string(root.join("pressure/memory"))
        .ok()
        .and_then(|s| pressure(&s))
        .unwrap_or(Value::Null);
    out["oom_kill_total_since_boot"] = fs::read_to_string(root.join("vmstat"))
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("oom_kill ")
                    .and_then(|v| v.trim().parse::<u64>().ok())
            })
        })
        .map_or(Value::Null, |n| json!(n));
    let mut processes = vec![];
    let mut unavailable = 0u64;
    for entry in fs::read_dir(root)?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            unavailable += 1;
            continue;
        };
        let m = kb_fields(&status);
        let Some(rss) = m.get("VmRSS") else { continue };
        let name = status
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .unwrap_or("")
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect::<String>();
        let uid = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok());
        processes.push(json!({"pid":pid,"name":name,"uid":uid,"rss_bytes":rss,"swap_bytes":m.get("VmSwap"),"rss_percent":100.0*(*rss as f64)/out["total_bytes"].as_u64().unwrap() as f64}));
    }
    processes.sort_by_key(|p| std::cmp::Reverse(p["rss_bytes"].as_u64().unwrap_or(0)));
    processes.truncate(20);
    out["top_processes"] = json!(processes);
    out["unavailable_processes"] = json!(unavailable);
    out["process_memory_note"] = json!(
        "RSS is approximate and includes shared pages; do not sum it. Processes can exit during sampling. No command arguments or environments are read."
    );
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn available_memory_and_no_swap_are_not_false_pressure() {
        let m=parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 800 kB\nMemFree: 10 kB\nCached: 790 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB").unwrap();
        assert_eq!(m["used_percent"], 20.0);
        assert_eq!(m["available_bytes"], 819200);
        assert!(m["swap_used_percent"].is_null());
        assert!(parse_meminfo("MemTotal: 100 kB\nMemAvailable: 101 kB").is_err());
        let p=pressure("some avg10=1.25 avg60=0.50 avg300=0.10 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0").unwrap();
        assert_eq!(p["some"]["avg10"], 1.25);
        assert_eq!(p["some"]["total_stall_microseconds"], 12345);
    }
}
