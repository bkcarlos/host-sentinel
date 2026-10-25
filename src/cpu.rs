use crate::config::CpuConfig;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuTicks {
    pub total: u64,
    pub idle: u64,
}
impl CpuTicks {
    pub fn parse(text: &str) -> Result<Self> {
        let line = text.lines().next().context("empty /proc/stat")?;
        let mut fields = line.split_whitespace();
        ensure!(fields.next() == Some("cpu"), "missing aggregate CPU line");
        let ticks: Vec<u64> = fields
            .take(8)
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(ticks.len() >= 4, "incomplete CPU counters");
        // guest and guest_nice are already included in user and nice.
        Ok(Self {
            total: ticks.iter().sum(),
            idle: ticks[3] + ticks.get(4).copied().unwrap_or(0),
        })
    }
    pub fn usage_since(self, previous: Self) -> Option<f64> {
        let total = self.total.checked_sub(previous.total)?;
        let idle = self.idle.checked_sub(previous.idle)?;
        if total == 0 || idle > total {
            return None;
        }
        Some(100.0 * (total - idle) as f64 / total as f64)
    }
}

#[derive(Debug, Clone)]
struct ProcessTicks {
    pid: u32,
    name: String,
    ticks: u64,
    start: u64,
}
fn parse_process_stat(text: &str) -> Option<ProcessTicks> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let pid = text[..open].trim().parse().ok()?;
    let fields: Vec<&str> = text[close + 1..].split_whitespace().collect();
    Some(ProcessTicks {
        pid,
        name: text[open + 1..close]
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect(),
        ticks: fields
            .get(11)?
            .parse::<u64>()
            .ok()?
            .saturating_add(fields.get(12)?.parse().ok()?),
        start: fields.get(19)?.parse().ok()?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopProcess {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub timestamp: u64,
    pub cpu_percent: f64,
    pub top_processes: Vec<TopProcess>,
}

#[derive(Default)]
pub struct Sampler {
    previous: Option<CpuTicks>,
    processes: HashMap<u32, ProcessTicks>,
}
impl Sampler {
    pub fn sample(&mut self, root: &Path, timestamp: u64) -> Result<Option<Sample>> {
        let ticks = CpuTicks::parse(
            &fs::read_to_string(root.join("stat")).context("read Linux /proc/stat")?,
        )?;
        let mut current = HashMap::new();
        for entry in fs::read_dir(root)? {
            let Ok(entry) = entry else { continue };
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            if let Ok(text) = fs::read_to_string(entry.path().join("stat"))
                && let Some(p) = parse_process_stat(&text)
            {
                current.insert(p.pid, p);
            }
        }
        let result = self.previous.and_then(|prev| {
            ticks.usage_since(prev).map(|usage| {
                let delta = ticks.total.saturating_sub(prev.total) as f64;
                let mut top: Vec<TopProcess> = current
                    .values()
                    .filter_map(|p| {
                        let before = self.processes.get(&p.pid)?;
                        if before.start != p.start {
                            return None;
                        }
                        let cpu = 100. * p.ticks.checked_sub(before.ticks)? as f64 / delta;
                        Some(TopProcess {
                            pid: p.pid,
                            name: p.name.clone(),
                            cpu_percent: cpu.clamp(0., 100.),
                        })
                    })
                    .collect();
                top.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent));
                top.truncate(5);
                Sample {
                    timestamp,
                    cpu_percent: usage,
                    top_processes: top,
                }
            })
        });
        self.previous = Some(ticks);
        self.processes = current;
        Ok(result)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Detector {
    history: VecDeque<(u64, f64)>,
    high_since: Option<u64>,
    spike_since: Option<u64>,
    high_active: bool,
    spike_active: bool,
    last_spike: Option<u64>,
    last_sample: Option<u64>,
}
#[derive(Debug, PartialEq)]
pub struct CpuAlert {
    pub kind: &'static str,
    pub baseline: Option<f64>,
}
impl Detector {
    pub fn update(
        &mut self,
        now: u64,
        usage: f64,
        config: &CpuConfig,
        interval: u64,
    ) -> Vec<CpuAlert> {
        if !usage.is_finite() || !(0.0..=100.).contains(&usage) {
            return vec![];
        }
        if self
            .last_sample
            .is_some_and(|last| now < last || now.saturating_sub(last) > interval * 3)
        {
            self.history.clear();
            self.high_since = None;
            self.spike_since = None;
        }
        self.last_sample = Some(now);
        while self
            .history
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) > config.baseline_seconds + interval)
        {
            self.history.pop_front();
        }
        let baseline = if self
            .history
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) >= config.baseline_seconds)
        {
            Some(self.history.iter().map(|(_, v)| v).sum::<f64>() / self.history.len() as f64)
        } else {
            None
        };
        let mut alerts = vec![];
        if usage >= config.high_percent {
            let since = self.high_since.get_or_insert(now);
            if !self.high_active && now.saturating_sub(*since) >= config.sustained_seconds {
                self.high_active = true;
                alerts.push(CpuAlert {
                    kind: "cpu_high",
                    baseline,
                });
            }
        } else {
            self.high_since = None;
        }
        if self.high_active && usage <= config.recovery_percent {
            self.high_active = false;
            alerts.push(CpuAlert {
                kind: "cpu_recovered",
                baseline,
            });
        }
        let spike = baseline.is_some_and(|base| {
            usage >= config.spike_min_percent && usage - base >= config.spike_delta_percent
        });
        if spike {
            let since = self.spike_since.get_or_insert(now);
            if !self.spike_active
                && now.saturating_sub(*since) >= config.spike_seconds
                && self
                    .last_spike
                    .is_none_or(|t| now.saturating_sub(t) >= config.cooldown_seconds)
            {
                self.spike_active = true;
                self.last_spike = Some(now);
                alerts.push(CpuAlert {
                    kind: "cpu_spike",
                    baseline,
                });
            }
        } else {
            self.spike_since = None;
        }
        if self.spike_active && usage < config.spike_min_percent {
            self.spike_active = false;
            alerts.push(CpuAlert {
                kind: "cpu_spike_recovered",
                baseline,
            });
        }
        self.history.push_back((now, usage));
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counters_exclude_guest_and_handle_reset() {
        let a = CpuTicks::parse("cpu 10 0 10 80 0 0 0 0 5 0").unwrap();
        let b = CpuTicks::parse("cpu 40 0 30 130 0 0 0 0 9 0").unwrap();
        assert_eq!(a.total, 100);
        assert_eq!(b.usage_since(a), Some(50.));
        assert_eq!(a.usage_since(b), None);
    }
    #[test]
    fn sustained_hysteresis_and_sampling_gaps() {
        let c = CpuConfig {
            sustained_seconds: 10,
            ..Default::default()
        };
        let mut d = Detector::default();
        assert!(d.update(0, 90., &c, 5).is_empty());
        assert!(d.update(5, 90., &c, 5).is_empty());
        assert_eq!(d.update(10, 90., &c, 5)[0].kind, "cpu_high");
        assert!(d.update(15, 80., &c, 5).is_empty());
        assert_eq!(d.update(20, 40., &c, 5)[0].kind, "cpu_recovered");
        d.update(25, 90., &c, 5);
        assert!(d.update(100, 90., &c, 5).is_empty());
    }
    #[test]
    fn spike_requires_baseline_and_duration() {
        let c = CpuConfig {
            baseline_seconds: 100,
            spike_seconds: 10,
            ..Default::default()
        };
        let mut d = Detector::default();
        for t in (0..100).step_by(5) {
            assert!(d.update(t, 10., &c, 5).is_empty());
        }
        assert!(d.update(100, 80., &c, 5).is_empty());
        assert!(d.update(105, 80., &c, 5).is_empty());
        assert_eq!(d.update(110, 80., &c, 5)[0].kind, "cpu_spike");
        assert_eq!(d.update(115, 20., &c, 5)[0].kind, "cpu_spike_recovered");
    }
    #[test]
    fn process_names_can_contain_parentheses() {
        let text = "42 (a (worker)) S 1 1 1 0 0 0 0 0 0 0 20 10 0 0 0 0 1 0 999 0";
        let p = parse_process_stat(text).unwrap();
        assert_eq!(p.name, "a (worker)");
        assert_eq!(p.ticks, 30);
        assert_eq!(p.start, 999);
    }
}
