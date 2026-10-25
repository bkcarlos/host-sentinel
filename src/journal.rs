use crate::config::SshConfig;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::LazyLock,
};

static SUCCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: .*?)?(?:$)").unwrap()
});
static FAILURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Failed \S+ for (?:invalid user )?\S+ from (\S+) port \d+").unwrap()
});
static INVALID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Invalid user .* from (\S+) port \d+").unwrap());
static FINGERPRINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"SHA256:[A-Za-z0-9+/=]+").unwrap());

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Login {
    pub user: String,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub method: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum AuthEvent {
    Login(Login),
    Failure(IpAddr),
    InvalidUser(IpAddr),
}

pub fn parse(message: &str) -> Option<AuthEvent> {
    if let Some(c) = SUCCESS.captures(message) {
        return Some(AuthEvent::Login(Login {
            user: c[2].into(),
            source_ip: c[3].parse().ok()?,
            source_port: c[4].parse().ok()?,
            method: c[1].into(),
            fingerprint: FINGERPRINT.find(message).map(|m| m.as_str().into()),
        }));
    }
    if let Some(c) = FAILURE.captures(message) {
        return Some(AuthEvent::Failure(c[1].parse().ok()?));
    }
    INVALID
        .captures(message)
        .and_then(|c| c[1].parse().ok())
        .map(AuthEvent::InvalidUser)
}

pub fn trusted(login: &Login, config: &SshConfig) -> bool {
    config.trusted.iter().any(|r| {
        r.user.as_ref().is_none_or(|u| u == &login.user)
            && (!r.networks.is_empty() || !r.fingerprints.is_empty())
            && (r.networks.is_empty() || r.networks.iter().any(|n| n.contains(&login.source_ip)))
            && (r.fingerprints.is_empty()
                || login
                    .fingerprint
                    .as_ref()
                    .is_some_and(|f| r.fingerprints.contains(f)))
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailureTracker {
    sources: HashMap<IpAddr, FailureWindow>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FailureWindow {
    times: VecDeque<u64>,
    last_alert: Option<u64>,
}
impl FailureTracker {
    pub fn record(&mut self, ip: IpAddr, time: u64, config: &SshConfig) -> Option<usize> {
        let horizon = config
            .failure_window_seconds
            .max(config.failure_cooldown_seconds);
        self.sources.retain(|_, v| {
            v.times
                .back()
                .is_some_and(|t| time.saturating_sub(*t) <= horizon)
                || v.last_alert
                    .is_some_and(|t| time.saturating_sub(t) <= horizon)
        });
        // Bound adversarial cardinality without permanently disabling new sources.
        if self.sources.len() >= 10000
            && !self.sources.contains_key(&ip)
            && let Some(oldest) = self
                .sources
                .iter()
                .min_by_key(|(_, v)| v.times.back().copied().unwrap_or(0))
                .map(|(ip, _)| *ip)
        {
            self.sources.remove(&oldest);
        }
        let state = self.sources.entry(ip).or_default();
        while state
            .times
            .front()
            .is_some_and(|t| time.saturating_sub(*t) > config.failure_window_seconds)
        {
            state.times.pop_front();
        }
        state.times.push_back(time);
        while state.times.len() > config.failure_count {
            state.times.pop_front();
        }
        if state.times.len() >= config.failure_count
            && state
                .last_alert
                .is_none_or(|last| time.saturating_sub(last) >= config.failure_cooldown_seconds)
        {
            state.last_alert = Some(time);
            Some(state.times.len())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TrustRule;
    #[test]
    fn parses_ipv6_key_and_requires_all_trust_fields() {
        let AuthEvent::Login(login) = parse(
            "Accepted publickey for ubuntu from 2001:db8::1 port 4242 ssh2: ED25519 SHA256:abc123",
        )
        .unwrap() else {
            panic!()
        };
        let mut c = SshConfig::default();
        assert!(!trusted(&login, &c));
        c.trusted.push(TrustRule {
            user: Some("ubuntu".into()),
            networks: vec!["2001:db8::/32".parse().unwrap()],
            fingerprints: vec!["SHA256:abc123".into()],
            ..Default::default()
        });
        assert!(trusted(&login, &c));
        c.trusted[0].fingerprints = vec!["SHA256:other".into()];
        assert!(!trusted(&login, &c));
        assert!(parse("text Accepted publickey for root from 192.0.2.1 port 22").is_none());
        assert!(matches!(
            parse("Failed password for invalid user test from 192.0.2.1 port 123 ssh2"),
            Some(AuthEvent::Failure(_))
        ));
        assert!(matches!(
            parse("Invalid user  from 192.0.2.1 port 123"),
            Some(AuthEvent::InvalidUser(_))
        ));
    }
    #[test]
    fn failure_window_persists_and_cools_down() {
        let c = SshConfig {
            failure_count: 3,
            failure_window_seconds: 20,
            failure_cooldown_seconds: 30,
            ..Default::default()
        };
        let mut tracker = FailureTracker::default();
        let ip = "192.0.2.1".parse().unwrap();
        assert_eq!(tracker.record(ip, 1, &c), None);
        assert_eq!(tracker.record(ip, 2, &c), None);
        assert_eq!(tracker.record(ip, 3, &c), Some(3));
        let mut restored: FailureTracker =
            serde_json::from_str(&serde_json::to_string(&tracker).unwrap()).unwrap();
        assert_eq!(restored.record(ip, 4, &c), None);
        assert_eq!(restored.record(ip, 40, &c), None);
        assert_eq!(restored.record(ip, 41, &c), None);
        assert_eq!(restored.record(ip, 42, &c), Some(3));
    }
}
