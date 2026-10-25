use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub host_label: String,
    pub sample_seconds: u64,
    pub retention_days: u64,
    pub cpu: CpuConfig,
    pub ssh: SshConfig,
    pub webhook: WebhookConfig,
    pub mcp: McpConfig,
    pub response: ResponseConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: "state".into(),
            host_label: "linux-host".into(),
            sample_seconds: 5,
            retention_days: 30,
            cpu: CpuConfig::default(),
            ssh: SshConfig::default(),
            webhook: WebhookConfig::default(),
            mcp: McpConfig::default(),
            response: ResponseConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CpuConfig {
    pub high_percent: f64,
    pub recovery_percent: f64,
    pub sustained_seconds: u64,
    pub baseline_seconds: u64,
    pub spike_delta_percent: f64,
    pub spike_min_percent: f64,
    pub spike_seconds: u64,
    pub cooldown_seconds: u64,
}
impl Default for CpuConfig {
    fn default() -> Self {
        Self {
            high_percent: 85.,
            recovery_percent: 65.,
            sustained_seconds: 180,
            baseline_seconds: 300,
            spike_delta_percent: 40.,
            spike_min_percent: 70.,
            spike_seconds: 30,
            cooldown_seconds: 900,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustRule {
    pub user: Option<String>,
    pub networks: Vec<IpNet>,
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshConfig {
    pub units: Vec<String>,
    pub trusted: Vec<TrustRule>,
    pub failure_count: usize,
    pub failure_window_seconds: u64,
    pub failure_cooldown_seconds: u64,
}
impl Default for SshConfig {
    fn default() -> Self {
        Self {
            units: vec!["ssh.service".into(), "sshd.service".into()],
            trusted: vec![],
            failure_count: 10,
            failure_window_seconds: 300,
            failure_cooldown_seconds: 900,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub token_env: String,
    pub timeout_seconds: u64,
}
impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            token_env: "RAKAZO_WEBHOOK_TOKEN".into(),
            timeout_seconds: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub token_env: String,
    pub allowed_hosts: Vec<String>,
}
impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:8787".parse().unwrap(),
            token_env: "SENTINEL_MCP_TOKEN".into(),
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "::1".into()],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseConfig {
    pub enabled: bool,
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    pub allowed_uid: Option<u32>,
    pub listen: SocketAddr,
    pub token_env: String,
    pub allowed_hosts: Vec<String>,
    pub protected_networks: Vec<IpNet>,
    pub protected_users: Vec<String>,
    pub process_allowed_uids: Vec<u32>,
    pub protected_process_names: Vec<String>,
    pub ssh_ports: Vec<u16>,
    pub max_quarantine_seconds: u64,
    pub proposal_ttl_seconds: u64,
}
impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: "/run/host-sentinel-response/control.sock".into(),
            state_dir: "/var/lib/host-sentinel-response".into(),
            allowed_uid: None,
            listen: "127.0.0.1:8788".parse().unwrap(),
            token_env: "SENTINEL_RESPONSE_TOKEN".into(),
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "::1".into()],
            protected_networks: vec![],
            protected_users: vec!["root".into(), "host-sentinel".into()],
            process_allowed_uids: vec![],
            protected_process_names: vec![],
            ssh_ports: vec![22],
            max_quarantine_seconds: 3600,
            proposal_ttl_seconds: 300,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let config: Self =
            toml::from_str(&std::fs::read_to_string(path).context("read configuration")?)
                .context("parse configuration")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.response.enabled {
            let r = &self.response;
            ensure!(
                r.allowed_uid.is_some_and(|u| u > 0),
                "response.allowed_uid must identify the unprivileged monitor user"
            );
            ensure!(
                !r.protected_networks.is_empty(),
                "response requires explicit protected management networks"
            );
            ensure!(
                !r.allowed_hosts.is_empty(),
                "response.allowed_hosts cannot be empty"
            );
            ensure!(
                !r.ssh_ports.is_empty()
                    && r.ssh_ports.len() <= 8
                    && r.ssh_ports.iter().all(|p| *p > 0),
                "invalid response SSH ports"
            );
            ensure!(
                r.ssh_ports.windows(2).all(|w| w[0] < w[1]),
                "SSH ports must be sorted and unique"
            );
            ensure!(
                r.process_allowed_uids
                    .iter()
                    .all(|uid| *uid >= 1000 && Some(*uid) != r.allowed_uid),
                "process action UIDs must be ordinary users, excluding the monitor"
            );
            ensure!(
                (60..=3600).contains(&r.max_quarantine_seconds),
                "quarantine maximum must be 60..3600 seconds"
            );
            ensure!(
                (30..=600).contains(&r.proposal_ttl_seconds),
                "proposal TTL must be 30..600 seconds"
            );
            ensure!(
                r.socket.is_absolute() && r.state_dir.is_absolute(),
                "response paths must be absolute"
            );
            ensure!(
                r.state_dir != self.state_dir,
                "privileged action state must be separate from monitor state"
            );
            ensure!(
                r.token_env != self.mcp.token_env && r.token_env != self.webhook.token_env,
                "response token must be independent"
            );
            ensure!(
                r.listen != self.mcp.listen,
                "response and monitoring need separate listeners"
            );
        }
        ensure!(
            (1..=60).contains(&self.sample_seconds),
            "sample_seconds must be 1..60"
        );
        ensure!(
            (1..=3650).contains(&self.retention_days),
            "retention_days must be 1..3650"
        );
        ensure!(
            !self.host_label.is_empty() && self.host_label.len() <= 128,
            "host_label must be 1..128 bytes"
        );
        for n in [
            self.cpu.high_percent,
            self.cpu.recovery_percent,
            self.cpu.spike_delta_percent,
            self.cpu.spike_min_percent,
        ] {
            ensure!(
                n.is_finite() && (0.0..=100.0).contains(&n),
                "CPU percentages must be finite and within 0..100"
            );
        }
        ensure!(
            self.cpu.recovery_percent < self.cpu.high_percent,
            "CPU recovery must be below high threshold"
        );
        for n in [
            self.cpu.sustained_seconds,
            self.cpu.baseline_seconds,
            self.cpu.spike_seconds,
            self.cpu.cooldown_seconds,
        ] {
            ensure!(
                (self.sample_seconds..=86400).contains(&n),
                "CPU durations must be sample_seconds..86400"
            );
        }
        ensure!(
            self.ssh.failure_count > 0 && self.ssh.failure_count <= 10000,
            "invalid failure_count"
        );
        ensure!(
            (1..=86400).contains(&self.ssh.failure_window_seconds),
            "invalid failure window"
        );
        ensure!(
            (1..=86400).contains(&self.ssh.failure_cooldown_seconds),
            "invalid failure cooldown"
        );
        ensure!(
            !self.ssh.units.is_empty(),
            "at least one journal unit is required"
        );
        ensure!(
            !self.mcp.allowed_hosts.is_empty(),
            "MCP allowed_hosts cannot be empty"
        );
        for rule in &self.ssh.trusted {
            ensure!(
                !rule.networks.is_empty() || !rule.fingerprints.is_empty(),
                "trust rules require a network or key fingerprint"
            );
            ensure!(
                rule.fingerprints
                    .iter()
                    .all(|f| f.starts_with("SHA256:") && f.len() > 7),
                "use SHA256 key fingerprints"
            );
        }
        if self.webhook.enabled {
            let url = reqwest::Url::parse(&self.webhook.url).context("invalid webhook URL")?;
            ensure!(
                url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "webhook URL must not contain credentials, query, or fragment"
            );
            let local = url.host_str().is_some_and(|s| {
                s == "localhost"
                    || s.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if url.scheme() != "https" && !(url.scheme() == "http" && local) {
                bail!("webhook requires HTTPS, except on loopback");
            }
            ensure!(
                (1..=60).contains(&self.webhook.timeout_seconds),
                "webhook timeout must be 1..60 seconds"
            );
        }
        Ok(())
    }
}

pub fn secret(name: &str) -> Result<String> {
    let value = std::env::var(name)
        .with_context(|| format!("missing secret environment variable {name}"))?;
    ensure!(
        value.len() >= 32 && !value.chars().any(char::is_whitespace),
        "{name} must contain at least 32 non-whitespace characters"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_config() {
        let mut c = Config::default();
        c.cpu.high_percent = f64::NAN;
        assert!(c.validate().is_err());
        c = Config::default();
        c.ssh.trusted.push(TrustRule::default());
        assert!(c.validate().is_err());
        c = Config::default();
        c.webhook.enabled = true;
        c.webhook.url = "http://example.com/hook".into();
        assert!(c.validate().is_err());
        c.webhook.url = "http://127.0.0.1:3100/api/v1/bots/example/webhook".into();
        assert!(c.validate().is_ok());
    }
}
