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

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let config: Self =
            toml::from_str(&std::fs::read_to_string(path).context("read configuration")?)
                .context("parse configuration")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
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
