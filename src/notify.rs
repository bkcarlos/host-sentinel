use crate::{
    config::{WebhookConfig, secret},
    store::{Event, Store},
};
use anyhow::{Result, bail};
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use std::time::Duration;

pub struct Notifier {
    client: Client,
    url: String,
}
impl Notifier {
    pub fn new(config: &WebhookConfig) -> Result<Self> {
        Self::with_token(config, secret(&config.token_env)?)
    }
    pub fn with_token(config: &WebhookConfig, token: String) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}"))?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);
        Ok(Self {
            client: Client::builder()
                .default_headers(headers)
                .timeout(Duration::from_secs(config.timeout_seconds))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            url: config.url.clone(),
        })
    }
    pub async fn send(&self, event: &Event) -> Result<()> {
        // Stable identity lets Rakazo deduplicate retries, including lost responses.
        let response = self
            .client
            .post(&self.url)
            .header("Idempotency-Key", &event.id)
            .json(event)
            .send()
            .await
            .map_err(|_| {
                anyhow::anyhow!("webhook transport failure (timeout, TLS, or connection)")
            })?;
        if !response.status().is_success() {
            bail!("webhook HTTP {}", response.status().as_u16());
        }
        // A 2xx HTML proxy page must not silently acknowledge an alert.
        if response.content_length().is_some_and(|n| n > 65536) {
            bail!("webhook response too large");
        }
        let mut response = response;
        let mut bytes = vec![];
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("webhook response read failed"))?
        {
            if bytes.len() + chunk.len() > 65536 {
                bail!("webhook response too large");
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("webhook response is not JSON"))?;
        if body.get("ok") != Some(&serde_json::Value::Bool(true)) {
            bail!("webhook response did not acknowledge delivery");
        }
        Ok(())
    }
    pub async fn flush(&self, store: &Store, now: u64) -> Result<()> {
        for (event, attempts) in store.pending(now)? {
            match self.send(&event).await {
                Ok(()) => {
                    store.delivered(&event.id)?;
                    tracing::info!(event_id=%event.id,"alert delivered");
                }
                Err(error) => {
                    store.retry(&event.id, crate::now(), attempts, &error.to_string())?;
                    tracing::warn!(event_id=%event.id,%error,"alert queued for retry");
                }
            }
        }
        Ok(())
    }
}
