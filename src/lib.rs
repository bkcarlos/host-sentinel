pub mod config;
pub mod cpu;
pub mod daemon;
pub mod journal;
pub mod mcp;
pub mod notify;
pub mod store;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
