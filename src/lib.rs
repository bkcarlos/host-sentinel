pub mod config;
pub mod cpu;
pub mod daemon;
pub mod disk;
pub mod journal;
pub mod mcp;
pub mod memory;
pub mod notify;
pub mod process_response;
pub mod response;
pub mod response_mcp;
pub mod store;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
