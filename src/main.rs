use anyhow::Result;
use clap::{Parser, Subcommand};
use host_sentinel::{config::Config, daemon, mcp, notify::Notifier, store::Event};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, default_value = "config.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run Linux monitoring, delivery worker, and optionally HTTP MCP.
    Run,
    /// Validate configuration without connecting or changing state.
    Check,
    /// Query local stored data as JSON (no server connection).
    Status,
    /// Serve read-only tools over MCP stdio using the daemon's state database.
    Mcp,
    /// Explicitly send a synthetic test notification to configured Rakazo bot.
    TestWebhook,
    /// Run the root-owned Unix-socket response broker (Linux, optional capability).
    ResponseAgent,
    /// Index retained SSH journal evidence without sending alerts or moving the live cursor.
    BackfillAuth {
        #[arg(long)]
        since: String,
        #[arg(long)]
        until: String,
    },
    /// Root-only local session attribution receipt. Does not grant trust or execute commands.
    RecordAutomation {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        label: String,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "host_sentinel=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    match cli.command {
        Action::BackfillAuth { since, until } => {
            let store = daemon::open_store(&config)?;
            println!(
                "{}",
                host_sentinel::investigation::backfill(&config, &store, &since, &until).await?
            );
        }
        Action::RecordAutomation {
            session_id,
            task_id,
            label,
        } => {
            println!(
                "{}",
                host_sentinel::sessions::record_automation(&config, &session_id, &task_id, &label)
                    .await?
            );
        }
        Action::Check => println!(
            "Configuration is valid. Secret availability and connectivity are checked at startup."
        ),
        Action::Run => daemon::run(config).await?,
        Action::ResponseAgent => {
            host_sentinel::response::serve_agent(config.response, config.host_label).await?
        }
        Action::Status => {
            let store = daemon::open_store(&config)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"sample":store.get("sample")?,"memory":store.get("memory")?,"disk":store.get("disk")?,"pending_notifications":store.queue_size()?,"alerts":store.recent(true,false,20)?})
                )?
            );
        }
        Action::Mcp => mcp::serve_stdio(daemon::open_store(&config)?).await?,
        Action::TestWebhook => {
            anyhow::ensure!(
                config.webhook.enabled,
                "enable webhook before sending a test"
            );
            Notifier::new(&config.webhook)?.send(&Event::new(&config.host_label,host_sentinel::now(),"monitor_test",serde_json::json!({"synthetic":true,"message":"Host Sentinel delivery test; no real incident"}))).await?;
            println!(
                "Rakazo acknowledged the test event. Verify its conversation and client notification settings."
            );
        }
    }
    Ok(())
}
