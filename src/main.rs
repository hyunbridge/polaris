//! Polaris binary entrypoint.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use clap::Parser;
use polaris::{app::build_router, config::PolarisConfig, state::AppState};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "polaris",
    version,
    about = "Polaris: lightweight pure-Rust DoH resolver"
)]
struct Cli {
    #[arg(long, env = "POLARIS_CONFIG", default_value = "config/polaris.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = load_config(&cli.config)?;
    init_tracing(&config);

    let state = Arc::new(AppState::new(config).context("failed to initialize app state")?);
    state.run_startup_self_check().await;

    let bind = state.config.server.bind;
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {bind}"))?;

    info!(%bind, "polaris starting");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("http server failure")?;

    info!("polaris stopped");
    Ok(())
}

fn load_config(path: &Path) -> anyhow::Result<PolarisConfig> {
    if path.exists() {
        PolarisConfig::load(path)
    } else {
        Ok(PolarisConfig::default())
    }
}

fn init_tracing(config: &PolarisConfig) {
    let filter = EnvFilter::try_new(config.logging.filter.clone())
        .unwrap_or_else(|_| EnvFilter::new("info,polaris=info"));

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if config.logging.json {
        builder.json().init();
    } else {
        builder.init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!(error = %err, "ctrl-c handler failed");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                error!(error = %err, "SIGTERM handler failed");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
