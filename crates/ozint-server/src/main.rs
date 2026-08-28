use std::net::SocketAddr;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ozint_server::install_crypto_provider();
    ozint_server::load_env();

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let port: u16 = ozint_core::config::or_default("PORT", "3000").parse()?;
    ozint_server::serve(SocketAddr::from(([127, 0, 0, 1], port))).await
}
