//! The OZINT HTTP server: `/api/ozint/*`, the kill switch, and the built web cockpit.
//!
//! Binds `127.0.0.1` by default, not `0.0.0.0`. An investigation cockpit holds the
//! analyst's raw seeds — names, emails, phone numbers — and has no authentication of its
//! own, so exposing it on a LAN by default would be a privacy failure shipped as a
//! convenience. Put it behind a reverse proxy with real auth if you need it remote.

mod app;
mod routes;
mod state;

#[cfg(test)]
mod test_support;

use std::net::SocketAddr;

pub use state::AppState;

/// Pick the rustls crypto provider explicitly, before anything opens a connection.
///
/// More than one provider can land in the dependency graph, and rustls then refuses to
/// choose and panics on *every* outbound HTTPS request — which surfaces as every tool
/// failing at once, far from the cause. Installing one up front makes that impossible.
pub fn install_crypto_provider() {
    // Already installed is fine; this only needs to win the race once.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Load API keys from a dotenv file.
///
/// `OZINT_ENV_FILE` wins if set; otherwise `.env.local` then `.env` from the working
/// directory. Variables already present in the real environment are never overwritten.
pub fn load_env() {
    if let Ok(path) = std::env::var("OZINT_ENV_FILE") {
        let _ = dotenvy::from_filename(path);
        return;
    }
    for candidate in [".env.local", ".env"] {
        if dotenvy::from_filename(candidate).is_ok() {
            return;
        }
    }
}

/// Bind `addr` and serve until the process ends.
///
/// Callers are responsible for [`install_crypto_provider`] and [`load_env`] first, so an
/// embedding application keeps control of how its own configuration is loaded.
pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let state = AppState::new()?;
    let router = app::router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("OZINT server listening on http://{addr}");
    axum::serve(listener, router).await?;
    Ok(())
}
