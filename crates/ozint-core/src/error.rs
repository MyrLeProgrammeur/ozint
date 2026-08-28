/// Errors surfaced by the OZINT crates.
#[derive(Debug, thiserror::Error)]
pub enum OzintError {
    #[error("missing environment variable: {0}")]
    MissingEnv(&'static str),

    #[error("{service} responded with HTTP {status}")]
    Upstream { service: &'static str, status: u16 },

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("cloud access is frozen: {0}")]
    Frozen(String),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T, E = OzintError> = std::result::Result<T, E>;
