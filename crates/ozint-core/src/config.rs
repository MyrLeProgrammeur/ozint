use crate::error::{OzintError, Result};

/// Read a required environment variable.
pub fn required(key: &'static str) -> Result<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(OzintError::MissingEnv(key)),
    }
}

/// Read an optional environment variable. Empty values are treated as absent, so a variable
/// exported as the empty string reads the same as one that was never set — which is what a
/// half-filled `.env` produces, and treating it as "present but blank" would arm a tool with
/// no credential.
pub fn optional(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Read an optional environment variable, falling back to a default.
pub fn or_default(key: &str, fallback: &str) -> String {
    optional(key).unwrap_or_else(|| fallback.to_string())
}

/// Root directory for runtime data (memory db, geo store).
/// Mirrors `OZINT_DATA_DIR` from the Next.js runtime.
pub fn data_dir() -> std::path::PathBuf {
    match optional("OZINT_DATA_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::path::PathBuf::from(".data"),
    }
}
