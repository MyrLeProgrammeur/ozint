//! Shared configuration, error handling and HTTP plumbing for the OZINT Rust server.
//!
//! Every domain crate (`ozint-db`, `ozint-llm`, `ozint`, `ozint-server`)
//! depends on this one so that env access, error mapping and the outbound HTTP
//! connection pool behave identically everywhere.

pub mod config;
pub mod error;
pub mod http;
pub mod json;
pub mod net;
pub mod safety;

pub use error::{OzintError, Result};
