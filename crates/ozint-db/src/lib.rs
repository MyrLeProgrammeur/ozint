//! The SQLite handle OZINT stores investigations in.
//!
//! This crate deliberately creates **no tables**. Every `oz_*` table — investigations,
//! layers, nodes, the quota ledger, the tool cache — is declared by the module in
//! `ozint` that owns it, next to the queries that read it, and each runs its own
//! `CREATE TABLE IF NOT EXISTS` on first use. Centralising the schema here would put a
//! table's definition one crate away from its only reader, which is exactly how a column
//! ends up added in one place and never read in the other.
//!
//! So this file is only: the shared handle type, and three ways to obtain one.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

/// A handle to the investigation database. Cloning shares one connection.
///
/// One connection behind a `Mutex` rather than a pool: SQLite writes serialise anyway,
/// and the engine's fan-out is bounded by network calls, not by database contention.
pub type Db = Arc<Mutex<Connection>>;

/// Open a database file, creating parent directories as needed. Pass `:memory:` for tests.
pub fn open_db(file: &str) -> rusqlite::Result<Connection> {
    if file != ":memory:"
        && let Some(parent) = Path::new(file).parent()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    let conn = Connection::open(file)?;
    // `:memory:` rejects WAL — ignoring the result is the intended behaviour, not a swallow.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    Ok(conn)
}

/// Path of the investigation database: `OZINT_DB_PATH`, else `<OZINT_DATA_DIR>/ozint.db`.
pub fn db_path() -> PathBuf {
    match ozint_core::config::optional("OZINT_DB_PATH") {
        Some(path) => PathBuf::from(path),
        None => ozint_core::config::data_dir().join("ozint.db"),
    }
}

/// Open the configured database as a shareable handle.
pub fn open_default() -> rusqlite::Result<Db> {
    let path = db_path();
    let conn = open_db(&path.to_string_lossy())?;
    Ok(Arc::new(Mutex::new(conn)))
}

/// An in-memory database, for tests.
pub fn open_memory() -> rusqlite::Result<Db> {
    Ok(Arc::new(Mutex::new(open_db(":memory:")?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_in_memory_db_starts_empty() {
        // The point of the assertion: this crate must not have created anything. A table
        // appearing here means a schema leaked back in from somewhere it does not belong.
        let db = open_memory().unwrap();
        let conn = db.lock().unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "ozint-db must create no tables of its own");
    }
}
