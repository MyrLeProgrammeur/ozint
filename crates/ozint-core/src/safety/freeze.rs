//! The server-side half of the OZINT kill switch.
//!
//! Until now "freeze" was client-side only: a `localStorage` boolean that the *surfaces*
//! agreed to consult before calling an API route, with server-side enforcement deliberately
//! deferred. The gap is real, not theoretical: a tab opened
//! before the freeze, a second browser, a `curl`, or the Tauri window's cached bundle all
//! reach the same routes and never see the flag. This module is the state the server itself
//! owns, so a refusal no longer depends on the caller's cooperation.
//!
//! ## Why it persists to a file
//!
//! The client store persists across reloads **on purpose** — a freeze holds until it is
//! explicitly lifted. A server-side freeze that evaporated on restart would be strictly
//! weaker than the client one it replaces, and "restart the server" would become an
//! accidental unfreeze. So the record is written to `<OZINT_DATA_DIR>/freeze.json`.
//!
//! ## Fail closed, and say why
//!
//! If the file **does not exist**, OZINT has never been frozen on this machine → not frozen.
//! If the file exists but cannot be read or parsed, the only honest reading is that *someone
//! set this state at least once and we can no longer tell what they chose*. That resolves to
//! **frozen**, with the reason kept in [`FreezeRecord::unreadable`] so `GET /api/safety/freeze`
//! shows an operator why everything is refusing rather than leaving them to guess. Lifting the
//! freeze rewrites the file and clears the condition.
//!
//! ## A failed write is returned, never swallowed
//!
//! [`FreezeState::set`] applies the new value in memory unconditionally (this process obeys
//! immediately) and hands back a `#[must_use]` [`FreezeUpdate`] carrying any persistence
//! error. An analyst who thinks they froze OZINT must not be told "ok" when the record that
//! survives a restart was never written.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// The freeze state as stored on disk and as reported to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreezeRecord {
    /// Is every outbound/outbound OZINT action currently refused?
    pub frozen: bool,
    /// Milliseconds since the Unix epoch, at the moment the value last changed.
    pub changed_at: i64,
    /// Free-form label for who flipped it (`"api"`, `"voice"`, `"startup"`…). Never trusted
    /// for anything but display.
    pub source: String,
    /// Present only when this record was **synthesised** because the stored file could not be
    /// read — see the module doc. Its presence means "frozen because we lost the truth", not
    /// "frozen because someone asked".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

impl FreezeRecord {
    fn thawed(source: &str) -> Self {
        Self {
            frozen: false,
            changed_at: now_ms(),
            source: source.to_string(),
            unreadable: None,
        }
    }

    fn fail_closed(reason: String) -> Self {
        Self {
            frozen: true,
            changed_at: now_ms(),
            source: "startup".to_string(),
            unreadable: Some(reason),
        }
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The result of a [`FreezeState::set`]. Must not be dropped on the floor: `persist_error`
/// is the difference between "frozen until lifted" and "frozen until the next restart".
#[derive(Debug, Clone)]
#[must_use = "a freeze that failed to persist will not survive a restart — report it"]
pub struct FreezeUpdate {
    /// The record now in force in this process.
    pub record: FreezeRecord,
    /// `Some(reason)` when the record could not be written to disk.
    pub persist_error: Option<String>,
}

/// Process-wide freeze state. One instance lives in the server's `AppState`.
#[derive(Debug)]
pub struct FreezeState {
    /// `None` for a purely in-memory state (tests, and any embedding that deliberately does
    /// not want a file).
    path: Option<PathBuf>,
    record: RwLock<FreezeRecord>,
}

impl FreezeState {
    /// A state with no backing file: starts thawed and never persists. For tests.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            record: RwLock::new(FreezeRecord::thawed("in-memory")),
        }
    }

    /// Loads (or synthesises) the record backing `path`. Never fails — an unreadable file
    /// resolves to *frozen*, per the module doc.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let record = read_record(&path);
        Self {
            path: Some(path),
            record: RwLock::new(record),
        }
    }

    /// The conventional location: `<OZINT_DATA_DIR>/freeze.json`, alongside `memory.db`.
    pub fn from_data_dir() -> Self {
        Self::load(crate::config::data_dir().join("freeze.json"))
    }

    /// The one question every gate asks.
    pub fn is_frozen(&self) -> bool {
        self.record.read().expect("freeze state poisoned").frozen
    }

    /// The full record, for `GET /api/safety/freeze`.
    pub fn snapshot(&self) -> FreezeRecord {
        self.record.read().expect("freeze state poisoned").clone()
    }

    /// Applies `frozen` in this process and tries to persist it. See [`FreezeUpdate`].
    ///
    /// Setting the same value again is not a no-op: it refreshes `changed_at`/`source` and,
    /// importantly, **clears an `unreadable` condition** by writing a record we can read back.
    pub fn set(&self, frozen: bool, source: &str) -> FreezeUpdate {
        let record = FreezeRecord {
            frozen,
            changed_at: now_ms(),
            source: source.to_string(),
            unreadable: None,
        };
        *self.record.write().expect("freeze state poisoned") = record.clone();

        let persist_error = match &self.path {
            Some(path) => write_record(path, &record).err(),
            None => None,
        };
        if let Some(reason) = &persist_error {
            tracing::error!(target: "ozint::safety::freeze", %reason, frozen, "freeze state could not be persisted");
        }
        FreezeUpdate {
            record,
            persist_error,
        }
    }
}

impl Default for FreezeState {
    /// Deliberately the *in-memory* variant, so a `Default::default()` written without
    /// thought cannot silently give a process a freeze file it does not own. The server wires
    /// [`FreezeState::from_data_dir`] explicitly.
    fn default() -> Self {
        Self::in_memory()
    }
}

fn read_record(path: &Path) -> FreezeRecord {
    match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<FreezeRecord>(&raw) {
            Ok(record) => record,
            Err(err) => FreezeRecord::fail_closed(format!(
                "{} is not a valid freeze record: {err}",
                path.display()
            )),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => FreezeRecord::thawed("startup"),
        Err(err) => {
            FreezeRecord::fail_closed(format!("{} could not be read: {err}", path.display()))
        }
    }
}

fn write_record(path: &Path, record: &FreezeRecord) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(record).map_err(|e| e.to_string())?;
    std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ozint-freeze-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("freeze.json")
    }

    #[test]
    fn a_missing_file_means_never_frozen() {
        let state = FreezeState::load(temp_path("missing").parent().unwrap().join("nope.json"));
        assert!(!state.is_frozen());
        assert!(state.snapshot().unreadable.is_none());
    }

    #[test]
    fn set_persists_and_reloads() {
        let path = temp_path("roundtrip");
        let update = FreezeState::load(&path).set(true, "api");
        assert!(update.persist_error.is_none());

        let reloaded = FreezeState::load(&path);
        assert!(reloaded.is_frozen(), "a freeze must survive a restart");
        assert_eq!(reloaded.snapshot().source, "api");
    }

    #[test]
    fn lifting_a_freeze_also_survives_a_restart() {
        let path = temp_path("lift");
        let _ = FreezeState::load(&path).set(true, "api");
        let _ = FreezeState::load(&path).set(false, "api");
        assert!(!FreezeState::load(&path).is_frozen());
    }

    #[test]
    fn an_unparsable_file_fails_closed_with_a_reason() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "{ this is not json").unwrap();

        let state = FreezeState::load(&path);
        assert!(
            state.is_frozen(),
            "losing the record must not read as 'not frozen'"
        );
        let snapshot = state.snapshot();
        assert!(
            snapshot.unreadable.is_some(),
            "the operator must be told why everything refuses"
        );
        assert_eq!(snapshot.source, "startup");
    }

    #[test]
    fn writing_a_valid_record_clears_an_unreadable_condition() {
        let path = temp_path("recover");
        std::fs::write(&path, "garbage").unwrap();
        let state = FreezeState::load(&path);
        assert!(state.is_frozen());

        let update = state.set(false, "api");
        assert!(update.persist_error.is_none());
        assert!(update.record.unreadable.is_none());
        assert!(!FreezeState::load(&path).is_frozen());
    }

    #[test]
    fn a_persistence_failure_is_reported_but_still_applies_in_memory() {
        // A directory where the file should be: the write cannot succeed.
        let path = temp_path("unwritable");
        std::fs::create_dir_all(&path).unwrap();

        let state = FreezeState::load(&path);
        let update = state.set(true, "api");

        assert!(
            state.is_frozen(),
            "this process must obey the freeze regardless"
        );
        assert!(
            update.persist_error.is_some(),
            "a lost write must never look like success"
        );
    }

    #[test]
    fn in_memory_state_never_touches_disk_and_starts_thawed() {
        let state = FreezeState::in_memory();
        assert!(!state.is_frozen());
        let update = state.set(true, "test");
        assert!(update.persist_error.is_none());
        assert!(state.is_frozen());
    }

    #[test]
    fn the_record_serialises_camel_case_for_the_spa() {
        let json = serde_json::to_string(&FreezeRecord {
            frozen: true,
            changed_at: 1_700_000_000_000,
            source: "api".into(),
            unreadable: None,
        })
        .unwrap();
        assert!(json.contains("\"changedAt\""), "{json}");
        assert!(
            !json.contains("unreadable"),
            "an absent reason must not appear at all: {json}"
        );
    }
}
