//! `ip-maxmind` — a local GeoLite2-City MMDB lookup. Writes rows only; owns no
//! [`crate::types::IpPayload`] field, the same posture `ip-peeringdb`/`ip-censys`/`ip-netlas`
//! take, and for the same reason: `ip-ipinfo` already owns `country`/`city`/`lat`/`lon`, and a
//! second writer of the same keys would be silently resolved by `runtime::merge_patch`'s
//! shallow last-writer-wins merge rather than shown as corroboration.
//!
//! ## `LocalOnly`, with one qualification
//!
//! Once the database file is on disk, a lookup is a pure local decode — no network call, same
//! tier as `img-exif`/`geo-map-links`. Getting the database *onto* disk needs one network
//! request, gated on `MAXMIND_LICENSE_KEY` — so this tool is armed like a keyed one
//! (`env_vars: &["MAXMIND_LICENSE_KEY"]` in the registry) even though `AccessTier::LocalOnly`
//! is the honest description of what a lookup itself costs.
//!
//! `GET https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&
//! license_key={key}&suffix=tar.gz` — verified live 2026-08-25: a `302` redirect to a signed
//! download URL, followed to a real ~32 MB gzip tarball containing `GeoLite2-City.mmdb`.
//! [`ensure_database`] downloads it once into `<data_dir>/ozint/geoip/GeoLite2-City.mmdb` (the
//! same `<data_dir>/ozint/*` convention `crate::media::media_dir` uses) and re-downloads only
//! when the file is missing or older than [`MAX_DB_AGE_DAYS`] — GeoLite2 databases are
//! republished roughly weekly, so a database this stale is already behind upstream.
//!
//! A full scheduled refresh job (cron, background task) is out of scope for this pass — the
//! "missing or stale, so refetch" check inside [`run_maxmind`] itself is what this pass builds;
//! wiring it to run unattended is a later unit.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const ENV_VAR: &str = "MAXMIND_LICENSE_KEY";
const DOWNLOAD_BASE: &str = "https://download.maxmind.com/app/geoip_download";

/// GeoLite2 databases are republished roughly weekly; a week and a half gives room for a
/// missed release without living on stale data for a month.
const MAX_DB_AGE_DAYS: u64 = 10;

fn geoip_dir() -> PathBuf {
    ozint_core::config::data_dir().join("ozint").join("geoip")
}

fn db_path() -> PathBuf {
    geoip_dir().join("GeoLite2-City.mmdb")
}

/// `true` when `path` is missing or older than [`MAX_DB_AGE_DAYS`].
fn needs_refresh(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return true;
    };
    let Ok(modified) = meta.modified() else {
        return true;
    };
    let Ok(age) = std::time::SystemTime::now().duration_since(modified) else {
        return true;
    };
    age > Duration::from_secs(MAX_DB_AGE_DAYS * 24 * 60 * 60)
}

/// Downloads the GeoLite2-City tarball, extracts `GeoLite2-City.mmdb`, and writes it to `dest`.
/// A plain `reqwest` call rather than `ctx.fetch`: this is a one-off, large, gzip-tarball
/// download with no JSON body to cap the way [`crate::fetch::oz_fetch`]'s `MAX_BODY_BYTES`
/// does for ordinary tool responses, and it is not a per-investigation request the tool cache
/// or cancel signal are meant to govern — it happens at most once every ten days.
async fn download_database(license_key: &str, dest: &Path) -> Result<(), String> {
    let url =
        format!("{DOWNLOAD_BASE}?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz");
    let client = ozint_core::http::client();
    let bytes = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("MaxMind download request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("MaxMind download answered an error status: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("MaxMind download body could not be read: {e}"))?;

    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    let mut found = false;
    for entry in archive
        .entries()
        .map_err(|e| format!("MaxMind tarball could not be read: {e}"))?
    {
        let mut entry =
            entry.map_err(|e| format!("MaxMind tarball entry could not be read: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("MaxMind tarball entry path invalid: {e}"))?;
        if path.extension().and_then(|e| e.to_str()) == Some("mmdb") {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("could not create {parent:?}: {e}"))?;
            }
            let mut out = std::fs::File::create(dest)
                .map_err(|e| format!("could not create {dest:?}: {e}"))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|e| format!("could not write {dest:?}: {e}"))?;
            found = true;
            break;
        }
    }
    if !found {
        return Err("MaxMind tarball contained no .mmdb file".to_string());
    }
    Ok(())
}

/// Ensures a usable database exists at [`db_path`], downloading it if missing or stale.
async fn ensure_database() -> Result<PathBuf, String> {
    let path = db_path();
    if needs_refresh(&path) {
        let key =
            ozint_core::config::optional(ENV_VAR).ok_or_else(|| format!("{ENV_VAR} is not set"))?;
        download_database(&key, &path).await?;
    }
    Ok(path)
}

fn record_to_rows(record: &maxminddb::geoip2::City) -> Vec<OzRow> {
    let mut rows = Vec::new();
    let city = record.city.names.english;
    let country = record.country.names.english;
    match (city, country) {
        (Some(city), Some(country)) => rows.push(OzRow {
            label: "MaxMind location".to_string(),
            value: format!("{city}, {country}"),
            ..Default::default()
        }),
        (None, Some(country)) => rows.push(OzRow {
            label: "MaxMind country".to_string(),
            value: country.to_string(),
            ..Default::default()
        }),
        _ => {}
    }
    if let (Some(lat), Some(lon)) = (record.location.latitude, record.location.longitude) {
        rows.push(OzRow {
            label: "MaxMind coordinates".to_string(),
            value: format!("{lat:.4}, {lon:.4}"),
            ..Default::default()
        });
    }
    rows
}

pub async fn run_maxmind(ip: &str) -> DispatchOutcome {
    if ozint_core::config::optional(ENV_VAR).is_none() && needs_refresh(&db_path()) {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    }

    let path = match ensure_database().await {
        Ok(path) => path,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    let reader = match maxminddb::Reader::open_readfile(&path) {
        Ok(reader) => reader,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not open the local MaxMind database: {e}"),
                },
                None,
            );
        }
    };

    let addr: std::net::IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("`{ip}` is not a parseable IP address: {e}"),
                },
                None,
            );
        }
    };

    let lookup = match reader.lookup(addr) {
        Ok(lookup) => lookup,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("MaxMind lookup failed: {e}"),
                },
                None,
            );
        }
    };
    let decoded = match lookup.decode::<maxminddb::geoip2::City>() {
        Ok(decoded) => decoded,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("MaxMind record could not be decoded: {e}"),
                },
                None,
            );
        }
    };

    match decoded {
        Some(record) => {
            let rows = record_to_rows(&record);
            if rows.is_empty() {
                DispatchOutcome::Ran(
                    ToolOutcome::OkEmpty,
                    Some(ToolYield {
                        payload_patch: serde_json::json!({}),
                        ..Default::default()
                    }),
                )
            } else {
                let count = rows.len() as u32;
                DispatchOutcome::Ran(
                    ToolOutcome::OkWithResults { count },
                    Some(ToolYield {
                        payload_patch: serde_json::json!({}),
                        rows,
                        ..Default::default()
                    }),
                )
            }
        }
        // A reserved/unrouted or otherwise unmapped address — MaxMind holds no record.
        None => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_needs_refresh() {
        assert!(needs_refresh(Path::new("/does/not/exist.mmdb")));
    }

    #[test]
    fn a_fresh_file_does_not_need_refresh() {
        let dir = std::env::temp_dir().join(format!("ozint-maxmind-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("fresh.mmdb");
        std::fs::write(&file, b"stub").unwrap();
        assert!(!needs_refresh(&file));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_neither_a_key_nor_a_cached_database_exists() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };
        // Redirect the data dir so this test never touches a real cached database on the
        // machine running it.
        let prev_dir = std::env::var("OZINT_DATA_DIR").ok();
        let dir = std::env::temp_dir().join(format!("ozint-maxmind-test-{}", uuid::Uuid::new_v4()));
        unsafe { std::env::set_var("OZINT_DATA_DIR", &dir) };

        let outcome = run_maxmind("8.8.8.8").await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, ENV_VAR);
                assert!(produced.is_none());
            }
            other => {
                panic!("expected SkippedNoKey without a key or a cached database, got {other:?}")
            }
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(ENV_VAR, v) };
        }
        match prev_dir {
            Some(v) => unsafe { std::env::set_var("OZINT_DATA_DIR", v) },
            None => unsafe { std::env::remove_var("OZINT_DATA_DIR") },
        }
    }
}
