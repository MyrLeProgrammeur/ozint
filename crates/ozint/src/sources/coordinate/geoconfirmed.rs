//! `geo-geoconfirmed` — verified conflict-event placemarks near a coordinate, from
//! GeoConfirmed's public API. Long considered but not built: this crate's own module doc on
//! `coordinate::mod` (now corrected) used to say "no endpoint enumerates the theatres" —
//! verified false by the 2026-08-25 category audit, which found and called
//! `GET https://geoconfirmed.org/api/Conflict` live.
//!
//! ## The two-call shape, verified by direct call 2026-08-26
//!
//! 1. `GET /api/Conflict` — keyless, `200`, a small JSON array (20 entries as of this
//!    writing): `url` (the slug the second call needs), `name`, `latitude`/`longitude` (the
//!    theatre's own centre point), `startDate`/`endDate`. This is the theatre index the
//!    original blocker said didn't exist.
//! 2. `GET /api/Placemark/{url}` — keyless, `200`, a nested array: `faction[].icons[].
//!    placemarks[]`, each placemark carrying `id`, `date`, `la`/`lo` (lat/lon). **Genuinely
//!    bulk, no spatial filter** — confirmed by size: `ukraine` is 6.9 MB, `israel` 840 KB,
//!    `yemen` 30 KB. A `POST /api/Placemark/table` exists in the OpenAPI spec with a
//!    `TableFilter` that looks coordinate-shaped, but answered `302` (redirect, looks
//!    auth-gated) when called unauthenticated — not usable here.
//!
//! ## Why nearest-theatre-by-distance, not a hand-kept country table
//!
//! The blocker this unit was waiting on was specifically "no endpoint enumerates the
//! theatres, so there's nothing to pick from short of a hand-maintained country→theatre map".
//! With the real index in hand, [`nearest_theatre`] replaces that hand-kept table with a
//! straight haversine distance to each theatre's own declared centre — the same computed-not-
//! hardcoded spirit `geo-overpass`'s distance sort already uses. [`META_THEATRE_URLS`] excludes
//! the handful of entries that are not geographic filters at all (`world`'s centre is a
//! meaningless `(0, 0)`; `wwi`/`wwii`/`history` share Berlin's coordinates as a placeholder).
//!
//! ## Two distance thresholds, and why they're different
//!
//! [`MAX_THEATRE_DISTANCE_KM`] gates whether *any* theatre is even worth downloading — a
//! coordinate nowhere near a declared theatre should not trigger a multi-megabyte fetch for
//! nothing. [`MAX_PLACEMARK_DISTANCE_KM`] then filters that theatre's own placemarks down to
//! ones actually near the query point, since a theatre the size of Ukraine has placemarks
//! scattered across the whole country and "nearest theatre" alone says nothing about proximity
//! to any single event within it.
//!
//! ## Why this writes only rows, never a payload field
//!
//! Same reasoning as `geo-overpass`: a verified event pin near a coordinate is context for the
//! analyst to weigh, not a fact this crate should assert onto `CoordinatePayload` — and no
//! field exists for it there. No children either, for the same reason `geo-overpass` seeds
//! none: a nearby placemark is not itself the subject of this investigation.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const CONFLICT_LIST_URL: &str = "https://geoconfirmed.org/api/Conflict";
const PLACEMARK_BASE: &str = "https://geoconfirmed.org/api/Placemark/";

/// Theatre slugs that are not real geographic filters — a meta-category (`world`, `history`)
/// or a historical placeholder (`wwi`/`wwii` share Berlin's coordinates) rather than a current,
/// location-scoped conflict. Verified by inspecting `/api/Conflict`'s own `latitude`/
/// `longitude` values: `world` is `(0, 0)`, the others cluster on one shared placeholder point.
const META_THEATRE_URLS: &[&str] = &["world", "wwi", "wwii", "history"];

/// How close a coordinate must be to a theatre's own centre point before that theatre's bulk
/// placemark data is even downloaded. Generous — theatres are country/region-scale, not
/// street-level — chosen so a coordinate anywhere inside a large theatre (Ukraine, Afghanistan)
/// still reaches its own placemark data even when far from the centroid.
const MAX_THEATRE_DISTANCE_KM: f64 = 1500.0;

/// How close an individual placemark must be to the query coordinate to be reported, once its
/// theatre's bulk data is in hand. Tighter than the theatre gate — a theatre-scale download
/// covers a whole country, and this is what turns that into "nearby", not "somewhere in the
/// same war".
const MAX_PLACEMARK_DISTANCE_KM: f64 = 100.0;

/// Cap on reported rows, sorted nearest-first — the same "bounded, not exhaustive" restraint
/// `sources::username::wmn`'s site sweep and `video-local-probe`'s keyframe cap both use, so a
/// dense theatre near a busy coordinate does not flood the node's detail panel.
const MAX_PLACEMARK_ROWS: usize = 20;

/// Mean Earth radius in metres (IUGG) — same constant `geo-overpass::haversine_m` uses,
/// duplicated here per this crate's "one module per tool" convention rather than reaching into
/// another module's private helper.
const EARTH_RADIUS_M: f64 = 6_371_000.0;

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (lat1, lon1, lat2, lon2) = (
        lat1.to_radians(),
        lon1.to_radians(),
        lat2.to_radians(),
        lon2.to_radians(),
    );
    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    (EARTH_RADIUS_M * c) / 1000.0
}

/// One theatre from `/api/Conflict`, narrowed to what [`nearest_theatre`] needs.
#[derive(Debug, Clone, PartialEq)]
pub struct Theatre {
    pub url: String,
    pub name: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// Parses `/api/Conflict`'s response array. Pure and tested.
pub fn parse_conflict_list(json: &serde_json::Value) -> Result<Vec<Theatre>, String> {
    let arr = json
        .as_array()
        .ok_or_else(|| "GeoConfirmed's conflict list was not a JSON array".to_string())?;
    arr.iter()
        .map(|c| {
            Ok(Theatre {
                url: c
                    .get("url")
                    .and_then(|v| v.as_str())
                    .ok_or("a conflict entry is missing `url`")?
                    .to_string(),
                name: c
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                latitude: c
                    .get("latitude")
                    .and_then(|v| v.as_f64())
                    .ok_or("a conflict entry is missing `latitude`")?,
                longitude: c
                    .get("longitude")
                    .and_then(|v| v.as_f64())
                    .ok_or("a conflict entry is missing `longitude`")?,
            })
        })
        .collect()
}

/// The single closest non-meta theatre to `(lat, lon)`, and its distance in km — or `None` if
/// the closest one is still farther than [`MAX_THEATRE_DISTANCE_KM`]. Pure and tested.
pub fn nearest_theatre(theatres: &[Theatre], lat: f64, lon: f64) -> Option<(Theatre, f64)> {
    theatres
        .iter()
        .filter(|t| !META_THEATRE_URLS.contains(&t.url.as_str()))
        .map(|t| (t.clone(), haversine_km(lat, lon, t.latitude, t.longitude)))
        .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .filter(|(_, dist)| *dist <= MAX_THEATRE_DISTANCE_KM)
}

/// One placemark, flattened out of `/api/Placemark/{url}`'s nested faction/icon structure,
/// with its owning faction name carried alongside.
#[derive(Debug, Clone, PartialEq)]
struct FlatPlacemark {
    faction: String,
    date: Option<String>,
    lat: f64,
    lon: f64,
}

/// Flattens `/api/Placemark/{url}`'s `faction[].icons[].placemarks[]` nesting into one list.
/// A malformed individual placemark is skipped, not fatal — a bulk document this size (up to
/// ~7 MB) genuinely reporting one bad entry should not lose every good one alongside it. Pure
/// and tested.
fn flatten_placemarks(json: &serde_json::Value) -> Vec<FlatPlacemark> {
    let Some(factions) = json.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for faction in factions {
        let faction_name = faction
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown faction")
            .to_string();
        let Some(icons) = faction.get("icons").and_then(|v| v.as_array()) else {
            continue;
        };
        for icon in icons {
            let Some(placemarks) = icon.get("placemarks").and_then(|v| v.as_array()) else {
                continue;
            };
            for pm in placemarks {
                let (Some(lat), Some(lon)) = (
                    pm.get("la").and_then(|v| v.as_f64()),
                    pm.get("lo").and_then(|v| v.as_f64()),
                ) else {
                    continue;
                };
                out.push(FlatPlacemark {
                    faction: faction_name.clone(),
                    date: pm.get("date").and_then(|v| v.as_str()).map(str::to_string),
                    lat,
                    lon,
                });
            }
        }
    }
    out
}

fn geoconfirmed_to_yield(theatre: &Theatre, nearby: &[(FlatPlacemark, f64)]) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "GeoConfirmed theatre".to_string(),
        value: theatre.name.clone(),
        href: Some(format!("https://geoconfirmed.org/{}", theatre.url)),
        ..Default::default()
    }];
    for (pm, dist_km) in nearby {
        rows.push(OzRow {
            label: pm.faction.clone(),
            value: format!(
                "{:.1} km away{}",
                dist_km,
                pm.date
                    .as_deref()
                    .map(|d| format!(", {d}"))
                    .unwrap_or_default()
            ),
            ..Default::default()
        });
    }
    ToolYield {
        rows,
        ..Default::default()
    }
}

/// Runs `geo-geoconfirmed` against `value` (`"lat,lon"`, the same shape `geo-nominatim`/
/// `geo-overpass` consume). Keyless.
pub async fn run_geoconfirmed(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some((lat, lon)) = super::parse_lat_lon(value) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{value}` is not a valid `lat,lon` pair"),
            },
            None,
        );
    };

    let list_outcome = ctx
        .fetch(
            "geo-geoconfirmed",
            "conflict-list",
            CONFLICT_LIST_URL,
            fetch::OzFetchOptions::default(),
        )
        .await;
    if matches!(list_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&list_outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(list_resp) = list_outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let OzBody::Json(list_json) = &list_resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "GeoConfirmed's conflict list was not JSON".to_string(),
            },
            None,
        );
    };
    let theatres = match parse_conflict_list(list_json) {
        Ok(t) => t,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    let Some((theatre, _dist)) = nearest_theatre(&theatres, lat, lon) else {
        // No theatre is close enough to be worth a multi-megabyte download — a genuine,
        // honest empty finding, not a failure.
        return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
    };

    let placemark_url = format!("{PLACEMARK_BASE}{}", theatre.url);
    let pm_outcome = ctx
        .fetch(
            "geo-geoconfirmed",
            &format!("placemarks:{}", theatre.url),
            &placemark_url,
            fetch::OzFetchOptions::default(),
        )
        .await;
    if matches!(pm_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&pm_outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(pm_resp) = pm_outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let OzBody::Json(pm_json) = &pm_resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "GeoConfirmed's placemark data was not JSON".to_string(),
            },
            None,
        );
    };

    let all_placemarks = flatten_placemarks(pm_json);
    let mut nearby: Vec<(FlatPlacemark, f64)> = all_placemarks
        .into_iter()
        .map(|pm| {
            let dist = haversine_km(lat, lon, pm.lat, pm.lon);
            (pm, dist)
        })
        .filter(|(_, dist)| *dist <= MAX_PLACEMARK_DISTANCE_KM)
        .collect();
    nearby.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    nearby.truncate(MAX_PLACEMARK_ROWS);

    let count = nearby.len() as u32;
    let produced = geoconfirmed_to_yield(&theatre, &nearby);
    if count == 0 {
        DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(produced))
    } else {
        DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(produced))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_conflicts() -> serde_json::Value {
        serde_json::json!([
            {"name": "World", "url": "world", "latitude": 0.0, "longitude": 0.0},
            {"name": "Ukraine", "url": "ukraine", "latitude": 48.3794, "longitude": 31.1656},
            {"name": "Yemen", "url": "yemen", "latitude": 15.3359872, "longitude": 42.7957825}
        ])
    }

    #[test]
    fn parses_the_conflict_list() {
        let theatres = parse_conflict_list(&sample_conflicts()).expect("parses");
        assert_eq!(theatres.len(), 3);
        assert_eq!(theatres[1].url, "ukraine");
    }

    #[test]
    fn rejects_a_non_array_body() {
        assert!(parse_conflict_list(&serde_json::json!({"error": "x"})).is_err());
    }

    #[test]
    fn nearest_theatre_excludes_meta_entries() {
        // A synthetic set where "World" (meta, centre (0,0)) is genuinely closer by raw
        // distance to the query point than the one real theatre — proving exclusion actually
        // does something, rather than a real theatre winning by distance alone regardless.
        let theatres = vec![
            Theatre {
                url: "world".to_string(),
                name: "World".to_string(),
                latitude: 0.0,
                longitude: 0.0,
            },
            Theatre {
                url: "nearby".to_string(),
                name: "Nearby".to_string(),
                latitude: 1.0,
                longitude: 1.0,
            },
        ];
        let (theatre, _) = nearest_theatre(&theatres, 0.1, 0.1).expect("the real theatre must win");
        assert_eq!(theatre.url, "nearby");
    }

    #[test]
    fn nearest_theatre_picks_the_genuinely_closest_one() {
        let theatres = parse_conflict_list(&sample_conflicts()).unwrap();
        // A coordinate right on Kyiv should pick Ukraine over Yemen.
        let (theatre, dist) = nearest_theatre(&theatres, 50.45, 30.52).expect("ukraine is close");
        assert_eq!(theatre.url, "ukraine");
        assert!(dist < 300.0);
    }

    #[test]
    fn nearest_theatre_returns_none_when_everything_is_too_far() {
        let theatres = parse_conflict_list(&sample_conflicts()).unwrap();
        // Deep in the Pacific, thousands of km from every theatre above.
        assert!(nearest_theatre(&theatres, -20.0, -150.0).is_none());
    }

    #[test]
    fn flattens_nested_faction_icon_placemarks() {
        let json = serde_json::json!([{
            "name": "Rebels",
            "icons": [{
                "icon": "/x.png",
                "placemarks": [
                    {"id": "a", "date": "2026-08-20T00:00:00", "la": 16.5, "lo": 43.0},
                    {"id": "b", "date": null, "la": 13.4, "lo": 43.6}
                ]
            }]
        }]);
        let flat = flatten_placemarks(&json);
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].faction, "Rebels");
        assert_eq!(flat[1].date, None);
    }

    #[test]
    fn flatten_skips_a_placemark_missing_coordinates_rather_than_failing_everything() {
        let json = serde_json::json!([{
            "name": "F",
            "icons": [{"icon": "/x.png", "placemarks": [
                {"id": "bad", "date": null},
                {"id": "good", "date": null, "la": 1.0, "lo": 2.0}
            ]}]
        }]);
        let flat = flatten_placemarks(&json);
        assert_eq!(flat.len(), 1);
    }

    #[test]
    fn haversine_matches_a_known_distance() {
        // Paris to London, ~344 km great circle.
        let d = haversine_km(48.8566, 2.3522, 51.5074, -0.1278);
        assert!((d - 344.0).abs() < 5.0, "expected ~344km, got {d}");
        assert_eq!(haversine_km(48.0, 2.0, 48.0, 2.0), 0.0);
    }

    #[tokio::test]
    async fn a_malformed_value_is_a_parse_error() {
        let outcome =
            run_geoconfirmed("not-a-coordinate", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::ParseError { .. }, None) => {}
            other => panic!("expected ParseError, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod live_smoke {
    use super::*;

    #[tokio::test]
    #[ignore = "hits the real GeoConfirmed API, including a multi-MB placemark download"]
    async fn live_geoconfirmed_lookup_near_kyiv() {
        let outcome = run_geoconfirmed("50.45,30.52", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(outcome, Some(y)) => {
                println!(
                    "LIVE GEOCONFIRMED: {outcome:?}, rows: {:?}",
                    &y.rows[..y.rows.len().min(5)]
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
