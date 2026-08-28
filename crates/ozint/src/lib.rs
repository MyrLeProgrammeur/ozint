//! OZINT — the investigation engine.
//!
//! Resolves a seed value (username, email, phone, IP, domain, hash, image, video,
//! coordinate, CVE, or a bare name) into a tree of typed nodes. Each **layer** fans out to
//! the tools applicable to one entity type, normalizes their results, and settles — it
//! **never** recurses on its own. The analyst grows the tree by hand, one
//! "continue search on this" at a time.
//!
//! The engine decomposes into 46 units: 11 entity orchestrators plus 35 supporting units
//! (fetch, health, normalize, layer planning, outcome taxonomy, and the rest of this crate).
//! This crate is the investigation-engine half; the route layer lives in
//! `crates/ozint-server/src/routes/ozint/`.
//!
//! Two boundaries that are hard rules, not preferences:
//! - **No globe or map widget of this engine's own, ever.** A coordinate finding links out to
//!   Google Maps / OSM / Apple. Nothing here may mount a WebGL globe or map view.
//! - **A layer that lost every tool renders `failed`, never the empty `0 NEW ENTITIES`
//!   block.** Silence and emptiness are different findings and must stay distinguishable.

pub mod cache;
pub mod classify;
pub mod decode;
pub mod directory;
pub mod dossier;
pub mod egress;
pub mod evidence;
pub mod exif;
pub mod fetch;
pub mod geo_links;
pub mod health;
pub mod layer_plan;
pub mod media;
pub mod normalize;
pub mod outcome;
pub mod plans;
pub mod refresh;
pub mod registry;
pub mod relations;
pub mod runtime;
pub mod scheduler;
pub mod signal;
pub mod sources;
pub mod store;
pub mod subject_file;
pub mod summary;
pub mod types;
pub mod visited;

pub use types::{
    Investigation, NodeStatus, OzNode, OzPayload, OzRow, OzSection, OzType, Provenance,
    RecordStatus, SectionKind, SignalChip, SignalTone,
};
