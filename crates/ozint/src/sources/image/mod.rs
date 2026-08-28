//! `entity-image (IMG)` — the image-node tools.
//!
//! Three, across two access tiers. [`local_exif`] and [`phash`] are `LocalOnly`: a decode of
//! bytes this crate's own media store already holds, no request, no rate limit. [`saucenao`]
//! is the first `FreeKey`, network-calling tool this category has — reverse-image lookup,
//! verified live 2026-08-25 now that `SAUCENAO_API_KEY` is held.
//!
//! Thumbnails still have no tool entry: `media::thumbnail` is served on demand by the HTTP
//! layer, not something a layer investigation "runs".
//!
//! ## Field ownership
//!
//! | tool | writes |
//! |---|---|
//! | [`local_exif`] | `mediaId`, `exif`, `lat`, `lon`, `accuracyM`, `takenAt`, `camera` |
//! | [`phash`] | `phash` |
//! | [`saucenao`] | `reverseMatches` |
//!
//! ## Why `saucenao` earns its own phase
//!
//! `plans::image_plan`'s own doc anticipated this before any tool existed to fill it: reverse-
//! image lookup is "a paid/keyed network call, a different class of cost entirely from a local
//! decode" than `local_exif`/`phash`. It joins `entity-image` as a second, unconditional phase
//! rather than the first — the local tools are free and instant, so there is nothing to hold
//! them back for, but nothing about SauceNAO's own cost is worth gating on either: unlike
//! `hash_plan`'s tier 2, there is no cheap earlier signal here that predicts whether a reverse-
//! image search will be productive.

pub mod local_exif;
pub mod phash;
pub mod saucenao;
