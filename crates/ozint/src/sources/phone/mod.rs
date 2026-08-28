//! `entity-phone (TEL)` — two tools as of the 2026-08-25 category audit.
//!
//! This category opens with a local `libphonenumber-js` normalise pass (free) before naming
//! Veriphone, IPQualityScore, Telnyx, DeHashed and LeakCheck. IPQualityScore, Telnyx, DeHashed and LeakCheck are deliberately
//! still unbuilt — the audit judged IPQualityScore's marginal value low relative to the
//! account-friction risk (Mathéo had already hit a duplicate-account block with them the same
//! night) and the other three need keys this build does not hold.
//!
//! | module | tool id | reached |
//! |---|---|---|
//! | [`local_normalize`] | `phone-local-normalize` | local — no request, `phonenumber` crate metadata only |
//! | [`veriphone`] | `phone-veriphone` | needs `VERIPHONE_API_KEY` — free, 1000/mo |
//!
//! `local_normalize` is deliberately a thin layer: `valid`/`country`/`line_type` are exactly
//! what `phonenumber`'s bundled metadata can answer without a network call. `veriphone` adds
//! `carrier` — the one field local metadata cannot answer — and reports its own live
//! `phone_type`/region/timezone as rows without contesting `local_normalize`'s payload fields;
//! see `veriphone`'s own module doc for why. Subscriber name (CNAM) and breach data stay
//! `None` — those need Telnyx/DeHashed, neither wired.
pub mod local_normalize;
pub mod veriphone;
