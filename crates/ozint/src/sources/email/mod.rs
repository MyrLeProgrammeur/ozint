//! `entity-email (EML)` — this type's first tool.
//!
//! This category opens with EmailRep.io as the triage gate and is graded "yes-with-paid-key"
//! overall (HIBP is paid; the rest are free/keyless). Neither of those claims is re-litigated
//! here — this module adds exactly one keyless tool, [`gravatar`], and leaves the rest of the
//! chain (EmailRep, HIBP, BreachDirectory, IntelX, Hunter.io, MXToolbox, DeHashed, LeakCheck) for
//! a future session with the keys the paid ones need.
//!
//! | module | tool id | reached |
//! |---|---|---|
//! | [`gravatar`] | `gravatar-email` | keyless — profile-by-email-hash |
//! | [`hudsonrock`] | `email-hudsonrock` | keyless — infostealer-compromise lookup |
//! | [`microsoft`] | `email-microsoft-credential-type` | keyless — Microsoft 365/Azure AD tenant fingerprint |
//!
//! `sidecar-holehe` (`crate::sources::sidecar::holehe`) is this type's second tool,
//! account-existence rather than identity — it lives under `sidecar` alongside Maigret and
//! SpiderFoot since all three share the Docker-sidecar contract, not this module's shape.
//! `sidecar-blackbird-email` joins it there for the same reason.
pub mod gravatar;
pub mod hudsonrock;
pub mod microsoft;
