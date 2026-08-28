//! `/api/ozint/*` — the HTTP wire for the OZINT cockpit.
//! Wraps `ozint`'s engine (`runtime::fire_layer`, `store`, `classify`, `registry`) with
//! its wire contract.
//!
//! - `POST /api/ozint/fire` — start (`{seed}`) or continue (`{investigationId,
//!   parentNodeId}`) a layer, streamed back as one multiplexed SSE connection. See
//!   `fire.rs`'s module doc.
//! - `POST /api/ozint/cancel` — the only way to stop a running layer; never inferred from a
//!   dropped connection. See `cancel.rs`'s module doc.
//! - `GET /api/ozint/investigations` / `GET /api/ozint/investigations/{id}` — the read half
//!   of history-resume. Plain JSON. See `investigations.rs`.
//! - `POST /api/ozint/refresh` — re-run one node's own tool chain. Plain JSON, no layer, no
//!   children. See `refresh.rs`'s module doc.
//! - `GET /api/ozint/investigations/{id}/relations` — POTENTIAL RELATIONS, derived live.
//! - `GET /api/ozint/investigations/{id}/export?format=json|markdown` — the dossier exporter,
//!   the whole investigation as a document. See `ozint::dossier`.
//! - `POST /api/ozint/decode` — local decode prepass over a seed. No network, no key.
//! - `POST /api/ozint/node/{id}/edit|reject|restore` — the analyst's three verdicts on a
//!   finding. Local writes, live even while frozen. See `node.rs`'s module doc.
//! - `POST /api/ozint/node/{id}/evidence` — ask the Internet Archive what captures it already
//!   holds for one URL. Slow (20-40 s), opt-in, behind the freeze gate. See `evidence.rs`.
//! - `POST /api/ozint/spawn` — open a separate investigation from one relation card. Creates
//!   only; firing stays in `fire.rs`. See `spawn.rs`'s module doc.
//!
//! `state.rs` holds the process-wide bookkeeping every route shares: live `CancelHandle`s,
//! and the per-investigation `VisitedSet`/`ToolHealth` pair `fire_layer` needs across
//! concurrently-running branches of one investigation.

pub mod cancel;
pub mod classifier_llm;
pub mod decode;
pub mod evidence;
pub mod fire;
pub mod investigations;
pub mod media;
pub mod node;
pub mod refresh;
pub mod spawn;
pub mod state;

pub use state::OzintState;
