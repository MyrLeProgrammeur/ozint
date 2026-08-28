//! Process-wide, in-memory bookkeeping for the OZINT routes: live `CancelHandle`s (so
//! `POST /api/ozint/cancel` can reach a running layer) and, per investigation, the shared
//! `VisitedSet`/`ToolHealth` `fire_layer` needs across concurrently-firing branches.
//!
//! Everything here is a `Mutex<HashMap<..>>` — the crate's own health/visited modules use
//! exactly that internally, and this module's scale (one entry per live layer, one per
//! investigation ever opened on this process) never justifies anything fancier.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ozint::fetch::CancelHandle;
use ozint::health::ToolHealth;
use ozint::visited::VisitedSet;

/// What one investigation needs to persist across separate `fire` calls, for as long as this
/// process runs. `visited` is shared (not rebuilt from scratch) between branches firing at
/// the same time — see `LayerContext::visited`'s own doc in `runtime.rs` — while a `fire`
/// handling a "continue" still re-seeds it from the stored tree before use (see
/// `fire.rs::load_visited`), so a sibling branch's just-persisted nodes are never missed.
struct InvestigationRuntime {
    visited: Arc<Mutex<VisitedSet>>,
    health: Arc<ToolHealth>,
}

/// Live `CancelHandle`s, keyed two ways: by the engine's own `layer_id` (known only once the
/// `LayerStart` frame has been observed) for `POST /api/ozint/cancel {layerId}`, and by
/// `investigation_id` for `{investigationId}` — which must be able to hit every branch
/// currently running under that investigation, not just one.
///
/// **Registration only happens once `LayerStart` is observed**, not at spawn time. The
/// engine sends `LayerStart` as its very first action (`runtime.rs`), before any store write
/// or tool call — so the window where a handle exists but isn't registered yet is a few
/// microseconds, and a client cannot name a `layerId` it hasn't received yet anyway. An
/// investigation-wide cancel that lands in that same sliver of time is the one case this
/// misses; accepted rather than adding a second "pending registration" bookkeeping path for
/// a race no real client can trigger (it would have to cancel an investigation before ever
/// receiving a single byte of the response it just opened).
#[derive(Default)]
struct CancelRegistry {
    by_layer: Mutex<HashMap<String, CancelHandle>>,
    by_investigation: Mutex<HashMap<String, HashSet<String>>>,
}

impl CancelRegistry {
    fn register(&self, investigation_id: &str, layer_id: &str, handle: CancelHandle) {
        self.by_layer
            .lock()
            .unwrap()
            .insert(layer_id.to_string(), handle);
        self.by_investigation
            .lock()
            .unwrap()
            .entry(investigation_id.to_string())
            .or_default()
            .insert(layer_id.to_string());
    }

    /// Called once the layer settles (or aborts) — see `fire.rs`'s relay task. Without this
    /// the maps would grow for as long as the process runs.
    fn remove(&self, investigation_id: &str, layer_id: &str) {
        self.by_layer.lock().unwrap().remove(layer_id);
        if let Some(set) = self
            .by_investigation
            .lock()
            .unwrap()
            .get_mut(investigation_id)
        {
            set.remove(layer_id);
        }
    }

    fn cancel_layer(&self, layer_id: &str) -> bool {
        match self.by_layer.lock().unwrap().get(layer_id) {
            Some(handle) => {
                handle.cancel();
                true
            }
            None => false,
        }
    }

    /// Cancels every layer currently registered under `investigation_id`. Returns how many
    /// were hit, so the route can report a genuine "nothing was running" distinctly from "we
    /// stopped N branches".
    fn cancel_investigation(&self, investigation_id: &str) -> usize {
        let layer_ids: Vec<String> = self
            .by_investigation
            .lock()
            .unwrap()
            .get(investigation_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();

        let by_layer = self.by_layer.lock().unwrap();
        let mut hit = 0;
        for id in &layer_ids {
            if let Some(handle) = by_layer.get(id) {
                handle.cancel();
                hit += 1;
            }
        }
        hit
    }

    /// Cancels every live layer on this process, whatever investigation it belongs to.
    /// Only the kill switch uses this: a freeze that refused new requests while already-
    /// running layers kept hitting third-party services would be a freeze in name only.
    fn cancel_everything(&self) -> usize {
        let by_layer = self.by_layer.lock().unwrap();
        for handle in by_layer.values() {
            handle.cancel();
        }
        by_layer.len()
    }
}

/// The lookup meter's in-flight half: how many tools are *currently* dispatched, per layer,
/// summed per investigation.
///
/// The cumulative half (lookups, cost) is persisted on the investigation row by the engine
/// itself and needs nothing here. In-flight is the opposite kind of number — it is only ever
/// true right now, so it lives in process memory and is rebuilt from nothing on restart, which
/// is correct: after a restart nothing *is* in flight.
///
/// **It is counted from the event stream, not from inside the engine**, because the relay task
/// already sees every frame of every branch and the engine would otherwise need to know about
/// server-side state it has no business holding.
///
/// The trap here is a counter that leaks upward. `ToolStart` increments and `ToolDone`
/// decrements, but a killed layer never emits `ToolDone` for the tools it never reached — they
/// are accounted for in the settle's `reports`, not as frames. A naive pair-matching counter
/// would therefore sit at "3 tools in flight" forever after a kill, on an investigation where
/// nothing is running at all. So a **terminal frame zeroes its layer outright**, which is both
/// the fix and the requirement: a kill must leave in-flight at zero.
#[derive(Default)]
struct InFlightRegistry {
    by_layer: Mutex<HashMap<String, (String, usize)>>,
}

impl InFlightRegistry {
    fn started(&self, investigation_id: &str, layer_id: &str) {
        let mut map = self.by_layer.lock().unwrap();
        let entry = map
            .entry(layer_id.to_string())
            .or_insert((investigation_id.to_string(), 0));
        entry.1 += 1;
    }

    fn finished(&self, layer_id: &str) {
        let mut map = self.by_layer.lock().unwrap();
        if let Some(entry) = map.get_mut(layer_id) {
            entry.1 = entry.1.saturating_sub(1);
        }
    }

    /// A layer settled, however it settled. See the struct doc: this is the only thing that
    /// makes the gauge honest after a kill.
    fn layer_done(&self, layer_id: &str) {
        self.by_layer.lock().unwrap().remove(layer_id);
    }

    fn count(&self, investigation_id: &str) -> usize {
        self.by_layer
            .lock()
            .unwrap()
            .values()
            .filter(|(inv, _)| inv == investigation_id)
            .map(|(_, n)| *n)
            .sum()
    }
}

/// Shared state for every `/api/ozint/*` route, held in [`crate::state::AppState`].
#[derive(Default)]
pub struct OzintState {
    cancels: CancelRegistry,
    in_flight: InFlightRegistry,
    investigations: Mutex<HashMap<String, InvestigationRuntime>>,
}

impl OzintState {
    /// Registers `handle` once a layer's real id is known. See [`CancelRegistry`]'s doc for
    /// why this can't happen any earlier.
    pub fn register_cancel(&self, investigation_id: &str, layer_id: &str, handle: CancelHandle) {
        self.cancels.register(investigation_id, layer_id, handle);
    }

    /// Removes a settled layer's handle. Must be called exactly once per fired layer, from a
    /// codepath that runs regardless of whether the SSE stream is still being read (see
    /// `fire.rs`) — a `CancelHandle` outliving its layer forever is the leak this exists to
    /// prevent.
    pub fn remove_cancel(&self, investigation_id: &str, layer_id: &str) {
        self.cancels.remove(investigation_id, layer_id);
    }

    pub fn cancel_layer(&self, layer_id: &str) -> bool {
        self.cancels.cancel_layer(layer_id)
    }

    pub fn cancel_investigation(&self, investigation_id: &str) -> usize {
        self.cancels.cancel_investigation(investigation_id)
    }

    /// Every live layer, everywhere. See [`CancelRegistry::cancel_everything`] — this exists
    /// for the kill switch and should not grow other callers.
    pub fn cancel_all(&self) -> usize {
        self.cancels.cancel_everything()
    }

    /// Folds one relayed frame into the in-flight gauge. Called from the `fire.rs` relay task
    /// for every event of every branch — see [`InFlightRegistry`] for why a terminal frame
    /// zeroes rather than decrements.
    pub fn observe(&self, investigation_id: &str, event: &ozint::runtime::LayerEvent) {
        use ozint::runtime::LayerEvent;
        match event {
            LayerEvent::ToolStart { layer_id, .. } => {
                self.in_flight.started(investigation_id, layer_id)
            }
            LayerEvent::ToolDone { layer_id, .. } => self.in_flight.finished(layer_id),
            other if other.is_terminal() => {
                if let Some(layer_id) = other.layer_id() {
                    self.in_flight.layer_done(layer_id);
                }
            }
            _ => {}
        }
    }

    /// Tools dispatched and not yet finished, across every branch of one investigation.
    pub fn in_flight(&self, investigation_id: &str) -> usize {
        self.in_flight.count(investigation_id)
    }

    /// The shared `(VisitedSet, ToolHealth)` pair for one investigation, creating it (empty)
    /// the first time this process sees that investigation id. Callers still owe the visited
    /// set a rebuild from the stored tree before firing — see `fire.rs`.
    pub fn investigation_runtime(
        &self,
        investigation_id: &str,
    ) -> (Arc<Mutex<VisitedSet>>, Arc<ToolHealth>) {
        let mut investigations = self.investigations.lock().unwrap();
        let runtime = investigations
            .entry(investigation_id.to_string())
            .or_insert_with(|| InvestigationRuntime {
                visited: Arc::new(Mutex::new(VisitedSet::new())),
                health: Arc::new(ToolHealth::new()),
            });
        (runtime.visited.clone(), runtime.health.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozint::fetch::CancelHandle;

    #[test]
    fn cancel_by_layer_hits_a_registered_handle_and_reports_the_unknown_one() {
        let state = OzintState::default();
        let (handle, signal) = CancelHandle::new();
        state.register_cancel("inv-1", "layer-1", handle);

        assert!(state.cancel_layer("layer-1"));
        assert!(signal.is_cancelled());
        assert!(!state.cancel_layer("layer-does-not-exist"));
    }

    #[test]
    fn cancel_by_investigation_hits_every_branch_and_only_that_investigation() {
        let state = OzintState::default();
        let (handle_a, signal_a) = CancelHandle::new();
        let (handle_b, signal_b) = CancelHandle::new();
        let (handle_other, signal_other) = CancelHandle::new();
        state.register_cancel("inv-1", "layer-a", handle_a);
        state.register_cancel("inv-1", "layer-b", handle_b);
        state.register_cancel("inv-2", "layer-c", handle_other);

        let hit = state.cancel_investigation("inv-1");

        assert_eq!(hit, 2);
        assert!(signal_a.is_cancelled());
        assert!(signal_b.is_cancelled());
        assert!(
            !signal_other.is_cancelled(),
            "a different investigation must not be touched"
        );
    }

    #[test]
    fn cancel_investigation_with_nothing_registered_reports_zero() {
        let state = OzintState::default();
        assert_eq!(state.cancel_investigation("nobody-home"), 0);
    }

    #[test]
    fn remove_cancel_makes_a_later_cancel_report_not_found() {
        let state = OzintState::default();
        let (handle, _signal) = CancelHandle::new();
        state.register_cancel("inv-1", "layer-1", handle);
        state.remove_cancel("inv-1", "layer-1");

        assert!(!state.cancel_layer("layer-1"));
        assert_eq!(
            state.cancel_investigation("inv-1"),
            0,
            "a removed layer must not still count toward its investigation"
        );
    }

    // ── The lookup meter: the in-flight gauge ─────────────────────────────────────────

    use ozint::runtime::LayerEvent;

    fn tool_start(layer_id: &str) -> LayerEvent {
        LayerEvent::ToolStart {
            layer_id: layer_id.into(),
            tool_id: "wmn-probe".into(),
            label: "WhatsMyName".into(),
            gated: false,
        }
    }

    fn tool_done(layer_id: &str) -> LayerEvent {
        LayerEvent::ToolDone {
            layer_id: layer_id.into(),
            report: ozint::outcome::ToolReport::new(
                "wmn-probe",
                "WhatsMyName",
                ozint::outcome::ToolOutcome::OkWithResults { count: 14 },
                12,
                false,
                "queried the site list",
            ),
        }
    }

    #[test]
    fn in_flight_rises_and_falls_with_the_tools() {
        let state = OzintState::default();
        assert_eq!(state.in_flight("inv-1"), 0);

        state.observe("inv-1", &tool_start("layer-a"));
        state.observe("inv-1", &tool_start("layer-a"));
        assert_eq!(state.in_flight("inv-1"), 2);

        state.observe("inv-1", &tool_done("layer-a"));
        assert_eq!(state.in_flight("inv-1"), 1);
    }

    #[test]
    fn a_killed_layer_zeroes_its_in_flight_instead_of_leaking_it_forever() {
        // The bug this guards: a cancelled layer never emits ToolDone for the tools it never
        // reached — they are accounted for in the settle's reports, not as frames. Matching
        // starts against dones would leave the gauge pinned at 2 on an investigation where
        // nothing is running.
        let state = OzintState::default();
        state.observe("inv-1", &tool_start("layer-a"));
        state.observe("inv-1", &tool_start("layer-a"));
        assert_eq!(state.in_flight("inv-1"), 2);

        state.observe(
            "inv-1",
            &LayerEvent::LayerAborted {
                layer_id: "layer-a".into(),
                reports: vec![],
            },
        );
        assert_eq!(
            state.in_flight("inv-1"),
            0,
            "a kill must take the gauge to zero"
        );
    }

    #[test]
    fn every_terminal_frame_clears_its_layer_not_just_an_abort() {
        for terminal in [
            LayerEvent::LayerSettled {
                layer_id: "l".into(),
                new_children: 1,
                reports: vec![],
            },
            LayerEvent::LayerEmpty {
                layer_id: "l".into(),
                reports: vec![],
            },
            LayerEvent::LayerDegraded {
                layer_id: "l".into(),
                new_children: 0,
                reports: vec![],
            },
            LayerEvent::LayerFailed {
                layer_id: "l".into(),
                reports: vec![],
            },
            LayerEvent::LayerAborted {
                layer_id: "l".into(),
                reports: vec![],
            },
        ] {
            let state = OzintState::default();
            state.observe("inv-1", &tool_start("l"));
            state.observe("inv-1", &terminal);
            assert_eq!(state.in_flight("inv-1"), 0, "leaked after {terminal:?}");
        }
    }

    #[test]
    fn branches_of_one_investigation_sum_and_other_investigations_do_not() {
        let state = OzintState::default();
        state.observe("inv-1", &tool_start("layer-a"));
        state.observe("inv-1", &tool_start("layer-b"));
        state.observe("inv-2", &tool_start("layer-c"));

        assert_eq!(
            state.in_flight("inv-1"),
            2,
            "concurrent branches share one gauge"
        );
        assert_eq!(state.in_flight("inv-2"), 1);

        state.observe(
            "inv-1",
            &LayerEvent::LayerSettled {
                layer_id: "layer-a".into(),
                new_children: 0,
                reports: vec![],
            },
        );
        assert_eq!(
            state.in_flight("inv-1"),
            1,
            "one branch settling must not zero its sibling"
        );
    }

    #[test]
    fn a_late_summary_frame_does_not_disturb_the_gauge() {
        // Summary arrives *after* the terminal frame by design. It must not resurrect a count.
        let state = OzintState::default();
        state.observe("inv-1", &tool_start("layer-a"));
        state.observe(
            "inv-1",
            &LayerEvent::LayerSettled {
                layer_id: "layer-a".into(),
                new_children: 1,
                reports: vec![],
            },
        );
        state.observe(
            "inv-1",
            &LayerEvent::Summary {
                layer_id: "layer-a".into(),
                text: "x".into(),
                fallback: true,
            },
        );
        assert_eq!(state.in_flight("inv-1"), 0);
    }

    #[test]
    fn a_stray_tool_done_never_underflows() {
        let state = OzintState::default();
        state.observe("inv-1", &tool_done("layer-a"));
        assert_eq!(state.in_flight("inv-1"), 0);
    }

    #[test]
    fn investigation_runtime_is_created_once_and_reused() {
        let state = OzintState::default();
        let (visited_a, health_a) = state.investigation_runtime("inv-1");
        let (visited_b, health_b) = state.investigation_runtime("inv-1");

        assert!(
            Arc::ptr_eq(&visited_a, &visited_b),
            "the same investigation must reuse the same VisitedSet"
        );
        assert!(
            Arc::ptr_eq(&health_a, &health_b),
            "the same investigation must reuse the same ToolHealth"
        );

        let (visited_other, _) = state.investigation_runtime("inv-2");
        assert!(
            !Arc::ptr_eq(&visited_a, &visited_other),
            "a different investigation must get its own VisitedSet"
        );
    }
}
