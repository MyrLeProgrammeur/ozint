//! The LLM implementation of `ozint::classify::ClassifierLlm`.
//!
//! `classify.rs` defines the trait, the system prompt, the ambiguity thresholds and the
//! honest-degradation rules; it deliberately does not name a model. Its own doc says who is
//! meant to supply one: *"a higher layer (`ozint-server`) implements it against the ported
//! the LLM client"*, the same define-the-trait-here / implement-it-one-layer-up seam used
//! elsewhere in this codebase. This file is that higher layer, and until now it did not exist.
//!
//! **What was missing.** `classify_with_llm` was built and tested against four fake LLMs, and
//! then nothing in the repo ever called it — both routes called the deterministic
//! `classify::classify` instead, and no implementation of `ClassifierLlm` existed outside test
//! code. The escalation tier therefore never ran, on any input, ever. It produced no symptom
//! because the deterministic tier always returns something usable by design: a two-word seed
//! like `Acme Industries` simply came back as `Name` with `Directory` as a close alternate and
//! `ClassifyMethod::Deterministic`, which is exactly what it would look like if an LLM had been
//! asked and had agreed. `ClassifyMethod::Llm` and `ClassifyMethod::DeterministicFallback` were
//! unreachable variants.
//!
//! **The egress gate is not optional here.** The text this sends is the analyst's raw seed —
//! frequently a person's name, which is the most identifying thing anyone types into this
//! cockpit. It goes through [`egress::oz_guard`] exactly like a layer summary does, including
//! the kill switch. A refusal is returned as an `Err`, which `classify_with_llm` already knows
//! how to handle: it falls back to the deterministic result and tags it
//! `DeterministicFallback`, never presenting it as LLM-confirmed.

use async_trait::async_trait;
use ozint::classify::ClassifierLlm;
use ozint::egress::{self, OzEgressDecision, OzEgressRequest};
use ozint_llm::{CallOpts, call_llm};

/// Routes `ozint`'s classifier escalation to the LLM, through the OZINT egress gate.
pub struct LlmClassifier {
    /// Sampled from `AppState::freeze` at the moment the seed is classified. A frozen instance
    /// refuses the call rather than making it — same rule the layer summary follows.
    frozen: bool,
}

impl LlmClassifier {
    pub fn new(frozen: bool) -> Self {
        Self { frozen }
    }
}

#[async_trait]
impl ClassifierLlm for LlmClassifier {
    async fn complete(&self, system: &str, user: &str) -> anyhow::Result<String> {
        match egress::oz_guard(&OzEgressRequest::new(user.to_string()).frozen(self.frozen)) {
            OzEgressDecision::Refused(refusal) => {
                // An `Err` rather than a silent deterministic return: the caller distinguishes
                // "we asked and it declined" from "we never asked", and only the caller can
                // tag the result honestly.
                Err(anyhow::anyhow!(
                    "ozint egress gate refused the classification call: {refusal:?}"
                ))
            }
            OzEgressDecision::Allowed(allowed) => {
                let opts = CallOpts {
                    system: Some(system.to_string()),
                    ..Default::default()
                };
                // `call_llm` returns `ozint_core::OzintError`; the trait speaks
                // `anyhow`. The conversion keeps the original as the source so a missing
                // `OZINT_LLM_API_KEY` still reads as a config error, not as a bare string.
                call_llm(&allowed.text, opts)
                    .await
                    .map_err(anyhow::Error::new)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_frozen_classifier_refuses_before_any_llm_attempt() {
        // The property that matters: the seed does not leave the process while frozen. If the
        // gate were skipped this would instead fail on a missing key, which reads the same in
        // a green test run and is not the same thing at all.
        let err = LlmClassifier::new(true)
            .complete("system", "Acme Industries")
            .await
            .expect_err("a frozen classifier must refuse");
        assert!(
            err.to_string().contains("refused"),
            "expected an egress refusal, got: {err}"
        );
    }
}
