//! Compliance PromessaController **skeleton** — the F-4 audit-readiness
//! reconcile loop, scaffolded.
//!
//! Implements the seven-beat [`crate::PromessaController`] against a
//! [`crate::compliance::CompliancePromessa`]. The two beats that touch
//! the outside world are wired to the REAL substrate:
//!
//! - **Observe** — reads each arm through a mockable [`ComplianceObserver`]
//!   seam (the Environment trait). Tests inject a mock; production
//!   injects a KubeApi/tameshi/shinryu reader.
//! - **Attest** — appends a typed `Receipt<CompliancePayload>` to the
//!   real [`lava_outcome_chain::OutcomeChain`] (BLAKE3-linked, optionally
//!   Ed25519-signed). This is what `kensa verify outcome-chain` walks.
//!
//! The two decision beats are **honestly stubbed** — per the
//! TYPED-SPEC-TRIPLET no-silent-stub rule, they return a typed
//! [`BeatIntent::Design`] marker, never a placeholder `Ok(success)`:
//!
//! - **Decide** — the RemediationPolicy → RoutingDecision mapping for a
//!   compliance violation is NOT YET WIRED. `decide_intent` returns
//!   [`BeatIntent::Design`] so a caller sees the gap mechanically.
//! - **Act** — auto-correcting a control violation (GitOps mTLS
//!   enforce, image-pin bump) is NOT YET WIRED. `act_intent` returns
//!   [`BeatIntent::Design`].
//!
//! ## Tier-honesty (LOAD-BEARING)
//!
//! This is a SCAFFOLD. "Attested" = auditable OutcomeChain provenance,
//! NOT proof-of-correctness. A scaffold tick that has not observed an
//! arm records [`crate::compliance::ArmVerdict::NotYetObserved`] and
//! sets `CompliancePayload::scaffold = true`, so a chain reader can
//! never mistake a scaffold receipt for closed-loop compliance
//! evidence. The closed Decide/Act beats, the FedRAMP-High baseline
//! mapping in `kensa`, and 3PAO acceptance are NAMED GATES.

#![allow(clippy::module_name_repetitions)]

use lava_outcome_chain::{OutcomeChain, OutcomeSink, Receipt, SigningProvider};

use crate::compliance::{
    ArmObservation, ArmOutcome, ArmVerdict, CompliancePayload, CompliancePromessa,
};

// ── ComplianceObserver (the Environment / side-effect seam) ────────

/// The mockable side-effect seam for the Observe beat. Real impls read
/// a live Kubernetes projection / tameshi chain / shinryu snapshot;
/// tests inject a deterministic mock. This trait IS the testability
/// contract (TYPED-SPEC-TRIPLET §3): no compliance tick needs a live
/// cluster or chain to be driven.
pub trait ComplianceObserver {
    /// Observe one arm against its declared source. Returns the typed
    /// verdict + an optional diagnostic.
    ///
    /// # Errors
    /// Backend-specific read failures surface as [`ObserveError`].
    fn observe_arm(
        &self,
        arm_tag: &str,
        observation: Option<&ArmObservation>,
    ) -> Result<(ArmVerdict, Option<String>), ObserveError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ObserveError {
    #[error("observe arm `{arm}`: {reason}")]
    Backend { arm: String, reason: String },
}

/// The scaffold observer: does NOT read any live source. Every arm
/// comes back [`ArmVerdict::NotYetObserved`]. This is the honest
/// default — a scaffold that has no wired observer must not invent a
/// `Holding` verdict. Production replaces it with a real reader.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScaffoldObserver;

impl ComplianceObserver for ScaffoldObserver {
    fn observe_arm(
        &self,
        _arm_tag: &str,
        _observation: Option<&ArmObservation>,
    ) -> Result<(ArmVerdict, Option<String>), ObserveError> {
        Ok((
            ArmVerdict::NotYetObserved,
            Some("scaffold observer — no live source wired".into()),
        ))
    }
}

// ── BeatIntent — the honest-stub marker ────────────────────────────

/// What a not-yet-wired beat *would* do. Returned by the Decide/Act
/// beats instead of a fake `Ok(success)`. LOAD-BEARING: this makes the
/// unimplemented surface visible mechanically (no silent stub, no
/// `todo!()`, no placeholder Ok that reads as success).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeatIntent {
    /// The beat is designed but not wired. Carries the design note so a
    /// caller (or an operator reading a log) sees exactly what is
    /// pending and why.
    Design {
        beat: &'static str,
        note: &'static str,
    },
}

impl BeatIntent {
    /// The Decide beat's honest design marker.
    #[must_use]
    pub const fn decide_pending() -> Self {
        Self::Design {
            beat: "Decide",
            note: "compliance-violation → RemediationPolicy → RoutingDecision mapping \
                   is a NAMED GATE (not wired). No decision is fabricated.",
        }
    }

    /// The Act beat's honest design marker.
    #[must_use]
    pub const fn act_pending() -> Self {
        Self::Design {
            beat: "Act",
            note: "auto-correct of a control violation (GitOps mTLS-enforce / image-pin \
                   bump) is a NAMED GATE (not wired). No action is taken.",
        }
    }
}

// ── ComplianceController ───────────────────────────────────────────

/// The F-4 compliance controller skeleton. Owns the promessa
/// declaration + the Observe seam. The wired beats (Observe, Attest)
/// run against real substrate; the decision beats return a typed
/// [`BeatIntent::Design`] marker.
pub struct ComplianceController<O: ComplianceObserver> {
    promessa: CompliancePromessa,
    observer: O,
}

impl<O: ComplianceObserver> ComplianceController<O> {
    #[must_use]
    pub fn new(promessa: CompliancePromessa, observer: O) -> Self {
        Self { promessa, observer }
    }

    #[must_use]
    pub fn promessa(&self) -> &CompliancePromessa {
        &self.promessa
    }

    /// **Observe beat (wired).** Read every arm through the observer
    /// seam. Returns the per-arm outcomes + whether this is a scaffold
    /// tick (any arm `NotYetObserved`).
    ///
    /// # Errors
    /// Surfaces the first arm observation failure as [`ObserveError`].
    pub fn observe_arms(&self) -> Result<(Vec<ArmOutcome>, bool), ObserveError> {
        let mut outcomes = Vec::with_capacity(self.promessa.arms.len());
        let mut scaffold = false;
        for arm in &self.promessa.arms {
            let (verdict, detail) = self
                .observer
                .observe_arm(&arm.arm, arm.observation.as_ref())?;
            if verdict == ArmVerdict::NotYetObserved {
                scaffold = true;
            }
            outcomes.push(ArmOutcome {
                arm: arm.arm.clone(),
                controls: arm.controls.clone(),
                verdict,
                detail,
            });
        }
        Ok((outcomes, scaffold))
    }

    /// **Decide beat (honest stub).** Returns the typed
    /// [`BeatIntent::Design`] marker — a compliance-violation decision
    /// is a NAMED GATE, never fabricated.
    #[must_use]
    pub fn decide_intent(&self) -> BeatIntent {
        BeatIntent::decide_pending()
    }

    /// **Act beat (honest stub).** Returns the typed
    /// [`BeatIntent::Design`] marker — auto-correct is a NAMED GATE.
    #[must_use]
    pub fn act_intent(&self) -> BeatIntent {
        BeatIntent::act_pending()
    }

    /// **Attest beat (wired).** Build the typed [`CompliancePayload`]
    /// for this tick and append it to the real OutcomeChain. Returns
    /// the sealed [`Receipt`] so the caller can hand its `content_hash`
    /// to `kensa verify`.
    ///
    /// # Errors
    /// Surfaces the spec-hash encode failure or the chain append
    /// failure as [`AttestError`].
    pub fn attest_tick<S, G>(
        &self,
        chain: &mut OutcomeChain<CompliancePayload, S, G>,
        tick_index: u64,
        arm_outcomes: Vec<ArmOutcome>,
        scaffold: bool,
    ) -> Result<Receipt<CompliancePayload>, AttestError>
    where
        S: OutcomeSink<CompliancePayload>,
        G: SigningProvider,
    {
        let spec_hash = self
            .promessa
            .spec_hash()
            .map_err(|e| AttestError::SpecHash(e.to_string()))?;
        let payload = CompliancePayload {
            promessa_name: self.promessa.name.clone(),
            baseline: self.promessa.baseline,
            spec_hash,
            tick_index,
            arm_outcomes,
            scaffold,
        };
        chain
            .append(payload)
            .map_err(|e| AttestError::Append(e.to_string()))
    }

    /// One scaffold tick: Observe → build payload → Attest. Decide/Act
    /// are represented by their typed [`BeatIntent`] markers (returned
    /// alongside the receipt) rather than executed. Composes the wired
    /// beats end-to-end so a test can drive Observe→Attest against a
    /// mock chain.
    ///
    /// # Errors
    /// Surfaces observe / attest failures.
    pub fn scaffold_tick<S, G>(
        &self,
        chain: &mut OutcomeChain<CompliancePayload, S, G>,
        tick_index: u64,
    ) -> Result<ScaffoldTickReport, ComplianceTickError>
    where
        S: OutcomeSink<CompliancePayload>,
        G: SigningProvider,
    {
        let (outcomes, scaffold) = self.observe_arms().map_err(ComplianceTickError::Observe)?;
        let decide = self.decide_intent();
        let act = self.act_intent();
        let receipt = self
            .attest_tick(chain, tick_index, outcomes, scaffold)
            .map_err(ComplianceTickError::Attest)?;
        Ok(ScaffoldTickReport {
            receipt_hash_hex: receipt.content_hash.hex(),
            sequence: receipt.sequence,
            scaffold,
            decide,
            act,
        })
    }
}

/// The typed result of one scaffold tick — the receipt provenance plus
/// the honest markers for the two unwired beats.
#[derive(Clone, Debug)]
pub struct ScaffoldTickReport {
    /// Hex of the sealed receipt's BLAKE3 content hash.
    pub receipt_hash_hex: String,
    /// The receipt's chain sequence number.
    pub sequence: u64,
    /// Whether this tick is a scaffold tick (any arm unobserved).
    pub scaffold: bool,
    /// The Decide beat's honest design marker.
    pub decide: BeatIntent,
    /// The Act beat's honest design marker.
    pub act: BeatIntent,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("spec-hash: {0}")]
    SpecHash(String),
    #[error("append: {0}")]
    Append(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ComplianceTickError {
    #[error(transparent)]
    Observe(#[from] ObserveError),
    #[error(transparent)]
    Attest(#[from] AttestError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::ComplianceBaseline;
    use lava_outcome_chain::{verify_chain, InMemorySink, NoOpVerifier, NoSigning};
    use std::collections::HashMap;

    /// A deterministic mock observer: returns a canned verdict per arm.
    struct MockObserver {
        verdicts: HashMap<String, ArmVerdict>,
    }

    impl MockObserver {
        fn holding_all() -> Self {
            let mut verdicts = HashMap::new();
            for tag in ["sc-8", "ra-5", "audit"] {
                verdicts.insert(tag.to_string(), ArmVerdict::Holding);
            }
            Self { verdicts }
        }
    }

    impl ComplianceObserver for MockObserver {
        fn observe_arm(
            &self,
            arm_tag: &str,
            _observation: Option<&ArmObservation>,
        ) -> Result<(ArmVerdict, Option<String>), ObserveError> {
            Ok((
                self.verdicts
                    .get(arm_tag)
                    .copied()
                    .unwrap_or(ArmVerdict::NotYetObserved),
                None,
            ))
        }
    }

    fn controller_with<O: ComplianceObserver>(obs: O) -> ComplianceController<O> {
        ComplianceController::new(CompliancePromessa::fedramp_high("compliance"), obs)
    }

    #[test]
    fn observe_to_attest_produces_a_verifiable_outcome_chain_entry() {
        let ctrl = controller_with(MockObserver::holding_all());
        let mut chain =
            OutcomeChain::new(InMemorySink::<CompliancePayload>::default(), NoSigning);

        let report = ctrl.scaffold_tick(&mut chain, 0).expect("tick");

        // A real receipt was appended to the real chain.
        let receipts = chain.read_all().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].sequence, 0);
        assert!(receipts[0].prev_hash.is_genesis());
        // Genesis receipt binds to the spec hash of exactly this promessa.
        assert_eq!(
            receipts[0].payload.spec_hash,
            ctrl.promessa().spec_hash().unwrap()
        );
        // The chain verifies end-to-end under the matching verifier.
        verify_chain(&receipts, &NoOpVerifier).expect("chain verifies");
        assert_eq!(report.sequence, 0);
        // All arms Holding ⇒ not a scaffold tick.
        assert!(!report.scaffold);
    }

    #[test]
    fn scaffold_observer_records_notyetobserved_and_flags_the_tick() {
        let ctrl = controller_with(ScaffoldObserver);
        let mut chain =
            OutcomeChain::new(InMemorySink::<CompliancePayload>::default(), NoSigning);

        let report = ctrl.scaffold_tick(&mut chain, 0).expect("tick");

        // The tick is honestly flagged as a scaffold tick.
        assert!(report.scaffold);
        let receipts = chain.read_all().unwrap();
        assert!(receipts[0].payload.scaffold);
        // Every arm records NotYetObserved — NOT a fake Holding.
        for outcome in &receipts[0].payload.arm_outcomes {
            assert_eq!(outcome.verdict, ArmVerdict::NotYetObserved);
        }
    }

    #[test]
    fn decide_beat_returns_the_typed_design_marker_not_a_fake_ok() {
        let ctrl = controller_with(ScaffoldObserver);
        let intent = ctrl.decide_intent();
        match intent {
            BeatIntent::Design { beat, .. } => assert_eq!(beat, "Decide"),
        }
    }

    #[test]
    fn act_beat_returns_the_typed_design_marker_not_a_fake_ok() {
        let ctrl = controller_with(ScaffoldObserver);
        let intent = ctrl.act_intent();
        match intent {
            BeatIntent::Design { beat, .. } => assert_eq!(beat, "Act"),
        }
    }

    #[test]
    fn scaffold_tick_surfaces_both_design_markers() {
        let ctrl = controller_with(ScaffoldObserver);
        let mut chain =
            OutcomeChain::new(InMemorySink::<CompliancePayload>::default(), NoSigning);
        let report = ctrl.scaffold_tick(&mut chain, 0).expect("tick");
        assert_eq!(report.decide, BeatIntent::decide_pending());
        assert_eq!(report.act, BeatIntent::act_pending());
    }

    #[test]
    fn successive_ticks_chain_via_prev_hash() {
        let ctrl = controller_with(MockObserver::holding_all());
        let mut chain =
            OutcomeChain::new(InMemorySink::<CompliancePayload>::default(), NoSigning);
        ctrl.scaffold_tick(&mut chain, 0).unwrap();
        ctrl.scaffold_tick(&mut chain, 1).unwrap();
        ctrl.scaffold_tick(&mut chain, 2).unwrap();
        let receipts = chain.read_all().unwrap();
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[1].prev_hash, receipts[0].content_hash);
        assert_eq!(receipts[2].prev_hash, receipts[1].content_hash);
        assert_eq!(receipts[2].payload.tick_index, 2);
        verify_chain(&receipts, &NoOpVerifier).unwrap();
    }

    #[test]
    fn baseline_carries_onto_the_receipt() {
        let ctrl = controller_with(MockObserver::holding_all());
        let mut chain =
            OutcomeChain::new(InMemorySink::<CompliancePayload>::default(), NoSigning);
        ctrl.scaffold_tick(&mut chain, 0).unwrap();
        let receipts = chain.read_all().unwrap();
        assert_eq!(receipts[0].payload.baseline, ComplianceBaseline::FedrampHigh);
    }
}
