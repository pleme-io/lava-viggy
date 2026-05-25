//! lava-viggy — typed PromessaController surface for the lava-suite.
//!
//! Operationalizes theory/CONTINUOUS-SOLUTION-MACHINE.md.
//!
//! ## The 7-beat Viggy tick
//!
//! ```text
//! ┌──────────┐
//! │ Observe  │  read live state
//! └────┬─────┘
//!      ▼
//! ┌──────────┐
//! │  Diff    │  declared vs observed
//! └────┬─────┘
//!      ▼
//! ┌──────────┐
//! │ Classify │  → Severity (Cosmetic/Functional/Critical)
//! └────┬─────┘
//!      ▼
//! ┌──────────┐
//! │  Decide  │  RemediationAction via AnomalyRouter
//! └────┬─────┘
//!      ▼
//! ┌──────────┐
//! │   Act    │  reconverge / hold / escalate
//! └────┬─────┘
//!      ▼
//! ┌──────────┐
//! │  Attest  │  append typed OutcomeChain receipt
//! └────┬─────┘
//!      ▼
//! ┌──────────┐
//! │   Tick   │  requeue / schedule next observation
//! └──────────┘
//! ```
//!
//! ## Solid abstractions
//!
//! - [`PromessaController`] — trait every controller in the suite
//!   implements. One typed method per beat; default impls let
//!   consumers override only what's non-standard.
//! - [`Beat`] — typed enum of the seven beats. Used in receipts +
//!   diagnostics + telemetry.
//! - [`BeatOutcome`] — what one beat returned + which beat ran.
//! - [`TickReport`] — full record of one tick (sequence of typed
//!   beat outcomes + final phase + total duration).
//! - [`ViggyEngine`] — composes a PromessaController + an
//!   AnomalyRouter + a RemediationPolicy. One `tick()` call drives
//!   every beat in order and produces a [`TickReport`].

#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use lava_anomaly::{AnomalyRouter, LavaAnomaly, RemediationAction, RemediationPolicy, RoutingDecision};
use lava_drift::{DriftReport, Severity};
use lava_outcome_chain::ResourceAddress;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Beat ───────────────────────────────────────────────────────────

/// One of the seven beats in the Viggy tick. Used in [`BeatOutcome`]
/// + receipts + telemetry tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Beat {
    Observe,
    Diff,
    Classify,
    Decide,
    Act,
    Attest,
    Tick,
}

impl Beat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "Observe",
            Self::Diff => "Diff",
            Self::Classify => "Classify",
            Self::Decide => "Decide",
            Self::Act => "Act",
            Self::Attest => "Attest",
            Self::Tick => "Tick",
        }
    }

    /// The seven beats in canonical order. Useful for verifying that
    /// a [`TickReport`] hit every beat.
    #[must_use]
    pub const fn canonical_order() -> &'static [Beat; 7] {
        &[
            Self::Observe,
            Self::Diff,
            Self::Classify,
            Self::Decide,
            Self::Act,
            Self::Attest,
            Self::Tick,
        ]
    }
}

// ── BeatOutcome + TickReport ──────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeatOutcome {
    pub beat: Beat,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub status: BeatStatus,
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BeatStatus {
    Ok,
    Skipped,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TickReport {
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub source: ResourceAddress,
    pub beats: Vec<BeatOutcome>,
    pub final_phase: TickPhase,
    pub decision: Option<RoutingDecision>,
}

impl TickReport {
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.ended_at - self.started_at
    }

    /// Did every beat run? Sanity check; a healthy tick visits
    /// every beat at least once.
    #[must_use]
    pub fn visited_every_beat(&self) -> bool {
        for canonical in Beat::canonical_order() {
            if !self.beats.iter().any(|b| b.beat == *canonical) {
                return false;
            }
        }
        true
    }
}

/// The terminal phase one tick lands in. Independent from the
/// operator's CRD Phase (which is more granular) — this is just the
/// engine-level "what happened on this tick" classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TickPhase {
    /// No drift, no work needed.
    Stable,
    /// Drift detected; action taken or scheduled.
    Reconverging,
    /// Drift detected; held for operator approval.
    HoldingForApproval,
    /// Anomaly escalated to a NotifyTarget.
    Escalated,
    /// A beat returned a typed error.
    Failed,
}

impl TickPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "Stable",
            Self::Reconverging => "Reconverging",
            Self::HoldingForApproval => "HoldingForApproval",
            Self::Escalated => "Escalated",
            Self::Failed => "Failed",
        }
    }
}

// ── PromessaController trait ──────────────────────────────────────

/// Every lava controller implements this trait. Each method is one
/// beat. Default impls let consumers override only the non-standard
/// ones.
pub trait PromessaController {
    /// Per-tick context the controller carries between beats.
    type Context;

    /// Read live state. Returns the typed context the rest of the
    /// tick threads through.
    ///
    /// # Errors
    /// Implementation-specific.
    fn observe(
        &self,
        source: &ResourceAddress,
        bindings: &IndexMap<String, String>,
    ) -> Result<Self::Context, ViggyError>;

    /// Compute the drift report from the observed state.
    ///
    /// # Errors
    /// Implementation-specific.
    fn diff(
        &self,
        ctx: &Self::Context,
        bindings: &IndexMap<String, String>,
    ) -> Result<DriftReport, ViggyError>;

    /// Classify severity. Default: `report.max_severity` (or `Cosmetic`
    /// on a clean report).
    fn classify(&self, report: &DriftReport) -> Severity {
        report.max_severity.unwrap_or(Severity::Cosmetic)
    }

    /// Decide what to do. Default: build a [`LavaAnomaly`] +
    /// route through the supplied router.
    ///
    /// # Errors
    /// Returns [`ViggyError::Decide`] on routing failure.
    fn decide<R: AnomalyRouter>(
        &self,
        router: &R,
        policy: &RemediationPolicy,
        source: ResourceAddress,
        severity: Severity,
        report: &DriftReport,
    ) -> Result<(RoutingDecision, LavaAnomaly), ViggyError> {
        let anomaly = LavaAnomaly::new(
            lava_anomaly::AnomalyKind::DriftDetected,
            severity,
            source,
            format!("drift detected: {} field(s)", report.count()),
        );
        let decision = router
            .route(&anomaly, policy)
            .map_err(|e| ViggyError::Decide(e.to_string()))?;
        Ok((decision, anomaly))
    }

    /// Take the action. Returns the [`TickPhase`] the engine should
    /// record + an optional message.
    ///
    /// # Errors
    /// Implementation-specific.
    fn act(
        &self,
        ctx: &Self::Context,
        decision: &RoutingDecision,
        report: &DriftReport,
    ) -> Result<(TickPhase, Option<String>), ViggyError> {
        // Default: encode the standard mapping. Consumers that need
        // custom side effects override this method.
        let _ = (ctx, report); // unused in default impl
        Ok(match decision.action {
            RemediationAction::NoOp | RemediationAction::Alert => (TickPhase::Stable, None),
            RemediationAction::AutoCorrect => (TickPhase::Reconverging, Some("auto-correct enqueued".into())),
            RemediationAction::RequireApproval => (
                TickPhase::HoldingForApproval,
                Some("awaiting LavaApproval CR".into()),
            ),
            RemediationAction::Escalate => (TickPhase::Escalated, Some("escalation notified".into())),
        })
    }

    /// Persist attestation. Default impl: no-op (caller can
    /// override to plug in lava-outcome-chain's OutcomeChain).
    ///
    /// # Errors
    /// Implementation-specific.
    fn attest(
        &self,
        report: &TickReport,
    ) -> Result<(), ViggyError> {
        let _ = report;
        Ok(())
    }

    /// Schedule the next tick. Default: respect
    /// `decision.requeue_after`.
    fn tick_after(&self, decision: &RoutingDecision) -> Duration {
        decision.requeue_after
    }
}

// ── ViggyEngine ────────────────────────────────────────────────────

/// Composes a [`PromessaController`] + an [`AnomalyRouter`] + a
/// [`RemediationPolicy`]. One `tick()` call drives every beat in
/// canonical order and produces a [`TickReport`].
pub struct ViggyEngine<C: PromessaController, R: AnomalyRouter> {
    pub controller: C,
    pub router: R,
    pub policy: RemediationPolicy,
}

impl<C: PromessaController, R: AnomalyRouter> ViggyEngine<C, R> {
    #[must_use]
    pub fn new(controller: C, router: R, policy: RemediationPolicy) -> Self {
        Self {
            controller,
            router,
            policy,
        }
    }

    /// Run one tick. Walks the seven beats in canonical order; on
    /// the first failed beat, the remaining beats are recorded as
    /// `BeatStatus::Skipped` and the report's final_phase is `Failed`.
    ///
    /// # Errors
    /// Returns [`ViggyError`] only when a beat fails BEFORE the
    /// report can be assembled. Individual beat failures show up in
    /// the [`TickReport`] as `BeatStatus::Failed` and don't return Err.
    pub fn tick(
        &self,
        source: ResourceAddress,
        bindings: IndexMap<String, String>,
    ) -> TickReport {
        let started_at = Utc::now();
        let mut beats: Vec<BeatOutcome> = Vec::with_capacity(7);
        let mut decision: Option<RoutingDecision> = None;
        let mut final_phase = TickPhase::Stable;

        // Beat 1: Observe.
        let observe_started = Utc::now();
        let ctx = match self.controller.observe(&source, &bindings) {
            Ok(ctx) => {
                beats.push(beat_ok(Beat::Observe, observe_started, None));
                ctx
            }
            Err(e) => {
                beats.push(beat_failed(Beat::Observe, observe_started, e.to_string()));
                skip_remaining(&mut beats, &[Beat::Diff, Beat::Classify, Beat::Decide, Beat::Act, Beat::Attest, Beat::Tick]);
                return finish_report(started_at, source, beats, TickPhase::Failed, None);
            }
        };

        // Beat 2: Diff.
        let diff_started = Utc::now();
        let report = match self.controller.diff(&ctx, &bindings) {
            Ok(r) => {
                beats.push(beat_ok(Beat::Diff, diff_started, Some(format!("{} drifted field(s)", r.count()))));
                r
            }
            Err(e) => {
                beats.push(beat_failed(Beat::Diff, diff_started, e.to_string()));
                skip_remaining(&mut beats, &[Beat::Classify, Beat::Decide, Beat::Act, Beat::Attest, Beat::Tick]);
                return finish_report(started_at, source, beats, TickPhase::Failed, None);
            }
        };

        // Beat 3: Classify.
        let classify_started = Utc::now();
        let severity = self.controller.classify(&report);
        beats.push(beat_ok(Beat::Classify, classify_started, Some(severity.as_str().into())));

        // Beat 4: Decide.
        let decide_started = Utc::now();
        let (rd, _anomaly) = match self.controller.decide(&self.router, &self.policy, source.clone(), severity, &report) {
            Ok(pair) => {
                beats.push(beat_ok(Beat::Decide, decide_started, Some(format!("{:?}", pair.0.action))));
                pair
            }
            Err(e) => {
                beats.push(beat_failed(Beat::Decide, decide_started, e.to_string()));
                skip_remaining(&mut beats, &[Beat::Act, Beat::Attest, Beat::Tick]);
                return finish_report(started_at, source, beats, TickPhase::Failed, None);
            }
        };
        decision = Some(rd.clone());

        // Beat 5: Act.
        let act_started = Utc::now();
        match self.controller.act(&ctx, &rd, &report) {
            Ok((phase, msg)) => {
                beats.push(beat_ok(Beat::Act, act_started, msg));
                final_phase = phase;
            }
            Err(e) => {
                beats.push(beat_failed(Beat::Act, act_started, e.to_string()));
                skip_remaining(&mut beats, &[Beat::Attest, Beat::Tick]);
                return finish_report(started_at, source, beats, TickPhase::Failed, decision);
            }
        }

        // Beat 6: Attest (preliminary — full report sealed after Beat 7).
        let attest_started = Utc::now();
        // We can only attest the partial report; the consumer's
        // attest impl typically just records what's known. Final
        // report seal happens implicitly via the return value.
        let pre_report = TickReport {
            started_at,
            ended_at: Utc::now(),
            source: source.clone(),
            beats: beats.clone(),
            final_phase,
            decision: decision.clone(),
        };
        match self.controller.attest(&pre_report) {
            Ok(()) => beats.push(beat_ok(Beat::Attest, attest_started, None)),
            Err(e) => {
                beats.push(beat_failed(Beat::Attest, attest_started, e.to_string()));
                // Attest failure isn't fatal for the next tick — we
                // still report what happened + tick again.
            }
        }

        // Beat 7: Tick (record the requeue delay).
        let tick_started = Utc::now();
        let requeue = self.controller.tick_after(&rd);
        beats.push(beat_ok(
            Beat::Tick,
            tick_started,
            Some(format!("requeue in {}s", requeue.num_seconds())),
        ));

        finish_report(started_at, source, beats, final_phase, decision)
    }
}

fn beat_ok(beat: Beat, started_at: DateTime<Utc>, msg: Option<String>) -> BeatOutcome {
    BeatOutcome {
        beat,
        started_at,
        ended_at: Utc::now(),
        status: BeatStatus::Ok,
        message: msg,
    }
}

fn beat_failed(beat: Beat, started_at: DateTime<Utc>, msg: String) -> BeatOutcome {
    BeatOutcome {
        beat,
        started_at,
        ended_at: Utc::now(),
        status: BeatStatus::Failed,
        message: Some(msg),
    }
}

fn skip_remaining(beats: &mut Vec<BeatOutcome>, remaining: &[Beat]) {
    let now = Utc::now();
    for b in remaining {
        beats.push(BeatOutcome {
            beat: *b,
            started_at: now,
            ended_at: now,
            status: BeatStatus::Skipped,
            message: None,
        });
    }
}

fn finish_report(
    started_at: DateTime<Utc>,
    source: ResourceAddress,
    beats: Vec<BeatOutcome>,
    final_phase: TickPhase,
    decision: Option<RoutingDecision>,
) -> TickReport {
    TickReport {
        started_at,
        ended_at: Utc::now(),
        source,
        beats,
        final_phase,
        decision,
    }
}

#[derive(Debug, Error)]
pub enum ViggyError {
    #[error("observe: {0}")]
    Observe(String),
    #[error("diff: {0}")]
    Diff(String),
    #[error("decide: {0}")]
    Decide(String),
    #[error("act: {0}")]
    Act(String),
    #[error("attest: {0}")]
    Attest(String),
}

// Local helper for severity stringification.
trait SeverityStr {
    fn as_str(self) -> &'static str;
}

impl SeverityStr for Severity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cosmetic => "cosmetic",
            Self::Functional => "functional",
            Self::Critical => "critical",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lava_anomaly::{PolicyRouter, RemediationPolicy};
    use lava_drift::{ChangeKind, DriftDetector, DriftFinding, MockPlanner, PlannerBackend, PlannerError};

    struct TestController {
        detector_findings: Vec<DriftFinding>,
        observe_fails: bool,
    }

    impl PromessaController for TestController {
        type Context = ();

        fn observe(
            &self,
            _source: &ResourceAddress,
            _bindings: &IndexMap<String, String>,
        ) -> Result<(), ViggyError> {
            if self.observe_fails {
                Err(ViggyError::Observe("simulated outage".into()))
            } else {
                Ok(())
            }
        }

        fn diff(
            &self,
            _ctx: &(),
            bindings: &IndexMap<String, String>,
        ) -> Result<DriftReport, ViggyError> {
            let detector = DriftDetector::new(MockPlanner::new(self.detector_findings.clone()));
            detector
                .scan("src", bindings)
                .map_err(|e| ViggyError::Diff(e.to_string()))
        }
    }

    fn finding(kind: ChangeKind, attr: &str) -> DriftFinding {
        DriftFinding {
            address: "aws_vpc.main".into(),
            attribute: attr.into(),
            change: kind,
            observed: None,
            declared: None,
        }
    }

    fn engine(findings: Vec<DriftFinding>, observe_fails: bool) -> ViggyEngine<TestController, PolicyRouter> {
        ViggyEngine::new(
            TestController { detector_findings: findings, observe_fails },
            PolicyRouter,
            RemediationPolicy::default(),
        )
    }

    #[test]
    fn clean_tick_visits_every_beat_and_lands_stable() {
        let engine = engine(vec![], false);
        let report = engine.tick(ResourceAddress::new("rio", "n", "x"), IndexMap::new());
        assert!(report.visited_every_beat());
        assert_eq!(report.final_phase, TickPhase::Stable);
    }

    #[test]
    fn functional_drift_tick_lands_reconverging() {
        let engine = engine(vec![finding(ChangeKind::Update, "cidr_block")], false);
        let report = engine.tick(ResourceAddress::new("rio", "n", "x"), IndexMap::new());
        assert_eq!(report.final_phase, TickPhase::Reconverging);
    }

    #[test]
    fn critical_drift_tick_lands_holding_for_approval() {
        let engine = engine(vec![finding(ChangeKind::Delete, "*")], false);
        let report = engine.tick(ResourceAddress::new("rio", "n", "x"), IndexMap::new());
        assert_eq!(report.final_phase, TickPhase::HoldingForApproval);
    }

    #[test]
    fn observe_failure_short_circuits_and_marks_remaining_skipped() {
        let engine = engine(vec![], true);
        let report = engine.tick(ResourceAddress::new("rio", "n", "x"), IndexMap::new());
        assert_eq!(report.final_phase, TickPhase::Failed);
        assert_eq!(report.beats[0].beat, Beat::Observe);
        assert_eq!(report.beats[0].status, BeatStatus::Failed);
        let skipped: Vec<_> = report
            .beats
            .iter()
            .filter(|b| b.status == BeatStatus::Skipped)
            .map(|b| b.beat)
            .collect();
        assert_eq!(skipped.len(), 6); // diff..tick
    }

    #[test]
    fn beat_canonical_order_returns_seven_beats() {
        assert_eq!(Beat::canonical_order().len(), 7);
        assert_eq!(Beat::canonical_order()[0], Beat::Observe);
        assert_eq!(Beat::canonical_order()[6], Beat::Tick);
    }

    #[test]
    fn tick_report_serializes_with_typed_phase_string() {
        let engine = engine(vec![], false);
        let report = engine.tick(ResourceAddress::new("rio", "n", "x"), IndexMap::new());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""finalPhase":"Stable""#));
    }

    #[test]
    fn tick_duration_is_non_negative() {
        let engine = engine(vec![], false);
        let report = engine.tick(ResourceAddress::new("rio", "n", "x"), IndexMap::new());
        assert!(report.duration().num_milliseconds() >= 0);
    }
}
