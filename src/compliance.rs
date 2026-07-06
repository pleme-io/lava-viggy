//! Compliance promessa — the typed `(defpromessa … :target (Compliance …))`
//! value for the Camelot FedRAMP audit-readiness arm (F-4).
//!
//! This is the **SCAFFOLD** half of the F-4 arm: the typed Compliance
//! promessa *value* + the OutcomeChain *payload* it attests. The
//! controller skeleton that ticks it lives in
//! [`crate::compliance_controller`].
//!
//! ## What this models
//!
//! `theory/CONTINUOUS-SOLUTION-MACHINE.md` §III.1 declares a
//! `PromessaTarget::Compliance(ComplianceTarget)` — a baseline + a
//! control set + an on-violation policy. `theory/CAMELOT-FEDRAMP-COMPLIANCE.md`
//! §3/§6 pins the F-4 arm to a *single* Compliance promessa observed
//! via a composite of three sources, one per compliance arm:
//!
//! | Arm  | Control(s)          | Observation source (F-4 §6 map) |
//! |------|---------------------|---------------------------------|
//! | SC-8 | SC-8, SC-8(1)       | `KubeApi` PeerAuthentication `.spec.mtls.mode == STRICT` (every east-west edge mTLS) |
//! | RA-5 | RA-5, SI-2          | `TameshiHeartbeat` image chain + `Shinryu` CVE snapshot (no unscanned/unsigned image) |
//! | Audit| AU-2, AU-12, CA-7   | the control set itself — `kensa verify outcome-chain` derives ABD/BoE/conmon |
//!
//! ## Tier-honesty (LOAD-BEARING — do not round up)
//!
//! "Attested" here means **auditable OutcomeChain provenance**, NOT
//! proof-of-correctness. Each [`ComplianceArm`] carries an
//! [`ArmObservation`] describing *how* the arm is observed — but the
//! observation itself is produced by the controller's Observe beat
//! against a live source, which is a NAMED GATE, not shipped. The
//! closed reconcile loop, the FedRAMP-High baseline mapping in
//! `kensa`, and 3PAO acceptance are all named gates. A 3PAO may still
//! require human-authored ABD/BoE regardless of this chain.
//!
//! ## Vocabulary bridge
//!
//! `lava-viggy` is dependency-light (it does not pull `tatara-lisp`),
//! so instead of `#[derive(TataraDomain)]` the authoring surface is
//! the [`defcompliance_promessa!`] macro — a `(defpromessa …)`-shaped
//! form that builds a [`CompliancePromessa`] from a terse declaration.
//! When this crate later adopts `tatara-lisp` the macro is replaced by
//! the derive without changing the value shape.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use chrono::Duration;
use lava_anomaly::EscalationLadder;
use lava_outcome_chain::{ContentHash, Payload, ResourceAddress};
use serde::{Deserialize, Serialize};

// ── ControlId ──────────────────────────────────────────────────────

/// A NIST SP 800-53 control identifier as it appears in the FedRAMP
/// baseline (e.g. `SC-8`, `SC-8(1)`, `RA-5`, `AU-12`). Kept as a typed
/// newtype so a control set is a set of typed values, not free text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlId(pub String);

impl ControlId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ControlId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ComplianceBaseline ─────────────────────────────────────────────

/// The FedRAMP impact baseline the promessa asserts. The
/// baseline→control-set expansion (and the `kensa` baseline mapping)
/// is a NAMED GATE — this enum only names which baseline is claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceBaseline {
    FedrampLow,
    FedrampModerate,
    FedrampHigh,
}

impl ComplianceBaseline {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FedrampLow => "fedramp-low",
            Self::FedrampModerate => "fedramp-moderate",
            Self::FedrampHigh => "fedramp-high",
        }
    }
}

// ── ArmObservation ─────────────────────────────────────────────────

/// The typed *description* of how an arm is observed. Mirrors the F-4
/// §6 control→attestation map's `Attested via` column. This names the
/// source; producing the observation is the controller's Observe beat
/// (a NAMED GATE).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum ArmObservation {
    /// Observe a projection of a live Kubernetes object (F-4 §6:
    /// PeerAuthentication `.spec.mtls.mode`, NetworkPolicy
    /// `.spec.policyTypes`).
    KubeApi {
        /// Group/version/resource, e.g. `security.istio.io/v1/PeerAuthentication`.
        gvr: String,
        /// JSONPath-style projection, e.g. `.spec.mtls.mode`.
        projection: String,
        /// The value that satisfies the control, e.g. `STRICT`.
        expect: String,
    },
    /// Observe the tameshi image-attestation heartbeat chain (F-4 §6:
    /// signed-image evidence). Peer of this crate's OutcomeChain.
    TameshiHeartbeat {
        /// The attestation chain name, e.g. `camelot-attest`.
        chain: String,
        /// The attested layer, e.g. `Build`.
        layer: String,
    },
    /// Observe a shinryu CVE snapshot (F-4 §6: `cve_open_by_pin`).
    Shinryu {
        /// The shinryu query, e.g. `cve_open_by_pin`.
        query: String,
    },
}

// ── ComplianceArm ──────────────────────────────────────────────────

/// One compliance arm: a set of controls plus how they're observed.
/// The three F-4 arms are [`ComplianceArm::sc8`], [`ComplianceArm::ra5`],
/// and [`ComplianceArm::audit_controls`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceArm {
    /// Short arm tag surfaced in receipts + telemetry, e.g. `sc-8`.
    pub arm: String,
    /// Human phrase, e.g. "every east-west edge is mTLS".
    pub intent: String,
    /// The typed controls this arm attests.
    pub controls: Vec<ControlId>,
    /// How the arm is observed. `None` = the arm is the control set
    /// itself (the audit-controls arm), derived by `kensa verify`.
    #[serde(default)]
    pub observation: Option<ArmObservation>,
}

impl ComplianceArm {
    /// F-4 ARM 1 — SC-8 / SC-8(1): every east-west edge is mTLS.
    #[must_use]
    pub fn sc8() -> Self {
        Self {
            arm: "sc-8".into(),
            intent: "every east-west edge is mTLS (a plaintext hop is unrepresentable)".into(),
            controls: vec![ControlId::new("SC-8"), ControlId::new("SC-8(1)")],
            observation: Some(ArmObservation::KubeApi {
                gvr: "security.istio.io/v1/PeerAuthentication".into(),
                projection: ".spec.mtls.mode".into(),
                expect: "STRICT".into(),
            }),
        }
    }

    /// F-4 ARM 2 — RA-5 / SI-2: no unscanned / unsigned image.
    #[must_use]
    pub fn ra5() -> Self {
        Self {
            arm: "ra-5".into(),
            intent: "no unscanned or unsigned image enters the trusted zone".into(),
            controls: vec![ControlId::new("RA-5"), ControlId::new("SI-2")],
            observation: Some(ArmObservation::TameshiHeartbeat {
                chain: "camelot-attest".into(),
                layer: "Build".into(),
            }),
        }
    }

    /// F-4 ARM 3 — AU-2 / AU-12 / CA-7: the audit-control set. This
    /// arm's evidence is the OutcomeChain projection itself — ABD/BoE/
    /// conmon derived by `kensa verify outcome-chain`.
    #[must_use]
    pub fn audit_controls() -> Self {
        Self {
            arm: "audit".into(),
            intent: "continuous-monitoring evidence is derived, not authored".into(),
            controls: vec![
                ControlId::new("AU-2"),
                ControlId::new("AU-12"),
                ControlId::new("CA-7"),
            ],
            observation: None,
        }
    }
}

// ── CompliancePromessa ─────────────────────────────────────────────

/// The typed Compliance promessa value — the `(defpromessa … :target
/// (Compliance …))` datum. This is a *declaration*, not a running
/// loop; the controller in [`crate::compliance_controller`] consumes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePromessa {
    /// Promessa name, e.g. `camelot-fedramp-high`.
    pub name: String,
    /// Kubernetes namespace the promessa is scoped to.
    pub namespace: String,
    /// The impact baseline claimed.
    pub baseline: ComplianceBaseline,
    /// The three F-4 arms (SC-8, RA-5, audit-controls).
    pub arms: Vec<ComplianceArm>,
    /// The escalation ladder walked when a control violation is
    /// classified `Critical` and the policy resolves to `Escalate`.
    /// Reuses `lava-anomaly`'s typed ladder — never a bespoke one.
    #[serde(default)]
    pub escalation: Option<EscalationLadder>,
    /// How often the controller should tick this promessa.
    #[serde(with = "duration_seconds")]
    pub reconcile_every: Duration,
}

impl CompliancePromessa {
    /// The canonical Camelot FedRAMP-High promessa: the three F-4 arms
    /// at a 5-minute reconcile interval (matches CAMELOT-FEDRAMP §3.1
    /// `:interval 5m`).
    #[must_use]
    pub fn camelot_fedramp_high(namespace: impl Into<String>) -> Self {
        Self {
            name: "camelot-fedramp-high".into(),
            namespace: namespace.into(),
            baseline: ComplianceBaseline::FedrampHigh,
            arms: vec![
                ComplianceArm::sc8(),
                ComplianceArm::ra5(),
                ComplianceArm::audit_controls(),
            ],
            escalation: None,
            reconcile_every: Duration::minutes(5),
        }
    }

    /// The flattened, de-duplicated typed control set across every arm
    /// — the baseline the auditor sees.
    #[must_use]
    pub fn control_set(&self) -> Vec<ControlId> {
        let mut seen: BTreeMap<String, ControlId> = BTreeMap::new();
        for arm in &self.arms {
            for c in &arm.controls {
                seen.entry(c.0.clone()).or_insert_with(|| c.clone());
            }
        }
        seen.into_values().collect()
    }

    /// BLAKE3 of the canonical spec — the OutcomeChain genesis anchor
    /// (CSM §III.3: `prev_receipt_hash = blake3(canonical(PromessaSpec))`).
    ///
    /// # Errors
    /// Surfaces canonical-encoding failures.
    pub fn spec_hash(&self) -> Result<ContentHash, serde_json::Error> {
        ContentHash::of_value(self)
    }

    /// The typed resource address for this promessa (cluster is left to
    /// the caller; namespace + name come from the spec).
    #[must_use]
    pub fn address(&self, cluster: impl Into<String>) -> ResourceAddress {
        ResourceAddress::new(cluster, self.namespace.clone(), self.name.clone())
    }

    /// Structural validation: the F-4 arm requires the three canonical
    /// arms present + a non-empty control set + a positive reconcile
    /// interval. Returns the first structural gap as a typed error.
    ///
    /// # Errors
    /// [`ComplianceSpecError`] naming the structural gap.
    pub fn validate(&self) -> Result<(), ComplianceSpecError> {
        if self.name.trim().is_empty() {
            return Err(ComplianceSpecError::EmptyName);
        }
        if self.reconcile_every <= Duration::zero() {
            return Err(ComplianceSpecError::NonPositiveInterval);
        }
        if self.arms.is_empty() {
            return Err(ComplianceSpecError::NoArms);
        }
        for arm in &self.arms {
            if arm.controls.is_empty() {
                return Err(ComplianceSpecError::ArmWithoutControls {
                    arm: arm.arm.clone(),
                });
            }
        }
        if self.control_set().is_empty() {
            return Err(ComplianceSpecError::EmptyControlSet);
        }
        Ok(())
    }
}

/// Typed structural error for a [`CompliancePromessa`]. Distinct from a
/// runtime tick error — this catches a malformed *declaration*.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ComplianceSpecError {
    #[error("compliance promessa has an empty name")]
    EmptyName,
    #[error("compliance promessa reconcile interval must be positive")]
    NonPositiveInterval,
    #[error("compliance promessa declares no arms")]
    NoArms,
    #[error("arm `{arm}` declares no controls")]
    ArmWithoutControls { arm: String },
    #[error("compliance promessa has an empty control set")]
    EmptyControlSet,
}

// ── CompliancePayload (OutcomeChain leaf) ──────────────────────────

/// The per-arm attestation outcome recorded on the OutcomeChain. Per
/// the F-4 §3.2 BoE definition, a control is *evidenced* by receipts
/// showing the accepting state (`Holding` = observed satisfied).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ArmVerdict {
    /// The arm was observed satisfied (BoE accepting state).
    Holding,
    /// The arm was observed violated.
    Violated,
    /// The arm's observation is not yet wired — a SCAFFOLD marker, NOT
    /// a passing verdict. Distinguishes "observed clean" from
    /// "unobserved" so a scaffold tick can never masquerade as
    /// compliant evidence.
    NotYetObserved,
}

impl ArmVerdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Holding => "Holding",
            Self::Violated => "Violated",
            Self::NotYetObserved => "NotYetObserved",
        }
    }
}

/// One arm's outcome at one tick — the atom the OutcomeChain records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArmOutcome {
    pub arm: String,
    pub controls: Vec<ControlId>,
    pub verdict: ArmVerdict,
    /// Free-text diagnostic (e.g. which projection was read).
    #[serde(default)]
    pub detail: Option<String>,
}

/// The typed OutcomeChain payload for a compliance tick. Implements
/// [`lava_outcome_chain::Payload`] so it appends onto the *real*
/// BLAKE3-linked, optionally-Ed25519-signed chain — the same machinery
/// tameshi's HeartbeatChain uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePayload {
    /// The promessa this receipt attests.
    pub promessa_name: String,
    /// The baseline claimed at this tick.
    pub baseline: ComplianceBaseline,
    /// BLAKE3 of the canonical `CompliancePromessa` spec — binds the
    /// receipt to exactly the declaration it attests.
    pub spec_hash: ContentHash,
    /// Monotonic tick index within this promessa's run.
    pub tick_index: u64,
    /// Per-arm outcomes at this tick.
    pub arm_outcomes: Vec<ArmOutcome>,
    /// Whether the whole tick is a scaffold tick (Decide/Act not yet
    /// wired). LOAD-BEARING: an auditor reading the chain sees this
    /// flag and knows the receipt is provenance, not a closed-loop
    /// proof.
    pub scaffold: bool,
}

impl Payload for CompliancePayload {
    const KIND: &'static str = "viggy.compliance";
}

// ── (defpromessa …)-shaped authoring macro (vocabulary bridge) ─────

/// A `(defpromessa …)`-shaped authoring form for a Compliance promessa.
/// Builds a [`CompliancePromessa`] from a terse declaration; the
/// vocabulary bridge that stands in for `#[derive(TataraDomain)]`
/// until this crate adopts `tatara-lisp`.
///
/// ```
/// use lava_viggy::{defcompliance_promessa, compliance::{ComplianceArm, ComplianceBaseline}};
/// use chrono::Duration;
///
/// let p = defcompliance_promessa! {
///     name: "camelot-fedramp-high",
///     namespace: "camelot",
///     baseline: ComplianceBaseline::FedrampHigh,
///     reconcile_every: Duration::minutes(5),
///     arms: [ComplianceArm::sc8(), ComplianceArm::ra5(), ComplianceArm::audit_controls()],
/// };
/// assert_eq!(p.name, "camelot-fedramp-high");
/// ```
#[macro_export]
macro_rules! defcompliance_promessa {
    {
        name: $name:expr,
        namespace: $ns:expr,
        baseline: $baseline:expr,
        reconcile_every: $every:expr,
        arms: [ $($arm:expr),* $(,)? ] $(,)?
    } => {
        $crate::compliance::CompliancePromessa {
            name: ($name).into(),
            namespace: ($ns).into(),
            baseline: $baseline,
            arms: ::std::vec![ $($arm),* ],
            escalation: None,
            reconcile_every: $every,
        }
    };
}

// ── duration <-> seconds serde helper (typed emission, no format!) ─

mod duration_seconds {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.num_seconds().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = i64::deserialize(d)?;
        Ok(Duration::seconds(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camelot_fedramp_high_has_the_three_f4_arms() {
        let p = CompliancePromessa::camelot_fedramp_high("camelot");
        let arm_tags: Vec<&str> = p.arms.iter().map(|a| a.arm.as_str()).collect();
        assert_eq!(arm_tags, vec!["sc-8", "ra-5", "audit"]);
        assert_eq!(p.baseline, ComplianceBaseline::FedrampHigh);
        assert_eq!(p.reconcile_every, Duration::minutes(5));
    }

    #[test]
    fn control_set_dedups_and_covers_all_three_arms() {
        let p = CompliancePromessa::camelot_fedramp_high("camelot");
        let controls: Vec<String> = p.control_set().into_iter().map(|c| c.0).collect();
        // SC-8, SC-8(1), RA-5, SI-2, AU-2, AU-12, CA-7 — 7 distinct.
        assert!(controls.contains(&"SC-8".to_string()));
        assert!(controls.contains(&"SC-8(1)".to_string()));
        assert!(controls.contains(&"RA-5".to_string()));
        assert!(controls.contains(&"SI-2".to_string()));
        assert!(controls.contains(&"AU-12".to_string()));
        assert!(controls.contains(&"CA-7".to_string()));
        assert_eq!(controls.len(), 7);
    }

    #[test]
    fn sc8_arm_observes_peerauth_strict() {
        let arm = ComplianceArm::sc8();
        match arm.observation.expect("sc-8 has an observation") {
            ArmObservation::KubeApi { projection, expect, .. } => {
                assert_eq!(projection, ".spec.mtls.mode");
                assert_eq!(expect, "STRICT");
            }
            other => panic!("expected KubeApi observation, got {other:?}"),
        }
    }

    #[test]
    fn audit_arm_has_no_observation_it_is_derived_by_kensa() {
        let arm = ComplianceArm::audit_controls();
        assert!(arm.observation.is_none());
    }

    #[test]
    fn valid_promessa_passes_validation() {
        let p = CompliancePromessa::camelot_fedramp_high("camelot");
        assert!(p.validate().is_ok());
    }

    #[test]
    fn empty_arms_fails_validation() {
        let mut p = CompliancePromessa::camelot_fedramp_high("camelot");
        p.arms.clear();
        assert_eq!(p.validate(), Err(ComplianceSpecError::NoArms));
    }

    #[test]
    fn spec_hash_is_stable_and_content_addressed() {
        let p = CompliancePromessa::camelot_fedramp_high("camelot");
        let h1 = p.spec_hash().unwrap();
        let h2 = p.spec_hash().unwrap();
        assert_eq!(h1, h2);
        assert!(!h1.is_genesis());
    }

    #[test]
    fn spec_hash_changes_with_baseline() {
        let p = CompliancePromessa::camelot_fedramp_high("camelot");
        let mut q = p.clone();
        q.baseline = ComplianceBaseline::FedrampModerate;
        assert_ne!(p.spec_hash().unwrap(), q.spec_hash().unwrap());
    }

    #[test]
    fn defcompliance_promessa_macro_builds_the_value() {
        let p = defcompliance_promessa! {
            name: "camelot-fedramp-high",
            namespace: "camelot",
            baseline: ComplianceBaseline::FedrampHigh,
            reconcile_every: Duration::minutes(5),
            arms: [ComplianceArm::sc8(), ComplianceArm::ra5(), ComplianceArm::audit_controls()],
        };
        assert_eq!(p.name, "camelot-fedramp-high");
        assert_eq!(p.arms.len(), 3);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn compliance_payload_kind_is_stable() {
        assert_eq!(CompliancePayload::KIND, "viggy.compliance");
    }

    #[test]
    fn promessa_serializes_with_typed_baseline_string() {
        let p = CompliancePromessa::camelot_fedramp_high("camelot");
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""baseline":"fedramp-high""#));
    }
}
