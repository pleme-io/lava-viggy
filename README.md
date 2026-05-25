# lava-viggy

Typed PromessaController surface — the 7-beat Viggy tick.
L5 of the lava-suite. Operationalizes
[theory/CONTINUOUS-SOLUTION-MACHINE.md](https://github.com/pleme-io/theory).

## The 7-beat tick

```text
Observe → Diff → Classify → Decide → Act → Attest → Tick
   │       │       │         │       │       │       │
   │       │       │         │       │       │       └─ requeue
   │       │       │         │       │       └─ OutcomeChain receipt
   │       │       │         │       └─ reconverge / hold / escalate
   │       │       │         └─ AnomalyRouter → RoutingDecision
   │       │       └─ Severity (Cosmetic/Functional/Critical)
   │       └─ DriftReport
   └─ live state
```

## Abstractions

| Type | Purpose |
|---|---|
| `PromessaController` trait | Every lava controller implements this |
| `Beat` | Typed enum of the 7 beats |
| `BeatOutcome` | Per-beat result (Ok / Skipped / Failed) |
| `TickReport` | Full record of one tick |
| `TickPhase` | Stable / Reconverging / HoldingForApproval / Escalated / Failed |
| `ViggyEngine<C, R>` | Composes controller + router + policy |

## Default impls

`PromessaController` ships default impls for `classify`, `decide`, `act`,
`attest`, `tick_after`. Consumers override only the non-standard ones.

`classify` → `report.max_severity` (or Cosmetic on a clean report)

`decide` → builds a typed `LavaAnomaly` + routes through `AnomalyRouter`

`act` → standard mapping:

| RemediationAction | TickPhase |
|---|---|
| NoOp / Alert | Stable |
| AutoCorrect | Reconverging |
| RequireApproval | HoldingForApproval |
| Escalate | Escalated |

## Use

```rust
struct MyController { /* state */ }

impl PromessaController for MyController {
    type Context = MyObservedState;
    fn observe(&self, src, bindings) -> Result<MyObservedState, ViggyError> { /*…*/ }
    fn diff(&self, ctx, bindings) -> Result<DriftReport, ViggyError> { /*…*/ }
    // classify/decide/act/attest/tick_after: defaults are usually enough
}

let engine = ViggyEngine::new(MyController { /* … */ }, PolicyRouter, policy);
let report = engine.tick(source, bindings);
```

## Tests

7 unit tests cover clean-tick visiting every beat, functional drift →
Reconverging, critical drift → HoldingForApproval, Observe-failure
short-circuit with 6 skipped beats, canonical 7-beat order, typed
JSON serialization, non-negative duration.
