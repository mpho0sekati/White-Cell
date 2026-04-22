# White Cell Immune Architecture

White Cell models host defense the way a security engineer can model the immune system: as a decentralized detection and response stack with memory, orchestration, cleanup, and signaling.

## Design Goals

The immune architecture exists to give White Cell:

- fast local detection without waiting for cloud AI
- clearer separation between detection, memory, orchestration, and cleanup
- safer handling of aggressive response actions
- a cleaner integration path between the Python control plane and the privileged C# shield
- a practical model for reducing false positives instead of reacting to every event the same way

## Biological To Security Mapping

| Biological Role | White Cell Component | Security Function |
|---|---|---|
| Neutrophils | `whitecell/immune/neutrophils.py` | Fast, local, low-latency first response |
| B-Lymphocytes | `whitecell/immune/b_cells.py` + `memory.py` | Threat memory, repeat sightings, future recognition |
| T-Lymphocytes | `whitecell/immune/t_cells.py` | Decision logic, command-mode activation, response coordination |
| Monocytes | `whitecell/immune/monocytes.py` | Incident record construction, cleanup-oriented post-processing |
| Basophils | `whitecell/immune/basophils.py` | Alert amplification, severity shaping, telemetry signaling |

## Package Layout

```text
whitecell/immune/
  __init__.py
  neutrophils.py
  b_cells.py
  memory.py
  t_cells.py
  monocytes.py
  basophils.py
  system.py
```

## Coordinator

`whitecell/immune/system.py` provides the `ImmuneSystem` coordinator.

The coordinator is the single place where White Cell converts raw operator input or future shield telemetry into:

- a confirmed or rejected detection decision
- a risk-scored incident
- a memory update
- an amplified alert signal
- a durable log entry
- an operator-facing response message

## Current Processing Flow

Current flow for `engine.handle_input()`:

1. Neutrophils inspect input and select the most likely threat match.
2. Central risk scoring is applied using existing risk logic.
3. B-cells remember the incident and increase sighting counts for repeated patterns.
4. Basophils build a normalized signal containing severity, risk, and alert context.
5. T-cells activate command mode and generate response guidance.
6. Monocytes build the canonical log entry for persistence.

## Module Responsibilities

### Neutrophils

File: `whitecell/immune/neutrophils.py`

Purpose:

- perform immediate local detection
- enrich top matches with threat context
- preserve a path for future multi-match correlation

This is the right place for:

- signature matching
- heuristic scoring
- host telemetry correlation
- C# shield alert ingestion

### B-Cells

Files: `whitecell/immune/b_cells.py`, `whitecell/immune/memory.py`

Purpose:

- remember past threat encounters
- reduce time to mitigation on repeat sightings
- track indicators and recurrence patterns

Current memory is in-process only. The next step is local persistence so threat memory survives CLI restarts.

### T-Cells

File: `whitecell/immune/t_cells.py`

Purpose:

- convert detection into action
- activate command mode
- decide what guidance the operator sees

This is where future response policy logic should live, such as:

- observe only
- contain
- suspend
- block
- require approval
- escalate to admin

### Monocytes

File: `whitecell/immune/monocytes.py`

Purpose:

- produce clean, durable incident records
- support post-incident audit and cleanup flows

This layer should eventually expand into:

- cleanup tasks
- remediation summaries
- closure notes
- recovery-state tracking

### Basophils

File: `whitecell/immune/basophils.py`

Purpose:

- amplify important events into a consistent signal
- shape incident severity for UX and governance layers
- prepare alert metadata for dashboards and shield integrations

This is the right place for:

- severity escalation
- incident urgency flags
- telemetry fan-out
- operator visibility tuning

## Engine Integration

`whitecell/engine.py` now uses the immune coordinator as its primary threat-processing path.

That means the public CLI behavior stays stable while the internal logic moves toward a clearer security architecture.

The engine still owns:

- threat log persistence
- process orchestration for helper binaries
- command parsing

But the actual detect-respond-memory flow is now delegated to the immune system.

## C# Shield Integration Direction

The new C# `WhiteCellShield` behavior is a natural upstream signal source for the immune pipeline.

Recommended next integration:

1. Shield emits structured alerts.
2. Python ingests those alerts as events.
3. Neutrophils correlate shield telemetry with local signatures.
4. T-cells decide whether to observe, contain, or escalate.
5. Basophils amplify the event into the CLI/dashboard/governance layers.

## False Positives And Autoimmune Risk

The immune analogy is useful because it makes the biggest risk very obvious: autoimmune behavior.

In security terms, autoimmune failure means:

- trusted processes suspended by mistake
- valid files quarantined or deleted
- privileged actions triggered on low-confidence evidence
- excessive alert amplification causing analyst fatigue

To reduce that risk, every destructive response should eventually consider:

- confidence score
- source quality
- trusted process policy
- trusted path policy
- operator role
- approval requirement
- auditability

## Recommended Next Upgrades

- persist B-cell memory to disk as local threat intelligence
- connect `WhiteCellShield` alerts directly into the immune coordinator
- add trust policies for processes, paths, and operators
- add response classes such as `observe`, `contain`, `suspend`, and `block`
- add confidence-aware response gating to reduce false positives
- expose immune telemetry in `dashboard` and `peek`

## Summary

White Cell is no longer just a CLI with detection and risk scoring. It now has the start of a real security architecture:

- fast detection
- adaptive memory
- orchestrated response
- cleanup-oriented logging
- amplified telemetry

That foundation is what will let the project grow into a stronger MDR-style local defense platform instead of a flat collection of commands.
