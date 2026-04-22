# White Cell Immune Architecture

White Cell models host defense the way a security engineer can model the immune system: as a decentralized detection and response stack.

## Component Mapping

| Biological Role | White Cell Component | Purpose |
|---|---|---|
| Neutrophils | `whitecell/immune/neutrophils.py` | Fast local detection and immediate threat identification |
| B-Lymphocytes | `whitecell/immune/b_cells.py` + `memory.py` | Cached threat memory and repeat-sighting awareness |
| T-Lymphocytes | `whitecell/immune/t_cells.py` | Response orchestration and command-mode activation |
| Monocytes | `whitecell/immune/monocytes.py` | Canonical logging and cleanup-oriented incident records |
| Basophils | `whitecell/immune/basophils.py` | Alert amplification, severity shaping, and telemetry signals |

## Coordinator

`whitecell/immune/system.py` provides the `ImmuneSystem` coordinator.

Current flow:

1. Neutrophils inspect input and identify a likely threat.
2. Risk scoring is applied.
3. B-cells remember the incident for future repeat sightings.
4. Basophils build a normalized alert signal.
5. T-cells activate response and generate operator guidance.
6. Monocytes build the durable log entry.

## Current Engine Integration

`whitecell/engine.py` now uses the immune coordinator as its primary threat-processing path. This keeps the public CLI behavior stable while moving the internal design toward a clearer security architecture.

## Why This Matters

This model gives White Cell:

- clearer separation of responsibilities
- a place for future adaptive detection logic
- better reasoning about false positives vs. aggressive response
- a cleaner way to integrate Python orchestration with the privileged C# shield

## Next Recommended Upgrades

- connect WhiteCellShield alerts directly into the immune coordinator
- persist B-cell memory to disk as local threat intelligence
- add trust policies to reduce “autoimmune” false positives
- add scored response policies for observe, contain, suspend, and escalate
