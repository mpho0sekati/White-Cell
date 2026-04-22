# Project Updates

## 2026-04-21

### CLI and Maintainer Workflow

- Removed duplicated `EnhancedWhiteCellCLI` definitions from `whitecell/cli_enhanced.py`
- Standardized CLI status messaging across the main and enhanced CLI entry points
- Centralized governed response action definitions in the enhanced CLI
- Normalized terminal output to ASCII-safe text for better Windows console compatibility
- Split the enhanced CLI into smaller modules with a command registry

### Immune System Architecture

- Added `whitecell/immune/` as a first-class architecture layer
- Implemented neutrophils, B-cells, T-cells, monocytes, and basophils as code modules
- Moved `whitecell/engine.py` onto the immune-system coordinator path
- Added initial tests for threat memory and immune pipeline activation

### Dependency and Runbook Alignment

- Aligned project metadata and launcher scripts on `rich>=15.0.0`
- Removed accidental dependency-output artifact from the repository root

### Documentation Refresh

- Updated `README.md` with developer setup guidance
- Updated `QUICKSTART.md` with Git clone flow, dev dependency setup, and contribution troubleshooting
- Added `docs/CONTRIBUTING_GITHUB.md` for contribution graph troubleshooting

## 2026-02-19

### Platform and Workflow

- Added SOC-first command model:
  - `triage`
  - `investigate`
  - `respond`
  - `soc run` chain command with optional execute action
- Added governance module:
  - role-based permissions
  - approval request and review flow
  - audit event logging
- Added domain allowlist and governance enforcement for active probing

### UX and CLI

- Standardized section headers and visual layout across major CLI views
- Improved SOC command discoverability in help text
- Kept branded prompt behavior consistent

### Tests

- Added governance tests
- Added SOC run parser tests
- Current suite status: passing locally

### Documentation Refresh

- Rewrote `README.md` with SOC-first and governance-first framing
- Rewrote `QUICKSTART.md` with production command paths only
- Rewrote `README_AGENT_SYSTEM.md` as operations guide
