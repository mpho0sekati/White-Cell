# Project Updates

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

