# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-02-20

### Added
- Packaging support via `pyproject.toml` with setuptools backend.
- Console entry point: `whitecell`.
- CI workflow for linting, tests, build validation, and optional type checking.
- SOC-focused integration tests for:
  - `agent configure` and `agent ask` flows
  - governance approval lifecycle
  - scan allowlist behavior for active website probing
  - golden-path `soc run` orchestration with execute action
- Groq API key hardening:
  - legacy `fernet://...` detection and migration path
  - explicit warnings for unsupported legacy format
  - invalid key recovery and stricter validation

### Changed
- Groq key loading now prefers valid configuration keys and safely falls back to environment keys.
- CLI enhanced module now includes fallback defaults for missing optional support modules.

### Fixed
- Prevented invalid or legacy Groq key formats from silently breaking AI command flows.
