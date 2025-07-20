# Changelog

## v1.0.1 – Unreleased

### Added
- Unified `locksum` launcher (CLI vs GUI auto-switch).
- Pre-commit configuration (`.pre-commit-config.yaml`).
- Documentation overhaul: README, vault format, architecture diagram, API reference via mkdocstrings.
- Coverage badge in README.

### Changed
- CLI `store` command now enforces zxcvbn score ≥2 when creating a new vault.

### Fixed
- Updated docs to reflect actual Fernet-based encryption (LSV1). 