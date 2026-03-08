> Maintainer instruction: This changelog is append-only. Always append new entries; do not edit or reorder previous entries.

# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-03-08

### Added
- Go-live staging scaffolding: `Dockerfile`, `docker-compose.staging.yml`, `scripts/go_live_staging.sh`
- `.env.staging.example` for local staging bootstrap
- `uv.lock` for reproducible contributor installs
- GitHub Actions `security.yml` hardened: Layer-3 now gates on `critical + high` (was `critical` only)

### Fixed
- Removed `continue-on-error: true` from all security-critical CI jobs (fail-open posture)
- Removed `|| true` from blocking scan/audit steps
- Pinned `owasp/zap2docker-stable:latest` → `2.15.0` (SC-003 self-violation)
- Layer-2 secrets scan correctly labeled as report-only; enforcement remains in Layer-3

### Changed
- `APP_USER` config added to `.env.example`
- Broadened `.coverage` ignore pattern to catch `.coverage*` variants
- Added Release Runbook section in `README.md` for PyPI trusted publishing (OIDC), tag flow, rerun guidance, and smoke-test verification.
- Renamed tool from `reposec` → `shipguard`: package, CLI entrypoint, config files (`.reposec.yml` → `.shipguard.yml`), env vars (`REPOSEC_*` → `SHIPGUARD_*`), GitHub Action usage example updated to `celstnblacc/shipguard@main`.

---

## [0.1.0] — 2026-02-01

### Added
- Initial release
- 40 security rules across 7 layers: Shell (9), Python (9), JavaScript (8), GitHub Actions (5), Config (3), Secrets (3), Supply Chain (3)
- CLI commands: `scan`, `list-rules`, `init`
- Output formats: terminal (Rich), JSON, Markdown
- GitHub Action integration (`action.yml`)
- Pre-commit hook support
- Test suite: 217 functions across 27 files
- Golden snapshot regression tests
- Concurrent scanning support
