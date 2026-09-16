# Changelog

## 1.0.0

- Initial public release.
- Adds the approval-gated `security_audit` Hermes tool.
- Integrates Gitleaks, OSV-Scanner, and Semgrep CE.
- Normalizes scanner output into `PASS`, `FAIL`, `NOT_APPLICABLE`, `UNRESOLVED`, or `BLOCKED`.
- Redacts Gitleaks secrets from normalized output.
- Cleans inherited Hermes/Python/terminal environment state before starting scanners while preserving explicit Semgrep metrics/auth settings.
- Adds dependency-free unit tests and GitHub Actions coverage for Windows and Linux.
