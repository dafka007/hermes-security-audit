# Changelog

## 1.0.1

- Treats Semgrep analysis errors as incomplete coverage instead of silently passing a partial scan.
- Keeps real Semgrep findings as `FAIL` even when the same scan also reports analysis errors, while marking coverage incomplete.
- Bounds scanner stdout/stderr while processes are running instead of buffering unlimited output in memory first.
- Hardens the human approval prompt by resolving and escaping the displayed workspace path.
- Expands `plugin.yaml` to the Hermes manifest v2 metadata format and declares the registered tool/hook explicitly.
- Clarifies that Gitleaks currently scans the workspace tree, not full Git history.
- Documents reproducible installs using Hermes' full-commit `--ref` option.
- Corrects the first real-world test environment to Windows 11.

## 1.0.0

- Initial public release.
- Adds the approval-gated `security_audit` Hermes tool.
- Integrates Gitleaks, OSV-Scanner, and Semgrep CE.
- Normalizes scanner output into `PASS`, `FAIL`, `NOT_APPLICABLE`, `UNRESOLVED`, or `BLOCKED`.
- Redacts Gitleaks secrets from normalized output.
- Cleans inherited Hermes/Python/terminal environment state before starting scanners while preserving explicit Semgrep metrics/auth settings.
- Adds dependency-free unit tests and GitHub Actions coverage for Windows and Linux.
