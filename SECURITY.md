# Security Policy

## Reporting a vulnerability

Please do not put working exploits, real credentials, or other sensitive test data in a public issue.

For normal bugs, open a GitHub issue with a small reproduction. For a security-sensitive report, use GitHub's private vulnerability reporting feature if it is enabled for this repository. If it is not available, contact the repository owner privately before publishing the details.

## Security model

This plugin launches local scanner executables found on `PATH` or supplied through the `HSA_*` executable overrides. Only point those settings at scanner binaries you trust.

The plugin does not intentionally execute project files. Gitleaks, OSV-Scanner, and Semgrep are started as subprocesses with `shell=False`, and the plugin itself does not modify the workspace. The scanners are separate projects with their own behavior, dependencies, caches, and network access, so their security/privacy documentation still applies.

A missing scanner, timeout, malformed scanner output, or unexpected process failure is reported as `UNRESOLVED`. It is never converted into a passing audit.

Gitleaks runs with full redaction, and the normalized result deliberately omits its `Secret` field.
