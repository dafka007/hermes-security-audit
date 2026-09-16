"""Scanner orchestration for Hermes Security Audit.

The module deliberately has no third-party Python dependencies. External
security scanners are resolved from PATH (or explicit HSA_* overrides), run
without a shell, and their machine-readable output is normalized into one
result object.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

MAX_CAPTURE_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 300


class ScannerProcessError(RuntimeError):
    pass


def _timeout_seconds() -> int:
    raw = os.environ.get("HSA_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return min(max(value, 10), 1800)


def _resolve_executable(env_name: str, candidates: Iterable[str]) -> str | None:
    override = os.environ.get(env_name, "").strip()
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        found = shutil.which(override)
        if found:
            return found
        return None

    for name in candidates:
        found = shutil.which(name)
        if found:
            return found
    return None


def _sanitized_env() -> dict[str, str]:
    """Create a stable child environment for scanner processes.

    Hermes Desktop can inject Python/Electron/terminal variables that affect
    child-process behavior. Those are removed while normal OS networking and
    proxy variables are preserved. Most Semgrep-specific environment variables
    are removed as well; explicit metrics/auth endpoint settings are preserved,
    and the rule source is configured through HSA_SEMGREP_CONFIG.
    """

    child = os.environ.copy()
    exact = {
        "VIRTUAL_ENV",
        "TERM",
        "COLORTERM",
        "FORCE_COLOR",
        "NO_COLOR",
        "CI",
        "ELECTRON_RUN_AS_NODE",
        "NODE_OPTIONS",
    }
    semgrep_keep = {
        key: value
        for key, value in child.items()
        if key.upper() in {
            "SEMGREP_SEND_METRICS",
            "SEMGREP_APP_TOKEN",
            "SEMGREP_URL",
        }
    }

    prefixes = ("HERMES_", "PYTHON", "UV_", "CONDA", "SEMGREP_")

    for key in list(child):
        upper = key.upper()
        if upper in exact or any(upper.startswith(prefix) for prefix in prefixes):
            child.pop(key, None)

    child.update(semgrep_keep)
    child["PYTHONUTF8"] = "1"
    child["PYTHONIOENCODING"] = "utf-8"
    child["PYTHONNOUSERSITE"] = "1"
    child["NO_COLOR"] = "1"
    return child


def _decode_temp_output(handle) -> str:
    handle.seek(0)
    return handle.read(MAX_CAPTURE_BYTES + 1).decode("utf-8", errors="replace")


def _run_process(args: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a scanner with bounded captured output and a hard timeout.

    Output is written to temporary files instead of being buffered in memory.
    While the process runs, file sizes are checked and the scanner is killed if
    either stream exceeds the 10 MiB limit.
    """

    deadline = time.monotonic() + timeout

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                args,
                cwd=str(cwd),
                env=_sanitized_env(),
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
            )
        except OSError as exc:
            raise ScannerProcessError(f"scanner could not be started: {exc}") from exc

        while True:
            returncode = process.poll()
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size

            if stdout_size > MAX_CAPTURE_BYTES or stderr_size > MAX_CAPTURE_BYTES:
                process.kill()
                process.wait()
                raise ScannerProcessError("scanner output exceeded the 10 MiB safety limit")

            if returncode is not None:
                break

            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise ScannerProcessError(f"scanner timed out after {timeout}s")

            time.sleep(0.05)

        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if stdout_size > MAX_CAPTURE_BYTES or stderr_size > MAX_CAPTURE_BYTES:
            raise ScannerProcessError("scanner output exceeded the 10 MiB safety limit")

        return subprocess.CompletedProcess(
            args=args,
            returncode=returncode,
            stdout=_decode_temp_output(stdout_file),
            stderr=_decode_temp_output(stderr_file),
        )


def _json_or_none(text: str) -> Any | None:
    payload = text.lstrip("\ufeff").strip()
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def _short_error(completed: subprocess.CompletedProcess[str]) -> str:
    text = (completed.stderr or completed.stdout or "").strip().replace("\x00", "")
    if not text:
        return f"scanner exited with code {completed.returncode}"
    return text[:2000]


def _scan_gitleaks(executable: str, workspace: Path, timeout: int) -> dict[str, Any]:
    completed = _run_process(
        [
            executable,
            "dir",
            str(workspace),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--redact=100",
            "--no-color",
        ],
        cwd=workspace,
        timeout=timeout,
    )

    parsed = _json_or_none(completed.stdout)
    if not isinstance(parsed, list):
        return {
            "status": "UNRESOLVED",
            "findings": [],
            "error": f"Gitleaks returned malformed JSON. {_short_error(completed)}",
        }

    findings = []
    for item in parsed[:200]:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "rule_id": item.get("RuleID") or item.get("RuleId"),
                "description": item.get("Description"),
                "file": item.get("File"),
                "start_line": item.get("StartLine"),
                "fingerprint": item.get("Fingerprint"),
            }
        )

    if findings:
        return {"status": "FAIL", "findings": findings}
    if completed.returncode == 0:
        return {"status": "PASS", "findings": []}
    return {
        "status": "UNRESOLVED",
        "findings": [],
        "error": _short_error(completed),
    }


def _walk_vulnerabilities(value: Any):
    if isinstance(value, dict):
        vulnerabilities = value.get("vulnerabilities")
        if isinstance(vulnerabilities, list):
            for item in vulnerabilities:
                if isinstance(item, dict):
                    yield item
        for child in value.values():
            yield from _walk_vulnerabilities(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_vulnerabilities(child)


def _scan_osv(executable: str, workspace: Path, timeout: int) -> dict[str, Any]:
    completed = _run_process(
        [executable, "scan", "source", "-r", str(workspace), "--format", "json"],
        cwd=workspace,
        timeout=timeout,
    )

    if completed.returncode == 128:
        return {
            "status": "NOT_APPLICABLE",
            "findings": [],
            "note": "No supported package sources were found.",
        }

    parsed = _json_or_none(completed.stdout)
    if not isinstance(parsed, (dict, list)):
        return {
            "status": "UNRESOLVED",
            "findings": [],
            "error": f"OSV-Scanner returned malformed JSON. {_short_error(completed)}",
        }

    findings = []
    seen: set[str] = set()
    for vulnerability in _walk_vulnerabilities(parsed):
        vuln_id = str(vulnerability.get("id") or vulnerability.get("ID") or "unknown")
        key = vuln_id + "\0" + str(vulnerability.get("summary") or "")
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "id": vuln_id,
                "summary": vulnerability.get("summary"),
                "details": vulnerability.get("details"),
            }
        )
        if len(findings) >= 200:
            break

    if findings:
        return {"status": "FAIL", "findings": findings}
    if completed.returncode == 0:
        return {"status": "PASS", "findings": []}
    return {
        "status": "UNRESOLVED",
        "findings": [],
        "error": _short_error(completed),
    }


def _semgrep_error_summary(errors: list[Any]) -> str:
    summaries = []
    for item in errors[:5]:
        if isinstance(item, dict):
            message = item.get("message") or item.get("type") or item.get("code")
            summaries.append(str(message or "unspecified Semgrep error"))
        else:
            summaries.append(str(item))
    suffix = "" if len(errors) <= 5 else f" (+{len(errors) - 5} more)"
    return "; ".join(summaries)[:1800] + suffix


def _scan_semgrep(executable: str, workspace: Path, timeout: int) -> dict[str, Any]:
    config = os.environ.get("HSA_SEMGREP_CONFIG", "auto").strip() or "auto"
    completed = _run_process(
        [executable, "scan", "--config", config, "--json", "--quiet", str(workspace)],
        cwd=workspace,
        timeout=timeout,
    )

    parsed = _json_or_none(completed.stdout)
    if (
        not isinstance(parsed, dict)
        or not isinstance(parsed.get("results"), list)
        or ("errors" in parsed and not isinstance(parsed.get("errors"), list))
    ):
        return {
            "status": "UNRESOLVED",
            "findings": [],
            "error": f"Semgrep returned malformed JSON. {_short_error(completed)}",
        }

    findings = []
    for item in parsed["results"][:200]:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        findings.append(
            {
                "check_id": item.get("check_id"),
                "path": item.get("path"),
                "line": start.get("line"),
                "message": extra.get("message"),
                "severity": extra.get("severity"),
            }
        )

    errors = parsed.get("errors") or []
    if errors:
        error_text = "Semgrep reported analysis errors: " + _semgrep_error_summary(errors)
        if findings:
            return {
                "status": "FAIL",
                "findings": findings,
                "coverage_incomplete": True,
                "error": error_text,
            }
        return {
            "status": "UNRESOLVED",
            "findings": [],
            "coverage_incomplete": True,
            "error": error_text,
        }

    if findings:
        return {"status": "FAIL", "findings": findings}
    if completed.returncode == 0:
        return {"status": "PASS", "findings": []}
    return {
        "status": "UNRESOLVED",
        "findings": [],
        "error": _short_error(completed),
    }


def _missing(name: str) -> dict[str, Any]:
    return {
        "status": "UNRESOLVED",
        "findings": [],
        "error": f"{name} was not found. Install it or configure its HSA_* executable override.",
    }


def _overall(scanners: dict[str, dict[str, Any]]) -> str:
    statuses = {scanner.get("status") for scanner in scanners.values()}
    if "FAIL" in statuses:
        return "FAIL"
    if "BLOCKED" in statuses or "UNRESOLVED" in statuses:
        return "UNRESOLVED"
    return "PASS"


def _summary(workspace: Path, scanners: dict[str, dict[str, Any]]) -> str:
    lines = [f"Workspace: {workspace}", ""]
    labels = {
        "gitleaks": "GITLEAKS",
        "osv": "OSV-SCANNER",
        "semgrep": "SEMGREP",
    }
    for key in ("gitleaks", "osv", "semgrep"):
        result = scanners[key]
        status = result["status"]
        count = len(result.get("findings", []))
        detail = result.get("note") or result.get("error")
        if detail:
            line = f"{labels[key]}: {status} - {detail}"
        elif status == "PASS":
            line = f"{labels[key]}: PASS - no findings"
        else:
            line = f"{labels[key]}: {status} - {count} finding(s)"
        lines.append(line)
    return "\n".join(lines)


def run_security_audit(workspace: str) -> dict[str, Any]:
    target = Path(workspace).expanduser()
    try:
        target = target.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return {
            "type": "SECURITY_AUDIT",
            "overall": "BLOCKED",
            "coverage_incomplete": True,
            "workspace": str(target),
            "scanners": {},
            "summary": f"Workspace validation failed: {exc}",
        }

    if not target.is_dir():
        return {
            "type": "SECURITY_AUDIT",
            "overall": "BLOCKED",
            "coverage_incomplete": True,
            "workspace": str(target),
            "scanners": {},
            "summary": "Workspace must be a directory.",
        }

    timeout = _timeout_seconds()
    gitleaks = _resolve_executable("HSA_GITLEAKS", ("gitleaks", "gitleaks.exe"))
    osv = _resolve_executable("HSA_OSV_SCANNER", ("osv-scanner", "osv-scanner.exe"))
    semgrep = _resolve_executable("HSA_SEMGREP", ("semgrep", "semgrep.exe"))

    scanners: dict[str, dict[str, Any]] = {}

    try:
        scanners["gitleaks"] = _scan_gitleaks(gitleaks, target, timeout) if gitleaks else _missing("Gitleaks")
    except ScannerProcessError as exc:
        scanners["gitleaks"] = {"status": "UNRESOLVED", "findings": [], "error": str(exc)}

    try:
        scanners["osv"] = _scan_osv(osv, target, timeout) if osv else _missing("OSV-Scanner")
    except ScannerProcessError as exc:
        scanners["osv"] = {"status": "UNRESOLVED", "findings": [], "error": str(exc)}

    try:
        scanners["semgrep"] = _scan_semgrep(semgrep, target, timeout) if semgrep else _missing("Semgrep")
    except ScannerProcessError as exc:
        scanners["semgrep"] = {"status": "UNRESOLVED", "findings": [], "error": str(exc)}

    overall = _overall(scanners)
    coverage_incomplete = any(
        result.get("status") == "UNRESOLVED" or result.get("coverage_incomplete") is True
        for result in scanners.values()
    )
    return {
        "type": "SECURITY_AUDIT",
        "overall": overall,
        "coverage_incomplete": coverage_incomplete,
        "workspace": str(target),
        "scanners": scanners,
        "summary": _summary(target, scanners),
    }
