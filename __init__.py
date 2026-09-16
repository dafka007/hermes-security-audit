"""Hermes Security Audit plugin.

Registers one model-facing tool, ``security_audit``, plus a pre-tool-call
approval hook so a human must approve the scan before any scanner executes.
"""

from __future__ import annotations

import json
from typing import Any

from .audit import run_security_audit


TOOL_SCHEMA = {
    "name": "security_audit",
    "description": (
        "Run an approval-gated, read-only security audit of a local workspace "
        "using Gitleaks, OSV-Scanner, and Semgrep CE. Returns structured JSON "
        "with PASS, FAIL, NOT_APPLICABLE, or UNRESOLVED scanner statuses."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "workspace": {
                "type": "string",
                "description": "Absolute or relative path to the workspace directory to scan.",
            }
        },
        "required": ["workspace"],
        "additionalProperties": False,
    },
}


def _run_security_audit(args: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    if not isinstance(args, dict):
        return json.dumps(
            {
                "type": "SECURITY_AUDIT",
                "overall": "BLOCKED",
                "coverage_incomplete": True,
                "error": "Tool arguments must be an object.",
            },
            indent=2,
        )

    workspace = args.get("workspace")
    if not isinstance(workspace, str) or not workspace.strip():
        return json.dumps(
            {
                "type": "SECURITY_AUDIT",
                "overall": "BLOCKED",
                "coverage_incomplete": True,
                "error": "workspace must be a non-empty string.",
            },
            indent=2,
        )

    return json.dumps(run_security_audit(workspace), indent=2)


def _approval_gate(
    tool_name: str,
    args: dict[str, Any] | None = None,
    task_id: str = "",
    **kwargs: Any,
):
    del task_id, kwargs
    if tool_name != "security_audit":
        return None

    workspace = ""
    if isinstance(args, dict):
        value = args.get("workspace")
        if isinstance(value, str):
            workspace = value

    target = workspace or "the requested workspace"
    return {
        "action": "approve",
        "message": (
            "Run the local security audit (Gitleaks, OSV-Scanner, Semgrep CE) "
            f"against: {target}. The scanners are launched without a shell and "
            "the plugin does not modify project files."
        ),
    }


def register(ctx) -> None:
    """Register the tool and its human-approval hook with Hermes."""
    ctx.register_tool(
        name="security_audit",
        toolset="security_audit",
        schema=TOOL_SCHEMA,
        handler=_run_security_audit,
    )
    ctx.register_hook("pre_tool_call", _approval_gate)
