from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import audit  # noqa: E402


def completed(args, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=args, returncode=code, stdout=stdout, stderr=stderr)


class AuditTests(unittest.TestCase):
    def test_clean_scan_passes_and_osv_can_be_not_applicable(self):
        with tempfile.TemporaryDirectory() as td, patch.object(
            audit, "_resolve_executable", side_effect=["gitleaks", "osv-scanner", "semgrep"]
        ), patch.object(audit, "_run_process") as run:
            def fake(args, **kwargs):
                if args[0] == "gitleaks":
                    return completed(args, stdout="[]")
                if args[0] == "osv-scanner":
                    return completed(args, code=128, stderr="No package sources found")
                return completed(args, stdout=json.dumps({"results": [], "errors": []}))

            run.side_effect = fake
            result = audit.run_security_audit(td)

        self.assertEqual(result["overall"], "PASS")
        self.assertFalse(result["coverage_incomplete"])
        self.assertEqual(result["scanners"]["gitleaks"]["status"], "PASS")
        self.assertEqual(result["scanners"]["osv"]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["scanners"]["semgrep"]["status"], "PASS")

    def test_gitleaks_finding_fails_and_does_not_require_secret_value(self):
        finding = {
            "RuleID": "generic-api-key",
            "Description": "Generic API key",
            "File": "config.txt",
            "StartLine": 4,
            "Secret": "REDACTED",
        }
        with tempfile.TemporaryDirectory() as td, patch.object(
            audit, "_resolve_executable", side_effect=["gitleaks", "osv-scanner", "semgrep"]
        ), patch.object(audit, "_run_process") as run:
            def fake(args, **kwargs):
                if args[0] == "gitleaks":
                    return completed(args, code=1, stdout=json.dumps([finding]))
                if args[0] == "osv-scanner":
                    return completed(args, stdout=json.dumps({"results": []}))
                return completed(args, stdout=json.dumps({"results": []}))

            run.side_effect = fake
            result = audit.run_security_audit(td)

        self.assertEqual(result["overall"], "FAIL")
        normalized = result["scanners"]["gitleaks"]["findings"][0]
        self.assertNotIn("Secret", normalized)
        self.assertEqual(normalized["rule_id"], "generic-api-key")

    def test_osv_vulnerability_fails(self):
        osv_json = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "demo"},
                            "vulnerabilities": [
                                {"id": "GHSA-demo", "summary": "Example vulnerability"}
                            ],
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as td, patch.object(
            audit, "_resolve_executable", side_effect=["gitleaks", "osv-scanner", "semgrep"]
        ), patch.object(audit, "_run_process") as run:
            def fake(args, **kwargs):
                if args[0] == "gitleaks":
                    return completed(args, stdout="[]")
                if args[0] == "osv-scanner":
                    return completed(args, code=1, stdout=json.dumps(osv_json))
                return completed(args, stdout=json.dumps({"results": []}))

            run.side_effect = fake
            result = audit.run_security_audit(td)

        self.assertEqual(result["overall"], "FAIL")
        self.assertEqual(result["scanners"]["osv"]["findings"][0]["id"], "GHSA-demo")

    def test_malformed_semgrep_json_is_unresolved(self):
        with tempfile.TemporaryDirectory() as td, patch.object(
            audit, "_resolve_executable", side_effect=["gitleaks", "osv-scanner", "semgrep"]
        ), patch.object(audit, "_run_process") as run:
            def fake(args, **kwargs):
                if args[0] == "gitleaks":
                    return completed(args, stdout="[]")
                if args[0] == "osv-scanner":
                    return completed(args, code=128)
                return completed(args, stdout="not-json")

            run.side_effect = fake
            result = audit.run_security_audit(td)

        self.assertEqual(result["overall"], "UNRESOLVED")
        self.assertTrue(result["coverage_incomplete"])
        self.assertEqual(result["scanners"]["semgrep"]["status"], "UNRESOLVED")

    def test_missing_scanner_is_unresolved(self):
        with tempfile.TemporaryDirectory() as td, patch.object(
            audit, "_resolve_executable", side_effect=[None, "osv-scanner", "semgrep"]
        ), patch.object(audit, "_run_process") as run:
            def fake(args, **kwargs):
                if args[0] == "osv-scanner":
                    return completed(args, code=128)
                return completed(args, stdout=json.dumps({"results": []}))

            run.side_effect = fake
            result = audit.run_security_audit(td)

        self.assertEqual(result["overall"], "UNRESOLVED")
        self.assertEqual(result["scanners"]["gitleaks"]["status"], "UNRESOLVED")


    def test_sanitized_env_strips_host_runtime_but_preserves_semgrep_privacy_choice(self):
        fake_env = {
            "PATH": "demo",
            "TERM": "xterm-256color",
            "PYTHONPATH": "C:/bad",
            "HERMES_HOME": "C:/hermes",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_APP_TOKEN": "token-value",
            "SEMGREP_DEBUG": "1",
        }
        with patch.dict(audit.os.environ, fake_env, clear=True):
            child = audit._sanitized_env()

        self.assertEqual(child["PATH"], "demo")
        self.assertNotIn("TERM", child)
        self.assertNotIn("PYTHONPATH", child)
        self.assertNotIn("HERMES_HOME", child)
        self.assertNotIn("SEMGREP_DEBUG", child)
        self.assertEqual(child["SEMGREP_SEND_METRICS"], "off")
        self.assertEqual(child["SEMGREP_APP_TOKEN"], "token-value")
        self.assertEqual(child["NO_COLOR"], "1")

    def test_missing_workspace_is_blocked(self):
        result = audit.run_security_audit(str(ROOT / "definitely-not-a-real-directory"))
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertTrue(result["coverage_incomplete"])
        self.assertEqual(result["scanners"], {})

    def test_approval_hook_ignores_other_tools(self):
        spec = importlib.util.spec_from_file_location(
            "hermes_security_audit_approval",
            ROOT / "__init__.py",
            submodule_search_locations=[str(ROOT)],
        )
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules["hermes_security_audit_approval"] = module
        spec.loader.exec_module(module)
        self.assertIsNone(module._approval_gate("terminal", {"workspace": "C:/demo"}))

    def test_plugin_registers_one_tool_and_one_hook(self):
        spec = importlib.util.spec_from_file_location(
            "hermes_security_audit",
            ROOT / "__init__.py",
            submodule_search_locations=[str(ROOT)],
        )
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules["hermes_security_audit"] = module
        spec.loader.exec_module(module)

        class Context:
            def __init__(self):
                self.tools = []
                self.hooks = []

            def register_tool(self, **kwargs):
                self.tools.append(kwargs)

            def register_hook(self, name, callback):
                self.hooks.append((name, callback))

        ctx = Context()
        module.register(ctx)
        self.assertEqual(len(ctx.tools), 1)
        self.assertEqual(ctx.tools[0]["name"], "security_audit")
        self.assertEqual(len(ctx.hooks), 1)
        self.assertEqual(ctx.hooks[0][0], "pre_tool_call")
        directive = ctx.hooks[0][1]("security_audit", {"workspace": "C:/demo"})
        self.assertEqual(directive["action"], "approve")


if __name__ == "__main__":
    unittest.main()
