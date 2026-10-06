from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import windows_prevention as toolkit


ROOT = Path(__file__).resolve().parent


class ToolkitTests(unittest.TestCase):
    def _hook_config(self) -> dict[str, object]:
        old_command = 'py -3 -B "C:\\Users\\test\\.codex\\hooks\\codex-command-guard\\v23\\bootstrap.py"'
        owned = {"matcher": "Bash", "hooks": [{"type": "command", "command": old_command, "commandWindows": old_command, "timeout": 2}]}
        unrelated = {"matcher": "*", "hooks": [{"type": "command", "command": "GitKraken helper"}]}
        return {"description": "local", "hooks": {event: [owned, unrelated] for event in ("SessionStart", "UserPromptSubmit", "PreToolUse")}}

    def _setup(self, root: Path) -> tuple[Path, Path, Path, str, str]:
        config = root / "codex"
        config.mkdir()
        hooks = config / "hooks.json"
        agents = config / "AGENTS.md"
        hooks.write_text(json.dumps(self._hook_config()), encoding="utf-8")
        agents.write_text("Existing runtime and GitKraken rules.\n", encoding="utf-8")
        return config, hooks, agents, hashlib.sha256(hooks.read_bytes()).hexdigest(), hashlib.sha256(agents.read_bytes()).hexdigest()

    def test_behavior_fixture_set_has_passing_replacements_and_unknown_cases(self) -> None:
        result = toolkit._validate(fixtures=ROOT / "fixtures" / "behavior.json")
        self.assertEqual("valid", result["outcome"])
        fixture_check = next(item for item in result["checks"] if item["id"] == "FIXTURE-SET-001")
        self.assertEqual(9, fixture_check["count"])
        self.assertEqual([], fixture_check["failures"])
        self.assertEqual(1, fixture_check["outcomes"]["unsupported"])
        self.assertEqual(1, fixture_check["outcomes"]["prerequisite_missing"])
        self.assertEqual(6, fixture_check["outcomes"]["invalid"])

    def test_empty_validate_is_unsupported(self) -> None:
        self.assertEqual("unsupported", toolkit._validate()["outcome"])

    def test_mcp_args_command_is_normalized_only_for_known_tool(self) -> None:
        known = {"tool_name": "mcp__process_manager__sync_run", "tool_input": {"args": {"cmd": "cmd.exe /c start tool.exe"}}}
        unknown = {"tool_name": "unknown", "tool_input": {"args": {"cmd": "cmd.exe /c start tool.exe"}}}
        self.assertEqual("invalid", toolkit.analyze_payload(known)[0])
        self.assertEqual("unsupported", toolkit.analyze_payload(unknown)[0])

    def test_recommendation_does_not_echo_command_by_default(self) -> None:
        payload = {"tool_name": "Bash", "tool_input": {"command": "Write-Output sk-" + "A" * 24}}
        output = {"diagnostics": [item.message for item in toolkit.analyze_payload(payload)[1]]}
        self.assertNotIn("sk-", json.dumps(output))

    def test_powershell_literal_quotes_single_quotes(self) -> None:
        self.assertEqual("'a''b'", toolkit.safe_powershell_literal("a'b"))
        with self.assertRaises(ValueError):
            toolkit.safe_powershell_literal("a\x00b")

    def test_plan_preserves_unrelated_hooks_and_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config, hooks, agents, hooks_hash, agents_hash = self._setup(Path(temp))
            original_hooks = hooks.read_bytes()
            plan = toolkit.install(config, ROOT, hooks_hash, agents_hash, plan_only=True)
            self.assertEqual("planned", plan["outcome"])
            self.assertEqual({"SessionStart": 0, "UserPromptSubmit": 0, "PreToolUse": 0}, plan["changes"][1]["events"])
            self.assertEqual(0, plan["trusted_hash_changes"])
            self.assertFalse(plan["candidate_commands_executed"])
            self.assertEqual(original_hooks, hooks.read_bytes())
            self.assertNotIn("managed V24", agents.read_text(encoding="utf-8"))

    def test_install_replaces_only_owned_entries_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config, hooks, agents, hooks_hash, agents_hash = self._setup(Path(temp))
            result = toolkit.install(config, ROOT, hooks_hash, agents_hash)
            self.assertEqual("installed", result["outcome"])
            installed_hooks = json.loads(hooks.read_text(encoding="utf-8"))
            for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
                self.assertIn("codex-windows-prevention", installed_hooks["hooks"][event][0]["hooks"][0]["command"])
                self.assertEqual("GitKraken helper", installed_hooks["hooks"][event][1]["hooks"][0]["command"])
            self.assertIn("GitKraken rules", agents.read_text(encoding="utf-8"))
            self.assertEqual(0, result["trusted_hash_changes"])
            rollback = toolkit.rollback(Path(result["transaction"]))
            self.assertEqual("rolled_back", rollback["outcome"])
            self.assertEqual(hooks_hash, hashlib.sha256(hooks.read_bytes()).hexdigest())
            self.assertEqual(agents_hash, hashlib.sha256(agents.read_bytes()).hexdigest())

    def test_rollback_checks_package_before_restoring_any_global_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config, hooks, agents, hooks_hash, agents_hash = self._setup(Path(temp))
            result = toolkit.install(config, ROOT, hooks_hash, agents_hash)
            after_hooks = hooks.read_bytes()
            after_agents = agents.read_bytes()
            installed_guard = config / "hooks" / "codex-windows-prevention" / "v24" / "guard.py"
            installed_guard.write_bytes(installed_guard.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "Owned package file changed"):
                toolkit.rollback(Path(result["transaction"]))
            self.assertEqual(after_hooks, hooks.read_bytes())
            self.assertEqual(after_agents, agents.read_bytes())

    def test_rollback_refuses_a_later_user_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config, hooks, agents, hooks_hash, agents_hash = self._setup(Path(temp))
            result = toolkit.install(config, ROOT, hooks_hash, agents_hash)
            hooks.write_bytes(hooks.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "installed bytes changed"):
                toolkit.rollback(Path(result["transaction"]))

    def test_wrong_precondition_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config, hooks, agents, hooks_hash, agents_hash = self._setup(Path(temp))
            before_hooks = hooks.read_bytes()
            before_agents = agents.read_bytes()
            with self.assertRaisesRegex(ValueError, "Precondition failed"):
                toolkit.install(config, ROOT, "0" * 64, agents_hash)
            self.assertEqual(before_hooks, hooks.read_bytes())
            self.assertEqual(before_agents, agents.read_bytes())

