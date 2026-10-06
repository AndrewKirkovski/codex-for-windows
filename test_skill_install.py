from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import windows_prevention as toolkit


ROOT = Path(__file__).resolve().parent
DESCRIPTION = toolkit.SKILL_DESCRIPTION


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _config(root: Path) -> tuple[Path, Path, Path, Path]:
    config = root / "codex"
    config.mkdir()
    hooks = config / "hooks.json"
    agents = config / "AGENTS.md"
    skill = config / "skills" / "windows-command-preflight" / "SKILL.md"
    old_command = 'py -3 -B "C:\\Users\\test\\.codex\\hooks\\codex-command-guard\\v23\\bootstrap.py"'
    definition = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": old_command, "commandWindows": old_command, "statusMessage": "Windows guard v23; v230 preview23"}],
    }
    data = {"hooks": {event: [definition.copy()] for event in ("SessionStart", "UserPromptSubmit", "PreToolUse")}}
    _write(hooks, json.dumps(data).encode("utf-8"))
    _write(agents, b"Existing rules.\n")
    original_skill = (
        "---\n"
        "name: windows-command-preflight\n"
        f"description: {DESCRIPTION}\n"
        "---\n\n"
        "# Existing detailed skill\n"
    ).encode("utf-8")
    _write(skill, original_skill)
    return config, hooks, agents, skill


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OptionalSkillInstallTests(unittest.TestCase):
    def _install(self, config: Path, hooks: Path, agents: Path, skill_hash: str | None = None) -> dict[str, object]:
        return toolkit.install(config, ROOT, _hash(hooks), _hash(agents), expected_skill_sha256=skill_hash)

    def test_absent_option_leaves_existing_skill_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, hooks, agents, skill = _config(Path(temporary))
            before = skill.read_bytes()
            self._install(config, hooks, agents)
            self.assertEqual(before, skill.read_bytes())

    def test_wrong_hash_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, hooks, agents, skill = _config(Path(temporary))
            before = {path: path.read_bytes() for path in (hooks, agents, skill)}
            with self.assertRaisesRegex(ValueError, "Precondition failed"):
                self._install(config, hooks, agents, "0" * 64)
            self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_skill_pointer_readback_and_rollback_restore_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, hooks, agents, skill = _config(Path(temporary))
            original_skill = skill.read_bytes()
            result = self._install(config, hooks, agents, _hash(skill))
            installed = skill.read_text(encoding="utf-8")
            self.assertIn(f"description: {DESCRIPTION}", installed)
            self.assertIn("](<", installed)
            self.assertIn("/hooks/codex-windows-prevention/v24/skills/windows-command-preflight/SKILL.md", installed)
            self.assertIn("/hooks/codex-windows-prevention/v24/recipes.md", installed)
            message = json.loads(hooks.read_text(encoding="utf-8"))["hooks"]["SessionStart"][0]["hooks"][0]["statusMessage"]
            self.assertEqual("Windows guard v24; v230 preview23", message)
            rollback = toolkit.rollback(Path(result["transaction"]))
            self.assertEqual("rolled_back", rollback["outcome"])
            self.assertEqual(original_skill, skill.read_bytes())

    def test_concurrent_skill_change_is_preserved_and_globals_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, hooks, agents, skill = _config(Path(temporary))
            original_hooks, original_agents = hooks.read_bytes(), agents.read_bytes()
            original_write = toolkit._write_atomic
            changed = False

            def write_then_change(path: Path, data: bytes) -> None:
                nonlocal changed
                original_write(path, data)
                if path == hooks and not changed:
                    skill.write_bytes(b"User changed skill during install.\n")
                    changed = True

            with patch.object(toolkit, "_write_atomic", side_effect=write_then_change):
                with self.assertRaisesRegex(RuntimeError, "Install failed"):
                    self._install(config, hooks, agents, _hash(skill))
            self.assertEqual(original_hooks, hooks.read_bytes())
            self.assertEqual(original_agents, agents.read_bytes())
            self.assertEqual(b"User changed skill during install.\n", skill.read_bytes())

    def test_rollback_skill_change_refuses_all_global_restores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, hooks, agents, skill = _config(Path(temporary))
            result = self._install(config, hooks, agents, _hash(skill))
            installed_hooks, installed_agents = hooks.read_bytes(), agents.read_bytes()
            skill.write_bytes(b"User changed skill after install.\n")
            with self.assertRaisesRegex(ValueError, "installed bytes changed"):
                toolkit.rollback(Path(result["transaction"]))
            self.assertEqual(installed_hooks, hooks.read_bytes())
            self.assertEqual(installed_agents, agents.read_bytes())
            self.assertEqual(b"User changed skill after install.\n", skill.read_bytes())


if __name__ == "__main__":
    unittest.main()
