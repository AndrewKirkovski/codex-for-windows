from __future__ import annotations

import contextlib
import codecs
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import windows_prevention as toolkit


ROOT = Path(__file__).resolve().parent
EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse")


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _legacy_entry(command: str = 'py -3 -B "C:\\Users\\test\\.codex\\hooks\\codex-command-guard\\v23\\bootstrap.py"') -> dict[str, object]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": command, "commandWindows": command, "statusMessage": "Windows guard v23"}],
    }


def _owned_hooks(hooks_file: Path, event: str) -> list[dict[str, object]]:
    document = json.loads(hooks_file.read_text(encoding="utf-8"))
    entries = document.get("hooks", {}).get(event, [])
    found: list[dict[str, object]] = []
    for entry in entries:
        for hook in entry.get("hooks", []):
            command = hook.get("command", "")
            if re.search(r"(?i)(?:codex-command-guard[\\/]v23|codex-windows-prevention[\\/]v24)[\\/]bootstrap\.py(?:[\"']|\s|$)", command):
                found.append(entry)
                break
    return found


def _install(config: Path, **kwargs: object) -> dict[str, object]:
    return toolkit.install(config, ROOT, **kwargs)


class FreshInstallTests(unittest.TestCase):
    def test_absent_config_install_and_rollback_restore_prior_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "missing" / ".codex"
            result = _install(config)
            hooks_file = config / "hooks.json"
            agents_file = config / "AGENTS.md"
            skill_file = config / "skills" / "windows-command-preflight" / "SKILL.md"
            self.assertEqual("installed", result["outcome"])
            for event in EVENTS:
                self.assertEqual(1, len(_owned_hooks(hooks_file, event)))
            document = json.loads(hooks_file.read_text(encoding="utf-8"))
            matcher = document["hooks"]["PreToolUse"][-1]["matcher"]
            for tool_name in toolkit.SUPPORTED_TOOLS:
                self.assertIsNotNone(re.fullmatch(matcher, tool_name))
            self.assertIsNone(re.fullmatch(matcher, "unregistered_tool"))
            self.assertTrue(agents_file.is_file())
            self.assertTrue(skill_file.is_file())
            metadata = json.loads((Path(result["transaction"]) / "transaction.json").read_text(encoding="utf-8"))
            self.assertEqual({False}, {item["before_exists"] for item in metadata["files"].values()})
            self.assertTrue(all(item["before"] is None for item in metadata["files"].values()))

            hooks_before_repeat = hooks_file.read_bytes()
            with self.assertRaisesRegex(ValueError, "AGENTS.md already contains a managed v24 block"):
                _install(config)
            self.assertEqual(hooks_before_repeat, hooks_file.read_bytes())
            self.assertEqual(1, len(_owned_hooks(hooks_file, "SessionStart")))

            rollback = toolkit.rollback(Path(result["transaction"]))
            self.assertEqual("rolled_back", rollback["outcome"])
            self.assertFalse(hooks_file.exists())
            self.assertFalse(agents_file.exists())
            self.assertFalse(skill_file.exists())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "v24").exists())

    def test_existing_config_preserves_unrelated_data_and_skill_without_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            config.mkdir()
            hooks_file = config / "hooks.json"
            agents_file = config / "AGENTS.md"
            config_toml = config / "config.toml"
            skill_file = config / "skills" / "windows-command-preflight" / "SKILL.md"
            unrelated = {"matcher": "OtherTool", "hooks": [{"type": "command", "command": "keep-me"}]}
            hooks_data = {
                "hooks": {"OtherEvent": [{"hooks": [{"type": "command", "command": "unrelated"}]}], "PreToolUse": [unrelated]},
                "disableAllHooks": True,
                "other_setting": {"keep": True},
            }
            original_hooks = json.dumps(hooks_data, separators=(",", ":")).encode("utf-8")
            original_agents = b"\xef\xbb\xbfGlobal rules.\r\nMore rules.\r\n"
            original_config = b"model = 'kept'\n"
            original_skill = b"User-managed skill bytes remain unchanged.\n"
            _write(hooks_file, original_hooks)
            _write(agents_file, original_agents)
            _write(config_toml, original_config)
            _write(skill_file, original_skill)

            result = _install(config)
            after = json.loads(hooks_file.read_text(encoding="utf-8"))
            self.assertEqual(True, after["disableAllHooks"])
            self.assertEqual({"keep": True}, after["other_setting"])
            self.assertEqual(hooks_data["hooks"]["OtherEvent"], after["hooks"]["OtherEvent"])
            self.assertEqual(unrelated, after["hooks"]["PreToolUse"][0])
            for event in EVENTS:
                self.assertEqual(1, len(_owned_hooks(hooks_file, event)))
            self.assertTrue(agents_file.read_bytes().startswith(original_agents))
            self.assertEqual(original_config, config_toml.read_bytes())
            self.assertEqual(original_skill, skill_file.read_bytes())
            metadata = json.loads((Path(result["transaction"]) / "transaction.json").read_text(encoding="utf-8"))
            self.assertNotIn(str(skill_file), metadata["files"])

            toolkit.rollback(Path(result["transaction"]))
            self.assertEqual(original_hooks, hooks_file.read_bytes())
            self.assertEqual(original_agents, agents_file.read_bytes())
            self.assertEqual(original_config, config_toml.read_bytes())
            self.assertEqual(original_skill, skill_file.read_bytes())

    def test_mixed_legacy_and_missing_events_update_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            config.mkdir()
            hooks_file = config / "hooks.json"
            unrelated = {"matcher": "OtherTool", "hooks": [{"type": "command", "command": "unrelated"}]}
            legacy = _legacy_entry()
            _write(hooks_file, json.dumps({"hooks": {"SessionStart": [unrelated, legacy]}}).encode("utf-8"))
            result = _install(config)
            after = json.loads(hooks_file.read_text(encoding="utf-8"))
            self.assertEqual(unrelated, after["hooks"]["SessionStart"][0])
            self.assertEqual("Bash", after["hooks"]["SessionStart"][1]["matcher"])
            self.assertIn("/v24/bootstrap.py", after["hooks"]["SessionStart"][1]["hooks"][0]["command"].replace("\\", "/"))
            for event in EVENTS:
                self.assertEqual(1, len(_owned_hooks(hooks_file, event)))
            toolkit.rollback(Path(result["transaction"]))

    def test_plan_only_accepts_missing_config_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "not-created" / ".codex"
            result = _install(config, plan_only=True)
            self.assertEqual("planned", result["outcome"])
            self.assertFalse(config.exists())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = toolkit.main(["install", "--config-dir", str(config), "--source", str(ROOT), "--plan-only"])
            self.assertEqual(0, status)
            self.assertEqual("planned", json.loads(output.getvalue())["outcome"])
            self.assertFalse(config.exists())

    def test_plan_only_emits_unicode_paths_through_legacy_code_page(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "配置" / ".codex"
            output_bytes = io.BytesIO()
            legacy_stdout = codecs.getwriter("cp1252")(output_bytes)
            original_stdout = toolkit.sys.stdout
            try:
                toolkit.sys.stdout = legacy_stdout
                status = toolkit.main(["install", "--config-dir", str(config), "--source", str(ROOT), "--plan-only"])
            finally:
                toolkit.sys.stdout = original_stdout

            self.assertEqual(0, status)
            result = json.loads(output_bytes.getvalue().decode("ascii"))
            self.assertEqual("planned", result["outcome"])
            self.assertEqual(str(config / "hooks.json"), result["changes"][1]["path"])
            self.assertFalse(config.exists())

    def test_supplied_wrong_hashes_and_hash_for_absent_skill_write_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            config.mkdir()
            hooks_file = config / "hooks.json"
            agents_file = config / "AGENTS.md"
            _write(hooks_file, b'{"hooks":{}}')
            _write(agents_file, b"Existing rules.\n")
            original = {hooks_file: hooks_file.read_bytes(), agents_file: agents_file.read_bytes()}
            with self.assertRaisesRegex(ValueError, "Precondition failed"):
                _install(config, expected_hooks_hash="0" * 64)
            with self.assertRaisesRegex(ValueError, "Precondition failed"):
                _install(config, expected_agents_hash="0" * 64)
            self.assertEqual(original, {path: path.read_bytes() for path in original})
            self.assertFalse((config / "hooks" / "codex-windows-prevention").exists())

        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "absent" / ".codex"
            with self.assertRaisesRegex(ValueError, "file is missing"):
                _install(config, expected_skill_sha256="0" * 64)
            self.assertFalse(config.exists())

    def test_concurrent_appearance_or_change_is_preserved_before_install_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            hooks_file = config / "hooks.json"
            appeared = b"Concurrent hooks file.\n"
            original_verify = toolkit._verify_transaction_files
            injected = False

            def create_before_check(transaction: Path, files: dict[str, dict[str, object]], written: set[str], *, verify_backups: bool = True) -> None:
                nonlocal injected
                if not injected:
                    _write(hooks_file, appeared)
                    injected = True
                original_verify(transaction, files, written, verify_backups=verify_backups)

            with patch.object(toolkit, "_verify_transaction_files", side_effect=create_before_check):
                with self.assertRaisesRegex(RuntimeError, "appeared during install"):
                    _install(config)
            self.assertEqual(appeared, hooks_file.read_bytes())
            self.assertFalse((config / "AGENTS.md").exists())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "v24").exists())

        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            config.mkdir()
            hooks_file = config / "hooks.json"
            agents_file = config / "AGENTS.md"
            original_hooks = b'{"hooks":{}}'
            concurrent_agents = b"Changed during preflight.\n"
            _write(hooks_file, original_hooks)
            _write(agents_file, b"Original.\n")
            original_verify = toolkit._verify_transaction_files
            injected = False

            def change_before_check(transaction: Path, files: dict[str, dict[str, object]], written: set[str], *, verify_backups: bool = True) -> None:
                nonlocal injected
                if not injected:
                    agents_file.write_bytes(concurrent_agents)
                    injected = True
                original_verify(transaction, files, written, verify_backups=verify_backups)

            with patch.object(toolkit, "_verify_transaction_files", side_effect=change_before_check):
                with self.assertRaisesRegex(RuntimeError, "changed during install"):
                    _install(config)
            self.assertEqual(original_hooks, hooks_file.read_bytes())
            self.assertEqual(concurrent_agents, agents_file.read_bytes())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "v24").exists())

    def test_failed_write_recovery_removes_only_unchanged_created_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            original_write_new = toolkit._write_new

            def fail_agents(path: Path, data: bytes) -> None:
                if path.name == "AGENTS.md":
                    raise OSError("injected write failure")
                original_write_new(path, data)

            with patch.object(toolkit, "_write_new", side_effect=fail_agents):
                with self.assertRaisesRegex(RuntimeError, "Install failed"):
                    _install(config)
            self.assertFalse((config / "hooks.json").exists())
            self.assertFalse((config / "AGENTS.md").exists())
            self.assertFalse((config / "skills" / "windows-command-preflight" / "SKILL.md").exists())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "v24").exists())

    def test_late_created_file_is_preserved_and_install_artifacts_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            agents_file = config / "AGENTS.md"
            concurrent_bytes = b"Created by another writer during install.\n"
            original_write_new = toolkit._write_new

            def create_agents_before_link(path: Path, data: bytes) -> None:
                if path == agents_file:
                    _write(path, concurrent_bytes)
                original_write_new(path, data)

            with patch.object(toolkit, "_write_new", side_effect=create_agents_before_link):
                with self.assertRaisesRegex(RuntimeError, "Install failed"):
                    _install(config)

            self.assertEqual(concurrent_bytes, agents_file.read_bytes())
            self.assertFalse((config / "hooks.json").exists())
            self.assertFalse((config / "skills" / "windows-command-preflight" / "SKILL.md").exists())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "v24").exists())

    def test_rollback_refuses_changed_created_file_before_removing_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            result = _install(config)
            hooks_file = config / "hooks.json"
            agents_file = config / "AGENTS.md"
            skill_file = config / "skills" / "windows-command-preflight" / "SKILL.md"
            changed_agents = b"Edited after install.\n"
            agents_file.write_bytes(changed_agents)

            with self.assertRaisesRegex(ValueError, "Rollback precondition failed for .*AGENTS.md"):
                toolkit.rollback(Path(result["transaction"]))

            self.assertEqual(changed_agents, agents_file.read_bytes())
            self.assertTrue(hooks_file.is_file())
            self.assertTrue(skill_file.is_file())
            self.assertTrue((config / "hooks" / "codex-windows-prevention" / "v24").is_dir())

    def test_duplicate_owned_entries_are_rejected_without_writes(self) -> None:
        for second_kind in ("legacy", "current"):
            with self.subTest(second_kind=second_kind), tempfile.TemporaryDirectory() as temporary:
                config = Path(temporary) / ".codex"
                config.mkdir()
                hooks_file = config / "hooks.json"
                agents_file = config / "AGENTS.md"
                second_command = (
                    'py -3 -B "C:\\Users\\test\\.codex\\hooks\\codex-command-guard\\v23\\bootstrap.py"'
                    if second_kind == "legacy"
                    else f'python -B "{config / "hooks" / "codex-windows-prevention" / "v24" / "bootstrap.py"}"'
                )
                hooks = {"hooks": {"SessionStart": [_legacy_entry(), _legacy_entry(second_command)]}}
                _write(hooks_file, json.dumps(hooks).encode("utf-8"))
                _write(agents_file, b"Existing rules.\n")
                original = {hooks_file: hooks_file.read_bytes(), agents_file: agents_file.read_bytes()}
                with self.assertRaisesRegex(ValueError, "at most one exact toolkit hook handler"):
                    _install(config)
                self.assertEqual(original, {path: path.read_bytes() for path in original})
                self.assertFalse((config / "hooks" / "codex-windows-prevention").exists())

    def test_old_v24_transaction_without_existence_flags_still_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            config.mkdir()
            hooks_file = config / "hooks.json"
            agents_file = config / "AGENTS.md"
            original_hooks = b'{"hooks":{}}'
            original_agents = b"Existing rules.\n"
            existing_skill = config / "skills" / "windows-command-preflight" / "SKILL.md"
            _write(hooks_file, original_hooks)
            _write(agents_file, original_agents)
            _write(existing_skill, b"Keep existing skill.\n")
            result = _install(config)
            transaction = Path(result["transaction"])
            metadata_path = transaction / "transaction.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            for details in metadata["files"].values():
                details.pop("before_exists", None)
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            rollback = toolkit.rollback(transaction)
            self.assertEqual("rolled_back", rollback["outcome"])
            self.assertEqual(original_hooks, hooks_file.read_bytes())
            self.assertEqual(original_agents, agents_file.read_bytes())


if __name__ == "__main__":
    unittest.main()
