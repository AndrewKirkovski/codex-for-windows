from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import windows_prevention as toolkit


ROOT = Path(__file__).resolve().parent


def _install(config: Path) -> dict[str, object]:
    return toolkit.install(config, ROOT)


def _portable_copy(destination: Path) -> Path:
    shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns("__pycache__", "test_*.py"))
    return destination


def _load_module(package_root: Path, name: str):
    sys.path.insert(0, str(package_root))
    try:
        spec = importlib.util.spec_from_file_location(name, package_root / "windows_prevention.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("Could not load installed toolkit module")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class SelfUpdateTests(unittest.TestCase):
    def test_owned_root_parser_uses_absolute_script_token_with_spaces_and_unicode(self) -> None:
        package_root = Path(r"C:\Users\Zoë Smith\.codex\hooks\codex-windows-prevention") / "revisions" / ("a" * 64)
        command = subprocess.list2cmdline([
            r"C:\Program Files\Python 3.12\python.exe",
            "-B",
            str(package_root / "bootstrap.py"),
        ])
        self.assertEqual(package_root, toolkit._extract_owned_root(command))
        self.assertTrue(toolkit._managed_handler_command(command, package_root))

    def test_status_detects_fresh_install_and_noop_update_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            self.assertEqual("missing", toolkit.status(config)["outcome"])
            installed = _install(config)
            self.assertEqual("installed", toolkit.status(config)["outcome"])
            before = {path: path.read_bytes() for path in (config / "hooks.json", config / "AGENTS.md")}
            result = toolkit.update(config, ROOT)
            self.assertEqual("already_current", result["outcome"])
            self.assertEqual(0, result["writes"])
            self.assertEqual(before, {path: path.read_bytes() for path in before})
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "active.json").exists())
            self.assertTrue(Path(installed["transaction"]).is_dir())

    def test_update_preserves_later_unrelated_hook_and_prompt_edits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / ".codex"
            _install(config)
            hooks_path = config / "hooks.json"
            agents_path = config / "AGENTS.md"
            hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
            unrelated = {"matcher": "CustomTool", "hooks": [{"type": "command", "command": "keep-user-hook"}]}
            hooks["hooks"].setdefault("PreToolUse", []).append(unrelated)
            hooks_path.write_text(json.dumps(hooks, ensure_ascii=False), encoding="utf-8")
            user_prose = "\nUser added this after install.\n"
            with agents_path.open("a", encoding="utf-8", newline="") as stream:
                stream.write(user_prose)
            candidate = _portable_copy(base / "reviewed-toolkit")
            with (candidate / "README.md").open("ab") as stream:
                stream.write(b"\nReviewed update fixture.\n")

            result = toolkit.update(config, candidate)
            self.assertEqual("updated", result["outcome"])
            self.assertIn(user_prose, agents_path.read_text(encoding="utf-8"))
            self.assertIn(unrelated, json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"])
            self.assertEqual("installed", toolkit.status(config)["outcome"])

    def test_update_refuses_changed_owned_block_and_package_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            _install(config)
            agents_path = config / "AGENTS.md"
            agents_path.write_text(agents_path.read_text(encoding="utf-8").replace("profile-free", "profile-full"), encoding="utf-8")
            before = agents_path.read_bytes()
            result = toolkit.status(config)
            self.assertEqual("modified", result["outcome"])
            with self.assertRaisesRegex(ValueError, "Managed AGENTS block changed"):
                toolkit.update(config, ROOT)
            self.assertEqual(before, agents_path.read_bytes())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "active.json").exists())

        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            _install(config)
            bootstrap = config / "hooks" / "codex-windows-prevention" / "v24" / "bootstrap.py"
            bootstrap.write_bytes(bootstrap.read_bytes() + b"\n# modified\n")
            with self.assertRaisesRegex(ValueError, "Installed package has no verifiable ownership record"):
                toolkit.update(config, ROOT)
            self.assertEqual("modified", toolkit.status(config)["outcome"])

    def test_legacy_owned_matcher_change_is_reported_and_blocks_update(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            installed = _install(config)
            transaction = Path(installed["transaction"])
            metadata_path = transaction / "transaction.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertIn("owned_handlers", metadata)
            self.assertFalse((transaction / "hooks.json.before").exists())
            metadata.pop("owned_handlers")
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            hooks_path = config / "hooks.json"
            hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
            hooks["hooks"]["PreToolUse"][0]["matcher"] = ".*"
            hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
            before = hooks_path.read_bytes()
            self.assertEqual("modified", toolkit.status(config)["outcome"])
            with self.assertRaisesRegex(ValueError, "Owned PreToolUse matcher changed"):
                toolkit.update(config, ROOT)
            self.assertEqual(before, hooks_path.read_bytes())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "active.json").exists())

    def test_legacy_migration_matcher_is_reconstructed_from_verified_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            config.mkdir()
            hooks_path = config / "hooks.json"
            legacy = {
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": 'py -3 -B "C:\\Users\\test\\.codex\\hooks\\codex-command-guard\\v23\\bootstrap.py"',
                    "commandWindows": 'py -3 -B "C:\\Users\\test\\.codex\\hooks\\codex-command-guard\\v23\\bootstrap.py"',
                    "timeout": 900,
                }],
            }
            hooks_path.write_text(json.dumps({"hooks": {"SessionStart": [legacy]}}), encoding="utf-8")
            installed = toolkit.install(config, ROOT)
            transaction = Path(installed["transaction"])
            self.assertTrue((transaction / "hooks.json.before").is_file())
            hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
            hooks["hooks"]["SessionStart"][0]["matcher"] = "ChangedMatcher"
            hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
            self.assertEqual("modified", toolkit.status(config)["outcome"])
            with self.assertRaisesRegex(ValueError, "Owned SessionStart matcher changed"):
                toolkit.update(config, ROOT)

    def test_legacy_history_skips_stale_package_records_but_rejects_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            installed = _install(config)
            transaction_root = config / "hooks" / "codex-windows-prevention" / "transactions"
            current_transaction = Path(installed["transaction"])
            current_metadata = json.loads((current_transaction / "transaction.json").read_text(encoding="utf-8"))

            stale_metadata = json.loads(json.dumps(current_metadata))
            stale_metadata["package_files"]["evidence.md"] = "0" * 64
            stale_transaction = transaction_root / "historical-stale"
            stale_transaction.mkdir()
            (stale_transaction / "transaction.json").write_text(json.dumps(stale_metadata), encoding="utf-8")
            self.assertEqual("installed", toolkit.status(config)["outcome"])

            duplicate_transaction = transaction_root / "duplicate-valid"
            duplicate_transaction.mkdir()
            (duplicate_transaction / "transaction.json").write_text(json.dumps(current_metadata), encoding="utf-8")
            hooks_before = (config / "hooks.json").read_bytes()
            agents_before = (config / "AGENTS.md").read_bytes()
            self.assertEqual("modified", toolkit.status(config)["outcome"])
            with self.assertRaisesRegex(ValueError, "no verifiable ownership record"):
                toolkit.update(config, ROOT)
            self.assertEqual(hooks_before, (config / "hooks.json").read_bytes())
            self.assertEqual(agents_before, (config / "AGENTS.md").read_bytes())

    def test_update_failure_preserves_concurrent_change_and_recovers_owned_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / ".codex"
            _install(config)
            hooks_path = config / "hooks.json"
            agents_path = config / "AGENTS.md"
            original_hooks = hooks_path.read_bytes()
            concurrent_agents = b"Concurrent edit during update.\n"
            candidate = _portable_copy(base / "reviewed-toolkit")
            with (candidate / "README.md").open("ab") as stream:
                stream.write(b"\nUpdate failure probe.\n")
            original_write_atomic = toolkit._write_atomic
            injected = False

            def race_after_hook_write(path: Path, data: bytes) -> None:
                nonlocal injected
                original_write_atomic(path, data)
                if path == hooks_path and not injected:
                    agents_path.write_bytes(concurrent_agents)
                    injected = True

            with patch.object(toolkit, "_write_atomic", side_effect=race_after_hook_write):
                with self.assertRaisesRegex(RuntimeError, "Update failed"):
                    toolkit.update(config, candidate)

            self.assertTrue(injected)
            self.assertEqual(original_hooks, hooks_path.read_bytes())
            self.assertEqual(concurrent_agents, agents_path.read_bytes())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "active.json").exists())
            revisions = config / "hooks" / "codex-windows-prevention" / "revisions"
            self.assertFalse(revisions.exists() and any(revisions.iterdir()))

    def test_update_rollback_restores_previous_globals_and_keeps_previous_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / ".codex"
            _install(config)
            hooks = config / "hooks.json"
            agents = config / "AGENTS.md"
            current_hooks = json.loads(hooks.read_text(encoding="utf-8"))
            current_hooks["hooks"].setdefault("OtherEvent", []).append({"hooks": [{"type": "command", "command": "preserve"}]})
            hooks.write_text(json.dumps(current_hooks), encoding="utf-8")
            with agents.open("a", encoding="utf-8", newline="") as stream:
                stream.write("\nCurrent user prose.\n")
            before_hooks, before_agents = hooks.read_bytes(), agents.read_bytes()
            candidate = _portable_copy(base / "reviewed-toolkit")
            with (candidate / "README.md").open("ab") as stream:
                stream.write(b"\nUpdate marker.\n")
            result = toolkit.update(config, candidate)
            new_root = Path(result["package_root"])
            rollback = toolkit.rollback(Path(result["transaction"]))
            self.assertEqual("rolled_back", rollback["outcome"])
            self.assertEqual(before_hooks, hooks.read_bytes())
            self.assertEqual(before_agents, agents.read_bytes())
            self.assertFalse(new_root.exists())
            self.assertTrue((config / "hooks" / "codex-windows-prevention" / "v24").is_dir())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "active.json").exists())

    def test_update_rollback_rechecks_targets_and_backups_before_each_write(self) -> None:
        for change_kind in ("target", "backup"):
            with self.subTest(change_kind=change_kind), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                config = base / ".codex"
                _install(config)
                candidate = _portable_copy(base / "reviewed-toolkit")
                with (candidate / "README.md").open("ab") as stream:
                    stream.write(b"\nConcurrent rollback probe.\n")
                result = toolkit.update(config, candidate)
                transaction = Path(result["transaction"])
                hooks = config / "hooks.json"
                agents = config / "AGENTS.md"
                agents_after_update = agents.read_bytes()
                user_bytes = b"Concurrent user content.\n"
                backup_path = transaction / "AGENTS.md.before"
                original_write_atomic = toolkit._write_atomic
                injected = False

                def inject_before_first_restore(path: Path, data: bytes) -> None:
                    nonlocal injected
                    if path == hooks and not injected:
                        injected = True
                        if change_kind == "target":
                            agents.write_bytes(user_bytes)
                        else:
                            backup_path.write_bytes(b"Changed rollback backup.\n")
                    original_write_atomic(path, data)

                with patch.object(toolkit, "_write_atomic", side_effect=inject_before_first_restore):
                    with self.assertRaisesRegex(RuntimeError, "Rollback incomplete after ValueError"):
                        toolkit.rollback(transaction)
                self.assertTrue(injected)
                if change_kind == "target":
                    self.assertEqual(user_bytes, agents.read_bytes())
                else:
                    self.assertEqual(agents_after_update, agents.read_bytes())
                    self.assertEqual(b"Changed rollback backup.\n", backup_path.read_bytes())

    def test_status_flags_wrong_owned_hook_type_as_modified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            _install(config)
            hooks_path = config / "hooks.json"
            hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
            hooks["hooks"]["SessionStart"][0]["hooks"][0]["type"] = "other"
            hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
            self.assertEqual("modified", toolkit.status(config)["outcome"])

    def test_default_config_precedence_and_relative_source_are_package_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            explicit = base / "explicit"
            environment = base / "environment"
            with patch.dict(os.environ, {"CODEX_HOME": str(environment)}):
                self.assertEqual(explicit, toolkit._resolve_config_dir(explicit))
                self.assertEqual(environment, toolkit._resolve_config_dir())
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(0, toolkit.main(["install", "--plan-only"]))
                self.assertEqual("planned", json.loads(output.getvalue())["outcome"])
                self.assertFalse(environment.exists())
            with patch.dict(os.environ, {}, clear=True), patch.object(Path, "home", return_value=base):
                self.assertEqual(base / ".codex", toolkit._resolve_config_dir())
            self.assertEqual((ROOT / "bundle").resolve(), toolkit._resolve_source(Path("bundle")))

    def test_installed_module_discovers_config_and_updates_from_its_own_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / ".codex"
            install_result = _install(config)
            update_source = _portable_copy(base / "portable-toolkit")
            with (update_source / "README.md").open("ab") as stream:
                stream.write(b"\nPortable update.\n")
            updated = toolkit.update(config, update_source)
            installed_root = Path(updated["package_root"])
            self.assertEqual("updated", updated["outcome"])

            installed_module = _load_module(installed_root, "installed_windows_prevention_test")
            self.assertEqual(config, installed_module._resolve_config_dir())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status_code = installed_module.main(["status"])
            self.assertEqual(0, status_code)
            self.assertEqual("installed", json.loads(output.getvalue())["outcome"])
            with contextlib.redirect_stdout(output := io.StringIO()):
                update_status = installed_module.main(["update"])
            self.assertEqual(0, update_status)
            self.assertEqual("already_current", json.loads(output.getvalue())["outcome"])
            self.assertTrue(Path(install_result["transaction"]).is_dir())

    def test_installed_cli_status_without_dash_b_does_not_write_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / ".codex"
            _install(config)
            candidate = _portable_copy(base / "reviewed-toolkit")
            with (candidate / "README.md").open("ab") as stream:
                stream.write(b"\nNo bytecode probe.\n")
            result = toolkit.update(config, candidate)
            installed_root = Path(result["package_root"])
            self.assertEqual("updated", result["outcome"])
            self.assertFalse(list(installed_root.rglob("__pycache__")))

            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("CODEX_HOME", None)
            completed = subprocess.run(
                [sys.executable, str(installed_root / "windows_prevention.py"), "status"],
                cwd=base,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("installed", json.loads(completed.stdout)["outcome"])
            self.assertFalse(list(installed_root.rglob("__pycache__")))

    def test_user_owned_skill_survives_revision_update(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / ".codex"
            skill = config / "skills" / "windows-command-preflight" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            original = b"User-owned skill.\n"
            skill.write_bytes(original)
            _install(config)
            candidate = _portable_copy(base / "reviewed-toolkit")
            with (candidate / "README.md").open("ab") as stream:
                stream.write(b"\nSkill preservation case.\n")
            result = toolkit.update(config, candidate)
            self.assertEqual("updated", result["outcome"])
            self.assertEqual(original, skill.read_bytes())
            self.assertFalse(any(Path(result["transaction"]).glob("SKILL.md.before")))

    def test_duplicate_owned_guard_in_another_event_refuses_update(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / ".codex"
            _install(config)
            hooks_path = config / "hooks.json"
            hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
            copied = json.loads(json.dumps(hooks["hooks"]["SessionStart"][0]))
            hooks["hooks"].setdefault("OtherEvent", []).append(copied)
            hooks_path.write_text(json.dumps(hooks), encoding="utf-8")
            before_hooks = hooks_path.read_bytes()
            with self.assertRaisesRegex(ValueError, "unsupported hook event"):
                toolkit.update(config, ROOT)
            self.assertEqual(before_hooks, hooks_path.read_bytes())
            self.assertFalse((config / "hooks" / "codex-windows-prevention" / "active.json").exists())


if __name__ == "__main__":
    unittest.main()
