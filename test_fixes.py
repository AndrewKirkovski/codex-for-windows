from __future__ import annotations

import contextlib
import hashlib
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


STAGE = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get("WINDOWS_PREVENTION_SOURCE_ROOT", STAGE))
sys.path.insert(0, str(STAGE))
import windows_prevention as toolkit  # noqa: E402

toolkit.ROOT = SOURCE
toolkit.PARSER_HELPER = SOURCE / "ps_parse_helper.ps1"
FIXTURES: Path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(root: Path, path: Path) -> Path:
    root_abs = Path(os.path.abspath(root))
    path_abs = Path(os.path.abspath(path))
    path_abs.relative_to(root_abs)
    return path_abs


def _junction(link: Path, target: Path, fixture_root: Path) -> None:
    link = _inside(fixture_root, link)
    target = _inside(fixture_root, target)
    if not target.is_dir():
        raise AssertionError("junction target must already exist")
    executable = shutil.which("powershell.exe")
    if not executable:
        raise unittest.SkipTest("Windows PowerShell is unavailable for junction fixture creation")
    ps_literal = lambda value: "'" + str(value).replace("'", "''") + "'"
    command = f"New-Item -ItemType Junction -Path {ps_literal(link)} -Target {ps_literal(target)} | Out-Null"
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Junction fixture creation failed with exit {result.returncode}: {(result.stdout + result.stderr).strip()}")


class ReviewFixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        global FIXTURES
        cls.fixture_owner = tempfile.TemporaryDirectory(prefix="toolkit-review-fixes-", dir=STAGE)
        FIXTURES = Path(cls.fixture_owner.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_owner.cleanup()

    def _setup(self, root: Path) -> tuple[Path, Path, Path, str, str]:
        config = root / "codex"
        config.mkdir()
        hooks = config / "hooks.json"
        agents = config / "AGENTS.md"
        old_command = 'py -3 -B "C:\\Users\\test\\.codex\\hooks\\codex-command-guard\\v23\\bootstrap.py"'
        owned = {"matcher": "Bash", "hooks": [{"type": "command", "command": old_command, "commandWindows": old_command, "timeout": 2}]}
        unrelated = {"matcher": "*", "hooks": [{"type": "command", "command": "GitKraken helper"}]}
        hooks.write_text(json.dumps({"description": "local", "hooks": {event: [owned, unrelated] for event in ("SessionStart", "UserPromptSubmit", "PreToolUse")}}), encoding="utf-8")
        agents.write_text("Existing runtime and GitKraken rules.\n", encoding="utf-8")
        return config, hooks, agents, _sha(hooks), _sha(agents)

    def _install(self, root: Path) -> tuple[Path, Path, Path, dict[str, object], str, str]:
        config, hooks, agents, hooks_hash, agents_hash = self._setup(root)
        result = toolkit.install(config, SOURCE, hooks_hash, agents_hash)
        self.assertEqual("installed", result["outcome"])
        return config, hooks, agents, result, hooks_hash, agents_hash

    def test_relative_config_is_saved_absolute_and_rolls_back_after_cwd_change(self) -> None:
        with tempfile.TemporaryDirectory(dir=FIXTURES) as temp:
            root = Path(temp)
            config, hooks, agents, hooks_hash, agents_hash = self._setup(root)
            other_cwd = root / "elsewhere"
            other_cwd.mkdir()
            previous = Path.cwd()
            try:
                os.chdir(root)
                result = toolkit.install(Path("codex"), SOURCE, hooks_hash, agents_hash)
                transaction = Path(str(result["transaction"]))
                metadata = json.loads((transaction / "transaction.json").read_text(encoding="utf-8"))
                self.assertTrue(Path(metadata["config_dir"]).is_absolute())
                self.assertTrue(transaction.is_absolute())
                os.chdir(other_cwd)
                rollback = toolkit.rollback(transaction)
            finally:
                os.chdir(previous)
            self.assertEqual("rolled_back", rollback["outcome"])
            self.assertEqual(hooks_hash, _sha(hooks))
            self.assertEqual(agents_hash, _sha(agents))

    def test_rollback_rejects_package_root_junction_before_restore_or_delete(self) -> None:
        with tempfile.TemporaryDirectory(dir=FIXTURES) as temp:
            root = Path(temp)
            config, hooks, agents, result, _, _ = self._install(root)
            install_root = config / "hooks" / "codex-windows-prevention" / "v24"
            moved_package = root / "moved-package"
            _inside(root, install_root)
            _inside(root, moved_package)
            install_root.rename(moved_package)
            _junction(install_root, moved_package, root)
            after_hooks, after_agents = hooks.read_bytes(), agents.read_bytes()
            try:
                with patch.object(toolkit.shutil, "rmtree", side_effect=AssertionError("must not delete through junction")):
                    with self.assertRaisesRegex(ValueError, "reparse point"):
                        toolkit.rollback(Path(str(result["transaction"])))
                self.assertEqual(after_hooks, hooks.read_bytes())
                self.assertEqual(after_agents, agents.read_bytes())
                self.assertTrue((moved_package / "guard.py").is_file())
            finally:
                os.rmdir(install_root)

    def test_rollback_rejects_owned_ancestor_junction_before_restore_or_delete(self) -> None:
        with tempfile.TemporaryDirectory(dir=FIXTURES) as temp:
            root = Path(temp)
            config, hooks, agents, result, _, _ = self._install(root)
            owned_parent = config / "hooks" / "codex-windows-prevention"
            moved_parent = root / "moved-owned-parent"
            _inside(root, owned_parent)
            _inside(root, moved_parent)
            owned_parent.rename(moved_parent)
            _junction(owned_parent, moved_parent, root)
            after_hooks, after_agents = hooks.read_bytes(), agents.read_bytes()
            transaction = Path(str(result["transaction"]))
            try:
                with patch.object(toolkit.shutil, "rmtree", side_effect=AssertionError("must not delete through junction")):
                    with self.assertRaisesRegex(ValueError, "reparse point"):
                        toolkit.rollback(transaction)
                self.assertEqual(after_hooks, hooks.read_bytes())
                self.assertEqual(after_agents, agents.read_bytes())
                self.assertTrue((moved_parent / "v24" / "guard.py").is_file())
            finally:
                os.rmdir(owned_parent)

    def test_verify_owned_tree_checks_components_before_traversal(self) -> None:
        with tempfile.TemporaryDirectory(dir=FIXTURES) as temp:
            root = Path(temp)
            config, hooks, agents, result, _, _ = self._install(root)
            actual_parent = config / "hooks" / "codex-windows-prevention"
            target = root / "actual-parent"
            actual_parent.rename(target)
            _junction(actual_parent, target, root)
            try:
                with self.assertRaisesRegex(ValueError, "reparse point"):
                    toolkit._verify_owned_tree(actual_parent / "v24", json.loads((Path(str(result["transaction"])) / "transaction.json").read_text(encoding="utf-8"))["package_files"], owned_root=config)
            finally:
                os.rmdir(actual_parent)

    def test_default_powerShell_selection_matches_managed_ps1_runtime(self) -> None:
        with tempfile.TemporaryDirectory(dir=FIXTURES) as temp:
            system_root = Path(temp)
            managed = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            managed.parent.mkdir(parents=True)
            managed.write_bytes(b"fixture executable path")
            with patch.dict(toolkit.os.environ, {"SystemRoot": str(system_root)}), patch.object(
                toolkit.shutil, "which", side_effect=lambda name: {"pwsh.exe": "C:/Program Files/PowerShell/7/pwsh.exe", "powershell.exe": "C:/Other/WindowsPowerShell/powershell.exe"}.get(name)
            ):
                self.assertEqual(str(managed), toolkit._powershell_executable())

    def test_doctor_rejects_nonzero_metadata_producer_even_with_valid_json(self) -> None:
        fake_exe = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        completed = subprocess.CompletedProcess([fake_exe], 1, '{"outcome":"valid","tools":[]}', "")
        valid_parse = {"outcome": "valid", "runtime": "5.1", "diagnostics": []}
        with patch.object(toolkit, "_powershell_executable", return_value=fake_exe), patch.object(
            toolkit, "_parse_powershell", return_value=valid_parse.copy()
        ), patch.object(toolkit, "_run_hidden", return_value=completed):
            report = toolkit._doctor()
        self.assertEqual("unsupported", report["outcome"])
        self.assertEqual("unsupported", report["powershell"]["lookup_metadata"]["outcome"])

    def test_public_validate_selects_exact_runtime_without_running_candidate(self) -> None:
        ps51 = shutil.which("powershell.exe")
        ps7 = shutil.which("pwsh.exe")
        if not ps51 or not ps7:
            self.skipTest("Both Windows PowerShell 5.1 and PowerShell 7 are required")
        with tempfile.TemporaryDirectory(dir=FIXTURES) as temp:
            root = Path(temp)
            candidate = root / "candidate.ps1"
            sentinel = root / "candidate-was-run.txt"
            candidate.write_text(f"$value = $null ?? 5\nSet-Content -LiteralPath '{sentinel}' -Value 'executed'\n", encoding="utf-8")
            reports: dict[str, dict[str, object]] = {}
            for label, executable in (("5.1", ps51), ("7", ps7)):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    status = toolkit.main(["validate", "--powershell-file", str(candidate), "--powershell-executable", executable])
                report = json.loads(stdout.getvalue())
                self.assertEqual(2 if label == "5.1" else 0, status)
                check = report["checks"][0]
                self.assertEqual(executable, check["executable"])
                self.assertTrue(check["runtime"].startswith("5.1" if label == "5.1" else "7."))
                reports[label] = report
            self.assertEqual("invalid", reports["5.1"]["outcome"])
            self.assertEqual("valid", reports["7"]["outcome"])
            self.assertFalse(sentinel.exists())

    def test_validate_rejects_bad_explicit_executable_without_launching(self) -> None:
        with tempfile.TemporaryDirectory(dir=FIXTURES) as temp:
            root = Path(temp)
            candidate = root / "candidate.ps1"
            candidate.write_text("$value = 1\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = toolkit.main(["validate", "--powershell-file", str(candidate), "--powershell-executable", "pwsh.exe"])
            self.assertEqual(2, status)
            report = json.loads(stdout.getvalue())
            self.assertEqual("prerequisite_missing", report["outcome"])
            self.assertEqual("POWERSHELL-EXECUTABLE-001", report["checks"][0]["diagnostics"][0]["id"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    existing_tests = SOURCE / "test_toolkit.py"
    if existing_tests.is_file():
        spec = importlib.util.spec_from_file_location("existing_toolkit_tests", existing_tests)
        if spec is None or spec.loader is None:
            raise RuntimeError("Could not load the existing toolkit tests")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
