#!/usr/bin/env python3
"""Portable stdlib tools for reviewing Windows command candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import guard


VERSION = 24
ROOT = Path(__file__).resolve().parent
PARSER_HELPER = ROOT / "ps_parse_helper.ps1"
MANAGED_MARKER = "# BEGIN CODEX WINDOWS PREVENTION V24"
END_MARKER = "# END CODEX WINDOWS PREVENTION V24"
SKILL_DESCRIPTION = "Prevent invalid Windows command construction before execution. Use before the first shell, managed-process, inventory, build, test, runtime, or repository-check command on Windows, and whenever changing execution surfaces, runtimes, path forms, or parallel orchestration after a failure."
KNOWN_TOOL_ALIASES = {
    "functions.shell_command": "shell_command",
    "functions.apply_patch": "apply_patch",
}
RECIPE_SECTIONS = {
    "source-read": "Read source text",
    "source-edit": "Edit source and JSON",
    "rg-literal": "Search files",
    "rg-glob": "Search files",
    "native-command": "Run native programs and scripts",
    "script-check": "Check script syntax without execution",
    "json-diagnostics": "Keep structured data separate from diagnostics",
    "cardinality": "Verify result counts and prerequisites",
    "prerequisites": "Verify result counts and prerequisites",
    "required-outputs": "Verify result counts and prerequisites",
    "test-selection": "Select and verify tests",
    "process-control": "Control processes",
}
SUPPORTED_TOOLS = {
    "Bash", "shell_command", "functions.shell_command", "exec_command",
    "unified_exec", "functions.apply_patch", "apply_patch",
    "mcp__process_manager__sync_run", "mcp__process_manager__bg_run",
    "process_manager.sync_run", "process_manager.bg_run", "sync_run", "bg_run",
}


@dataclass(frozen=True)
class Diagnostic:
    outcome: str
    rule_id: str
    message: str
    replacement: str


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8-sig", errors="strict")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".codex-write-", dir=str(path.parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def _absolute_lexical(path: Path) -> Path:
    """Make a path absolute without following junctions or symbolic links."""
    return Path(os.path.abspath(os.fspath(path)))


def _reject_reparse_components(path: Path, *, owned_root: Path | None = None) -> None:
    """Reject reparse points before any operation can follow an owned path."""
    absolute = _absolute_lexical(path)
    if owned_root is None:
        anchor = Path(absolute.anchor)
        parts = absolute.parts[1:]
    else:
        anchor = _absolute_lexical(owned_root)
        try:
            relative = absolute.relative_to(anchor)
        except ValueError as error:
            raise ValueError("Owned path is outside its supported root") from error
        parts = relative.parts
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    current = anchor
    for part in parts:
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        if current.is_symlink() or getattr(info, "st_file_attributes", 0) & reparse_flag:
            raise ValueError("Owned path contains a reparse point")
        current = current / part
    try:
        info = current.lstat()
    except FileNotFoundError:
        return
    if current.is_symlink() or getattr(info, "st_file_attributes", 0) & reparse_flag:
        raise ValueError("Owned path contains a reparse point")


def _verify_owned_tree(root: Path, expected_files: dict[str, str], *, allow_incomplete: bool = False, owned_root: Path | None = None) -> set[str]:
    root = _absolute_lexical(root)
    _reject_reparse_components(root, owned_root=owned_root)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        root_info = None
    if root_info is None or root.is_symlink() or getattr(root_info, "st_file_attributes", 0) & reparse_flag or not root.is_dir():
        raise ValueError("Owned package root is missing or is a reparse point")
    expected_dirs = {
        str(Path(relative).parent).replace("\\", "/")
        for relative in expected_files
        if str(Path(relative).parent) not in {"", "."}
    }
    for relative in expected_files:
        parent = Path(relative).parent
        while str(parent) not in {"", "."}:
            expected_dirs.add(str(parent).replace("\\", "/"))
            parent = parent.parent
    found_files: set[str] = set()
    found_dirs: set[str] = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            item = current_path / name
            info = item.lstat()
            if item.is_symlink() or getattr(info, "st_file_attributes", 0) & reparse_flag:
                raise ValueError(f"Owned package contains a reparse point: {item.name}")
            relative = item.relative_to(root).as_posix()
            if item.is_file():
                found_files.add(relative)
                expected = expected_files.get(relative)
                if expected is None:
                    raise ValueError(f"Owned package contains an unknown file: {relative}")
                if _digest(_read(item)) != expected:
                    raise ValueError(f"Owned package file changed: {relative}")
            elif item.is_dir():
                found_dirs.add(relative)
                if relative not in expected_dirs:
                    raise ValueError(f"Owned package contains an unknown directory: {relative}")
            else:
                raise ValueError(f"Owned package contains an unsupported filesystem entry: {relative}")
    if not allow_incomplete and (found_files != set(expected_files) or found_dirs != expected_dirs):
        raise ValueError("Owned package inventory changed")
    return found_files


def _tool_input(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("tool_input")
    return value if isinstance(value, dict) else {}


def _tool_name(payload: dict[str, Any]) -> str:
    name = payload.get("tool_name")
    return KNOWN_TOOL_ALIASES.get(name, name) if isinstance(name, str) else ""


def normalize_payload(payload: object) -> tuple[dict[str, Any] | None, str | None]:
    """Normalize known hook payloads without guessing unknown tool schemas."""
    if not isinstance(payload, dict):
        return None, "Payload must be a JSON object."
    name = _tool_name(payload)
    if name not in SUPPORTED_TOOLS:
        return None, "unsupported tool name"
    source = _tool_input(payload)
    value: object = source.get("command")
    if not isinstance(value, str):
        value = source.get("cmd")
    if not isinstance(value, str):
        args = source.get("args")
        if isinstance(args, dict):
            value = args.get("command", args.get("cmd"))
    if name in {"apply_patch", "functions.apply_patch"} and not isinstance(value, str):
        value = source.get("patch")
    if not isinstance(value, str) or not value.strip():
        return None, "unsupported command field shape"
    normalized = dict(payload)
    normalized_input = dict(source)
    normalized_input["command"] = value
    normalized["tool_input"] = normalized_input
    normalized["tool_name"] = name
    return normalized, None


def analyze_payload(payload: object) -> tuple[str, list[Diagnostic]]:
    normalized, issue = normalize_payload(payload)
    if issue:
        return "unsupported", [Diagnostic("unsupported", "INPUT-SHAPE-001", issue, "Check the tool schema and pass its literal command field.")]
    findings = guard.classify(normalized)
    if findings:
        return "invalid", [
            Diagnostic("invalid", finding.rule_id, finding.message, finding.message)
            for finding in findings
        ]
    return "clear_unverified", []


def safe_powershell_literal(value: str) -> str:
    if any(ord(char) < 32 and char not in "\t\r\n" for char in value):
        raise ValueError("PowerShell literal contains an unsupported control character")
    return "'" + value.replace("'", "''") + "'"


def safe_argv_template(program: str, arguments: list[str]) -> list[str]:
    """Return an argv template, preserving caller values as separate fields."""
    for value in [program, *arguments]:
        if "\x00" in value:
            raise ValueError("NUL cannot be passed in a process argument")
    return [program, *arguments]


def recommendations(rule_ids: list[str]) -> list[dict[str, Any]]:
    template_data = json.loads((ROOT / "templates.json").read_text(encoding="utf-8"))
    templates = template_data.get("templates", {})
    results: list[dict[str, str]] = []
    for rule_id in dict.fromkeys(rule_ids):
        template = templates.get(rule_id)
        if isinstance(template, dict) and isinstance(template.get("template"), str):
            results.append({"rule_id": rule_id, **template})
    return results


def _recipe_text(recipe_id: str) -> str:
    heading = RECIPE_SECTIONS[recipe_id]
    lines = (ROOT / "recipes.md").read_text(encoding="utf-8").splitlines()
    matches = [index for index, line in enumerate(lines) if line.strip() == f"## {heading}"]
    if len(matches) != 1:
        raise ValueError(f"Recipe section is missing or ambiguous: {recipe_id}")
    start = matches[0] + 1
    end = next((index for index in range(start, len(lines)) if lines[index].startswith("## ") or lines[index].startswith("# ")), len(lines))
    return "\n".join(lines[start:end]).strip()


def _run_hidden(argv: list[str], *, input_text: str | None = None, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    return subprocess.run(
        argv, input=input_text, text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        check=False, creationflags=flags,
    )


def _powershell_executable() -> str | None:
    # The managed .ps1 hook runs under Windows PowerShell 5.1.
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if system_root:
            managed = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            if managed.is_file():
                return str(managed)
    return shutil.which("powershell.exe")


def _parse_powershell(path: Path, executable: str | None = None) -> dict[str, Any]:
    if not path.is_file() or path.suffix.lower() != ".ps1":
        return {"outcome": "prerequisite_missing", "runtime": None, "diagnostics": [{"id": "POWERSHELL-FILE-001", "line": None, "column": None}]}
    exe = executable or _powershell_executable()
    if not exe:
        return {"outcome": "prerequisite_missing", "runtime": "PowerShell", "diagnostics": []}
    selected = Path(exe)
    if not selected.is_absolute() or selected.suffix.lower() != ".exe" or not selected.is_file():
        return {"outcome": "prerequisite_missing", "runtime": None, "executable": str(selected), "diagnostics": [{"id": "POWERSHELL-EXECUTABLE-001", "line": None, "column": None}]}
    helper = PARSER_HELPER.resolve()
    candidate = path.resolve()
    result = _run_hidden([str(selected), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(helper), str(candidate)])
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return {"outcome": "unsupported", "runtime": Path(exe).name, "executable": str(selected), "diagnostics": [{"id": "PARSER-OUTPUT-001", "line": None, "column": None}]}
    if result.returncode != 0:
        return {"outcome": "unsupported", "runtime": Path(exe).name, "executable": str(selected), "diagnostics": [{"id": "PARSER-EXECUTION-001", "line": None, "column": None}]}
    data["executable"] = str(selected)
    return data


def _doctor() -> dict[str, Any]:
    python_ok = sys.version_info >= (3, 10)
    ps_exe = _powershell_executable()
    powershell: dict[str, Any]
    if ps_exe:
        powershell = _parse_powershell(PARSER_HELPER, ps_exe)
        powershell["executable_found"] = True
        metadata_run = _run_hidden([
            ps_exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            str(PARSER_HELPER.resolve()), "-Mode", "Metadata",
        ])
        try:
            if metadata_run.returncode != 0:
                raise ValueError("metadata producer exited unsuccessfully")
            metadata = json.loads(metadata_run.stdout)
        except (json.JSONDecodeError, TypeError, ValueError):
            metadata = {"outcome": "unsupported", "tools": []}
        powershell["lookup_metadata"] = metadata
    else:
        powershell = {"outcome": "prerequisite_missing", "executable_found": False, "diagnostics": []}
    metadata_outcome = powershell.get("lookup_metadata", {}).get("outcome") if isinstance(powershell.get("lookup_metadata"), dict) else None
    required_checks_ok = python_ok and powershell.get("outcome") == "valid" and metadata_outcome == "valid"
    outcome = "valid" if required_checks_ok else (
        "prerequisite_missing" if not python_ok or powershell.get("outcome") == "prerequisite_missing" else "unsupported"
    )
    return {
        "outcome": outcome,
        "version": VERSION,
        "platform": platform.platform(),
        "python": {"version": platform.python_version(), "minimum_ok": python_ok},
        "powershell": powershell,
        "ripgrep": {"executable_found": bool(shutil.which("rg.exe") or shutil.which("rg"))},
        "candidate_execution": "never performed",
        "hook_trust_review": "required through the normal Codex hook trust flow before activation",
    }


def _validate(path: Path | None = None, fixtures: Path | None = None, powershell_executable: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"outcome": "valid", "checks": [], "candidate_execution": "never performed"}
    if path is None and fixtures is None:
        return {"outcome": "unsupported", "checks": [{"id": "VALIDATE-INPUT-001", "reason": "provide a PowerShell file or a behavior fixture set"}], "candidate_execution": "never performed"}
    if powershell_executable is not None and path is None:
        return {"outcome": "unsupported", "checks": [{"id": "VALIDATE-INPUT-001", "reason": "a PowerShell executable requires a PowerShell file"}], "candidate_execution": "never performed"}
    if path is not None:
        if not path.is_file():
            return {**result, "outcome": "prerequisite_missing", "checks": [{"id": "INPUT-FILE-MISSING-001"}]}
        parsed = _parse_powershell(path, str(powershell_executable) if powershell_executable is not None else None)
        result["checks"].append({"id": "POWERSHELL-PARSER-001", **parsed})
        result["outcome"] = parsed["outcome"]
    if fixtures is not None:
        try:
            cases = json.loads(fixtures.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {**result, "outcome": "invalid", "checks": result["checks"] + [{"id": "FIXTURE-DATA-001", "outcome": "invalid"}]}
        if not isinstance(cases, list):
            return {**result, "outcome": "invalid", "checks": result["checks"] + [{"id": "FIXTURE-SCHEMA-001", "outcome": "invalid"}]}
        outcomes: dict[str, int] = {}
        failures: list[dict[str, Any]] = []
        for index, case in enumerate(cases):
            if not isinstance(case, dict) or "expected" not in case:
                failures.append({"case": index, "id": "FIXTURE-CASE-SCHEMA-001"})
                continue
            actual = _evaluate_fixture(case)
            outcomes[actual] = outcomes.get(actual, 0) + 1
            if actual != case["expected"]:
                failures.append({"case": index, "id": "FIXTURE-OUTCOME-001", "expected": case["expected"], "actual": actual})
            if actual in {"invalid", "unsupported", "prerequisite_missing"}:
                replacement = case.get("replacement")
                replacement_expected = case.get("replacement_expected")
                if replacement is None or not isinstance(replacement_expected, str) or replacement_expected not in {"clear_unverified", "valid"}:
                    failures.append({"case": index, "id": "FIXTURE-REPLACEMENT-MISSING-001"})
                else:
                    replacement_actual = _evaluate_fixture({**case, "observation": replacement, "payload": replacement, "expected": replacement_expected, "replacement": None})
                    if replacement_actual != replacement_expected or replacement_actual not in {"clear_unverified", "valid"}:
                        failures.append({"case": index, "id": "FIXTURE-REPLACEMENT-OUTCOME-001", "expected": replacement_expected, "actual": replacement_actual})
        result["checks"].append({"id": "FIXTURE-SET-001", "count": len(cases), "evidence": "synthetic behavior contract cases, not historical audit records", "outcomes": outcomes, "failures": failures})
        if failures:
            result["outcome"] = "invalid"
    return result


def _evaluate_fixture(case: dict[str, Any]) -> str:
    kind = case.get("kind", "payload")
    if kind == "payload":
        if "payload" not in case:
            return "unsupported"
        return analyze_payload(case["payload"])[0]
    observation = case.get("observation")
    if not isinstance(observation, dict):
        return "unsupported"
    if kind == "test-selection":
        suite = observation.get("expected_suite")
        selected = observation.get("selected_suite")
        count = observation.get("test_count")
        if not isinstance(suite, str) or not suite or not isinstance(selected, str) or not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return "unsupported"
        return "valid" if selected == suite and count > 0 else "invalid"
    if kind == "lookup-cardinality":
        count = observation.get("match_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return "unsupported"
        return "valid" if count == 1 else "invalid"
    if kind == "prerequisites":
        checks = observation.get("checks")
        if not isinstance(checks, list) or not checks or any(not isinstance(value, str) or value not in {"passed", "failed", "unknown"} for value in checks):
            return "unsupported"
        if "unknown" in checks:
            return "unsupported"
        return "valid" if all(value == "passed" for value in checks) else "prerequisite_missing"
    if kind == "required-outputs":
        required = observation.get("required")
        present = observation.get("present")
        if not isinstance(required, list) or not required or not isinstance(present, list) or any(not isinstance(value, str) for value in required + present):
            return "unsupported"
        return "valid" if set(required) <= set(present) else "invalid"
    if kind == "homogeneous-results":
        kinds = observation.get("result_kinds")
        if not isinstance(kinds, list) or not kinds or any(not isinstance(item, str) or not item for item in kinds):
            return "unsupported"
        return "valid" if len(set(kinds)) == 1 else "invalid"
    return "unsupported"


def _expected_hash(path: Path, expected: str) -> bytes:
    raw = _read(path)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected) or _digest(raw).lower() != expected.lower():
        raise ValueError(f"Precondition failed for {path}: bytes do not match the supplied SHA-256.")
    return raw


def _skill_pointer_bytes(install_root: Path) -> bytes:
    detailed = quote((install_root / "skills" / "windows-command-preflight" / "SKILL.md").resolve().as_posix(), safe=":/")
    recipes = quote((install_root / "recipes.md").resolve().as_posix(), safe=":/")
    text = (
        "---\n"
        "name: windows-command-preflight\n"
        f"description: {SKILL_DESCRIPTION}\n"
        "---\n\n"
        "# Windows Command Preflight\n\n"
        "Read the installed Windows command preflight and recipes before constructing commands.\n\n"
        f"- [Detailed preflight](<{detailed}>)\n"
        f"- [Command recipes](<{recipes}>)\n"
    )
    return text.encode("utf-8")


def _verify_transaction_files(transaction: Path, files: dict[str, dict[str, str]], written: set[str]) -> None:
    for path_text, details in files.items():
        backup_path = transaction / details["backup"]
        if _digest(_read(backup_path)) != details["before"]:
            raise RuntimeError(f"Transaction backup changed: {details['backup']}")
        expected = details["after"] if path_text in written else details["before"]
        if _digest(_read(Path(path_text))) != expected:
            raise RuntimeError(f"Configuration changed during install: {Path(path_text).name}")


def _replace_owned_hook_table(original: dict[str, Any], install_root: Path) -> tuple[dict[str, Any], dict[str, int]]:
    hooks = original.get("hooks")
    if not isinstance(hooks, dict):
        raise ValueError("hooks.json must contain an object named hooks")
    root = install_root.resolve()
    command = subprocess.list2cmdline([sys.executable, "-B", str(root / "bootstrap.py")])
    replaced: dict[str, int] = {}
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        entries = hooks.get(event)
        if not isinstance(entries, list):
            raise ValueError(f"hooks.{event} must be a list")
        found: list[tuple[int, int, dict[str, Any]]] = []
        for entry_index, entry in enumerate(entries):
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                continue
            for hook_index, hook in enumerate(entry["hooks"]):
                if not isinstance(hook, dict):
                    continue
                command_values = [hook.get(key) for key in ("command", "commandWindows")]
                owned = any(
                    isinstance(value, str)
                    and re.search(r"(?i)codex-command-guard[\\/]v23[\\/]bootstrap\.py(?:\"|')?\s*$", value)
                    for value in command_values
                )
                if owned:
                    found.append((entry_index, hook_index, hook))
        if len(found) != 1:
            raise ValueError(f"Expected one exact v23 hook entry for {event}, found {len(found)}")
        entry_index, hook_index, hook = found[0]
        if hook.get("type") != "command":
            raise ValueError(f"Owned {event} hook has an unsupported type")
        hook["command"] = command
        if "commandWindows" in hook:
            hook["commandWindows"] = command
        status_message = hook.get("statusMessage")
        if isinstance(status_message, str) and re.search(r"\bv23\b", status_message):
            hook["statusMessage"] = re.sub(r"\bv23\b", "v24", status_message)
        replaced[event] = entry_index
    return original, replaced


def install(config_dir: Path, source: Path, expected_hooks_hash: str, expected_agents_hash: str, plan_only: bool = False, expected_skill_sha256: str | None = None) -> dict[str, Any]:
    """Install with full preflight, snapshots, owned-change rollback on failure."""
    config_dir = _absolute_lexical(config_dir)
    _reject_reparse_components(config_dir)
    hooks_path = config_dir / "hooks.json"
    agents_path = config_dir / "AGENTS.md"
    source = source.resolve()
    if not source.is_dir():
        raise ValueError("Candidate source directory is missing")
    original_hooks = _expected_hash(hooks_path, expected_hooks_hash)
    original_agents = _expected_hash(agents_path, expected_agents_hash)
    skill_path: Path | None = None
    original_skill: bytes | None = None
    updated_skill: bytes | None = None
    if expected_skill_sha256 is not None:
        skill_path = config_dir / "skills" / "windows-command-preflight" / "SKILL.md"
        original_skill = _expected_hash(skill_path, expected_skill_sha256)
    if source == config_dir.resolve() or config_dir.resolve() in source.parents:
        raise ValueError("Source and destination layout is unsafe")
    hooks_obj = json.loads(_decode(original_hooks))
    agents_text = _decode(original_agents)
    if MANAGED_MARKER in agents_text or END_MARKER in agents_text:
        raise ValueError("AGENTS.md already contains a managed v24 block")
    source_files = [
        "windows_prevention.py", "guard.py", "bootstrap.py", "ps_parse_helper.ps1",
        "manifest.json", "README.md", "NOTICE.md", "LICENSE", "templates.json", "recipes.md",
        "manifest-v23-source.json", "audit_summary.json", "evidence.md", "evidence-references.json",
        "skills/windows-command-preflight/SKILL.md",
    ]
    fixture_files = sorted(
        path.relative_to(source).as_posix()
        for path in (source / "fixtures").rglob("*")
        if path.is_file()
    )
    source_files.extend(fixture_files)
    for filename in source_files:
        if not (source / filename).is_file():
            raise ValueError(f"Candidate file is missing: {filename}")
    install_root = _absolute_lexical(config_dir / "hooks" / "codex-windows-prevention" / f"v{VERSION}")
    _reject_reparse_components(install_root, owned_root=config_dir)
    if install_root.exists():
        raise ValueError(f"Install destination already exists: {install_root}")
    if skill_path is not None:
        updated_skill = _skill_pointer_bytes(install_root)
    updated_hooks, replaced_hooks = _replace_owned_hook_table(hooks_obj, install_root)
    block = (
        f"\n{MANAGED_MARKER}\n"
        "For Windows commands, check the execution surface, working directory, runtime, literal paths, syntax, and expected result count. Use profile-free non-interactive PowerShell for cmdlets. Report failures and verify the replacement. Keep the existing Wippy Makefile and local port rules.\n"
        f"Read the detailed preflight at `{install_root / 'skills' / 'windows-command-preflight' / 'SKILL.md'}` and command recipes at `{install_root / 'recipes.md'}`.\n"
        f"{END_MARKER}\n"
    )
    updated_agents = (agents_text.rstrip("\r\n") + block).encode("utf-8")
    updated_hooks_raw = _json_bytes(updated_hooks)
    package_hashes = {
        filename: _digest(_read(source / filename))
        for filename in source_files
    }
    plan = {
        "outcome": "planned",
        "changes": [
            {"path": str(install_root), "operation": "create package files", "file_count": len(source_files)},
            {"path": str(hooks_path), "operation": "replace existing v23 guard commands in place", "events": replaced_hooks},
            {"path": str(agents_path), "operation": "append short Windows preflight pointer"},
        ],
        "preserved": "all other hook entries, matchers, GitKraken entries, and hook state remain as found",
        "activation": "Hook trust review and any enable action remain user controlled. Existing disabled state is preserved.",
        "trusted_hash_changes": 0,
        "candidate_commands_executed": False,
    }
    if skill_path is not None:
        plan["changes"].append({"path": str(skill_path), "operation": "replace existing skill with a short pointer to installed detailed guidance"})
    if plan_only:
        return plan
    transaction_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    transaction = config_dir / "hooks" / "codex-windows-prevention" / "transactions" / transaction_id
    transaction.mkdir(parents=True, exist_ok=False)
    files = {
        str(hooks_path): {"before": _digest(original_hooks), "after": _digest(updated_hooks_raw), "backup": "hooks.json.before"},
        str(agents_path): {"before": _digest(original_agents), "after": _digest(updated_agents), "backup": "AGENTS.md.before"},
    }
    if skill_path is not None and original_skill is not None and updated_skill is not None:
        files[str(skill_path)] = {"before": _digest(original_skill), "after": _digest(updated_skill), "backup": "SKILL.md.before"}
    snapshot = {
        "version": VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "include_skill": skill_path is not None,
        "files": files,
        "install_root": str(install_root),
        "config_dir": str(config_dir),
        "package_files": package_hashes,
    }
    (transaction / "hooks.json.before").write_bytes(original_hooks)
    (transaction / "AGENTS.md.before").write_bytes(original_agents)
    if skill_path is not None and original_skill is not None:
        (transaction / "SKILL.md.before").write_bytes(original_skill)
    _write_atomic(transaction / "plan.json", _json_bytes(plan))
    _write_atomic(transaction / "transaction.json", _json_bytes(snapshot))
    try:
        _verify_transaction_files(transaction, files, set())
    except (OSError, RuntimeError) as error:
        raise RuntimeError(f"Install precondition changed after transaction plan creation: {transaction}")
    written: list[Path] = []
    try:
        install_root.mkdir(parents=True, exist_ok=False)
        for filename in source_files:
            target_path = install_root / filename
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / filename, target_path)
            if _digest(_read(target_path)) != package_hashes[filename]:
                raise OSError(f"Package read-back mismatch for {filename}")
        _verify_owned_tree(install_root, package_hashes, owned_root=config_dir)
        _verify_transaction_files(transaction, files, set())
        _write_atomic(hooks_path, updated_hooks_raw)
        written.append(hooks_path)
        written_text = {str(path) for path in written}
        _verify_transaction_files(transaction, files, written_text)
        _write_atomic(agents_path, updated_agents)
        written.append(agents_path)
        written_text = {str(path) for path in written}
        _verify_transaction_files(transaction, files, written_text)
        if skill_path is not None and updated_skill is not None:
            _write_atomic(skill_path, updated_skill)
            written.append(skill_path)
            written_text = {str(path) for path in written}
            _verify_transaction_files(transaction, files, written_text)
        if _digest(_read(hooks_path)) != snapshot["files"][str(hooks_path)]["after"]:
            raise OSError("hooks.json read-back mismatch")
        if _digest(_read(agents_path)) != snapshot["files"][str(agents_path)]["after"]:
            raise OSError("AGENTS.md read-back mismatch")
        if skill_path is not None and updated_skill is not None and _digest(_read(skill_path)) != snapshot["files"][str(skill_path)]["after"]:
            raise OSError("Skill read-back mismatch")
    except BaseException as error:
        residual: list[str] = []
        for path in reversed(written):
            expected = snapshot["files"][str(path)]["after"]
            try:
                if _digest(_read(path)) == expected:
                    details = snapshot["files"][str(path)]
                    backup_path = transaction / details["backup"]
                    backup = _read(backup_path)
                    if _digest(backup) != details["before"]:
                        residual.append(str(path))
                        continue
                    _write_atomic(path, backup)
                else:
                    residual.append(str(path))
            except OSError:
                residual.append(str(path))
        try:
            _reject_reparse_components(install_root, owned_root=config_dir)
            if install_root.exists():
                _verify_owned_tree(install_root, package_hashes, allow_incomplete=True, owned_root=config_dir)
                shutil.rmtree(install_root)
        except OSError:
            residual.append(str(install_root))
        except ValueError as package_error:
            residual.append(f"{install_root} ({type(package_error).__name__})")
        raise RuntimeError(f"Install failed: {type(error).__name__}; residual paths: {residual}; transaction: {transaction}") from error
    return {**plan, "outcome": "installed", "transaction": str(transaction), "plan_file": str(transaction / "plan.json"), "trust_review": "required through normal Codex hook trust flow"}


def rollback(transaction_dir: Path) -> dict[str, Any]:
    transaction_dir = _absolute_lexical(transaction_dir)
    _reject_reparse_components(transaction_dir)
    metadata = json.loads((transaction_dir / "transaction.json").read_text(encoding="utf-8"))
    if metadata.get("version") != VERSION or not isinstance(metadata.get("files"), dict):
        raise ValueError("Transaction metadata is unsupported")
    raw_config_dir = Path(metadata.get("config_dir", ""))
    if not raw_config_dir.is_absolute():
        raise ValueError("Transaction config directory must be absolute")
    config_dir = _absolute_lexical(raw_config_dir)
    _reject_reparse_components(config_dir)
    expected_transaction_parent = _absolute_lexical(config_dir / "hooks" / "codex-windows-prevention" / "transactions")
    if transaction_dir.parent != expected_transaction_parent:
        raise ValueError("Transaction directory is outside its supported config destination")
    if transaction_dir.name in {"", ".", ".."}:
        raise ValueError("Transaction directory name is invalid")
    expected_hooks_path = _absolute_lexical(config_dir / "hooks.json")
    expected_agents_path = _absolute_lexical(config_dir / "AGENTS.md")
    include_skill = metadata.get("include_skill", False)
    if not isinstance(include_skill, bool):
        raise ValueError("Transaction optional skill flag is invalid")
    expected_skill_path = _absolute_lexical(config_dir / "skills" / "windows-command-preflight" / "SKILL.md")
    expected_install_root = _absolute_lexical(config_dir / "hooks" / "codex-windows-prevention" / f"v{VERSION}")
    allowed_paths = {str(expected_hooks_path), str(expected_agents_path)}
    if include_skill:
        allowed_paths.add(str(expected_skill_path))
    if any(not Path(value).is_absolute() for value in metadata["files"]) or set(map(lambda value: str(_absolute_lexical(Path(value))), metadata["files"].keys())) != allowed_paths:
        raise ValueError("Transaction contains paths outside its supported config files")
    if not Path(metadata.get("install_root", "")).is_absolute() or _absolute_lexical(Path(metadata.get("install_root", ""))) != expected_install_root:
        raise ValueError("Transaction install path is outside its supported destination")
    preflight: list[tuple[Path, bytes, bytes, str, Path]] = []
    expected_package = metadata.get("package_files")
    if not isinstance(expected_package, dict) or any(not isinstance(key, str) or Path(key).is_absolute() or ".." in Path(key).parts for key in expected_package):
        raise ValueError("Transaction package inventory is invalid")
    install_root = expected_install_root
    _verify_owned_tree(install_root, expected_package, owned_root=config_dir)
    for path_text, data in metadata["files"].items():
        path = Path(path_text)
        if not path.is_absolute():
            raise ValueError("Transaction contains a relative configuration path")
        path = _absolute_lexical(path)
        _reject_reparse_components(path, owned_root=config_dir)
        current = _read(path)
        if _digest(current) != data.get("after"):
            raise ValueError(f"Rollback precondition failed for {path}; installed bytes changed")
        backup_name = data.get("backup")
        if path == expected_hooks_path:
            expected_backup = "hooks.json.before"
        elif path == expected_agents_path:
            expected_backup = "AGENTS.md.before"
        elif include_skill and path == expected_skill_path:
            expected_backup = "SKILL.md.before"
        else:
            raise ValueError("Transaction contains an unsupported configuration path")
        if backup_name != expected_backup:
            raise ValueError(f"Transaction backup path is invalid for {path}")
        backup_path = transaction_dir / backup_name
        _reject_reparse_components(backup_path, owned_root=transaction_dir)
        backup = _read(backup_path)
        if _digest(backup) != data.get("before"):
            raise ValueError(f"Transaction backup check failed for {path}")
        preflight.append((path, current, backup, data["before"], backup_path))
    restored: list[Path] = []
    try:
        restored_set: set[Path] = set()
        for path, expected_current, backup, before_hash, backup_path in preflight:
            for candidate, candidate_current, candidate_backup, candidate_before, candidate_backup_path in preflight:
                expected_live = candidate_backup if candidate in restored_set else candidate_current
                if _digest(_read(candidate)) != _digest(expected_live):
                    raise ValueError(f"Rollback target changed after preflight: {candidate}")
                if _digest(_read(candidate_backup_path)) != candidate_before:
                    raise ValueError(f"Rollback backup changed after preflight: {candidate.name}")
            _verify_owned_tree(install_root, expected_package, owned_root=config_dir)
            _reject_reparse_components(path, owned_root=config_dir)
            _write_atomic(path, backup)
            restored.append(path)
            restored_set.add(path)
        for path, _, backup, _, _ in preflight:
            if _digest(_read(path)) != _digest(backup):
                raise OSError(f"Read-back mismatch for {path}")
    except BaseException as error:
        raise RuntimeError(f"Rollback incomplete after {type(error).__name__}; restored paths: {[str(p) for p in restored]}") from error
    _reject_reparse_components(install_root, owned_root=config_dir)
    if install_root.exists():
        _verify_owned_tree(install_root, expected_package, owned_root=config_dir)
        shutil.rmtree(install_root)
    return {"outcome": "rolled_back", "restored": [str(path) for path in restored]}


def _emit(value: Any) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="windows_prevention")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("doctor")
    recommend_parser = sub.add_parser("recommend")
    recommendation_input = recommend_parser.add_mutually_exclusive_group(required=True)
    recommendation_input.add_argument("--payload", type=Path)
    recommendation_input.add_argument("--recipe", choices=tuple(RECIPE_SECTIONS))
    recommendation_input.add_argument("--list-recipes", action="store_true")
    recommend_parser.add_argument("--show-command", action="store_true")
    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--powershell-file", type=Path)
    validate_parser.add_argument("--powershell-executable", type=Path)
    validate_parser.add_argument("--fixtures", type=Path)
    install_parser = sub.add_parser("install")
    install_parser.add_argument("--config-dir", type=Path, required=True)
    install_parser.add_argument("--source", type=Path, default=ROOT)
    install_parser.add_argument("--expected-hooks-sha256", required=True)
    install_parser.add_argument("--expected-agents-sha256", required=True)
    install_parser.add_argument("--expected-skill-sha256")
    install_parser.add_argument("--plan-only", action="store_true")
    rollback_parser = sub.add_parser("rollback")
    rollback_parser.add_argument("--transaction", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "doctor":
            output = _doctor()
        elif args.action == "recommend":
            if args.list_recipes:
                output = {"outcome": "available", "recipes": [{"id": recipe_id, "section": section} for recipe_id, section in RECIPE_SECTIONS.items()]}
            elif args.recipe:
                output = {"outcome": "available", "recipe": args.recipe, "section": RECIPE_SECTIONS[args.recipe], "instructions": _recipe_text(args.recipe), "candidate_execution": "never performed"}
            else:
                if args.show_command and args.payload is None:
                    raise ValueError("--show-command requires --payload")
                payload = json.loads(args.payload.read_text(encoding="utf-8"))
                outcome, diagnostics = analyze_payload(payload)
                output = {"outcome": outcome, "interpretation": "no known violation was found; command correctness and prerequisites remain unverified" if outcome == "clear_unverified" else None, "diagnostics": [asdict(item) for item in diagnostics], "recommendations": recommendations([item.rule_id for item in diagnostics]), "command_included": False}
                if args.show_command and isinstance(payload, dict):
                    normalized, issue = normalize_payload(payload)
                    if normalized is not None:
                        output["command"] = normalized["tool_input"]["command"]
                        output["command_included"] = True
        elif args.action == "validate":
            output = _validate(args.powershell_file, args.fixtures, args.powershell_executable)
        elif args.action == "install":
            output = install(args.config_dir, args.source, args.expected_hooks_sha256, args.expected_agents_sha256, args.plan_only, args.expected_skill_sha256)
        else:
            output = rollback(args.transaction)
        _emit(output)
        return 0 if output.get("outcome") not in {"invalid", "unsupported", "prerequisite_missing"} else 2
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired, RuntimeError) as error:
        _emit({"outcome": "invalid", "diagnostics": [{"id": "TOOL-OPERATION-001", "error_type": type(error).__name__, "message": "The operation could not complete. Verify required inputs, current hashes, package ownership, and access before retrying.", "replacement": "Use a read-only validation or install plan with inspected current inputs. For rollback, verify the transaction and current files before writing."}]})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
