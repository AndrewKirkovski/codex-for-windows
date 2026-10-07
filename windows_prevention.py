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
import shlex
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

if __name__ == "__main__":
    sys.dont_write_bytecode = True

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


def _snapshot_config_file(path: Path, expected: str | None) -> bytes | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if expected is not None:
            raise ValueError(f"Precondition failed for {path}: file is missing.")
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Precondition failed for {path}: expected a regular file.")
    raw = _read(path)
    if expected is not None and (not re.fullmatch(r"[0-9a-fA-F]{64}", expected) or _digest(raw).lower() != expected.lower()):
        raise ValueError(f"Precondition failed for {path}: bytes do not match the supplied SHA-256.")
    return raw


def _matches_file_state(path: Path, *, exists: bool, digest: str | None = None) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return not exists
    if not exists or not stat.S_ISREG(info.st_mode):
        return False
    return digest is None or _digest(_read(path)) == digest


def _write_new(path: Path, data: bytes) -> None:
    """Create a file without replacing a path that appeared after preflight."""
    _reject_reparse_components(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".codex-write-", dir=str(path.parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, path)
    finally:
        try:
            temp.unlink()
        except OSError:
            pass


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


def _package_file_names(source: Path) -> list[str]:
    names = [
        "windows_prevention.py", "guard.py", "bootstrap.py", "ps_parse_helper.ps1",
        "manifest.json", "README.md", "NOTICE.md", "LICENSE", "templates.json", "recipes.md",
        "manifest-v23-source.json", "audit_summary.json", "evidence.md", "evidence-references.json",
        "skills/windows-command-preflight/SKILL.md",
    ]
    fixtures = source / "fixtures"
    if fixtures.exists():
        names.extend(sorted(path.relative_to(source).as_posix() for path in fixtures.rglob("*") if path.is_file()))
    return names


def _package_hashes(source: Path) -> dict[str, str]:
    names = _package_file_names(source)
    for name in names:
        if not (source / name).is_file():
            raise ValueError(f"Candidate file is missing: {name}")
    return {name: _digest(_read(source / name)) for name in names}


def _package_id(package_files: dict[str, str]) -> str:
    canonical = json.dumps(package_files, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _digest(canonical)


def _manager_root(config_dir: Path) -> Path:
    return config_dir / "hooks" / "codex-windows-prevention"


def _active_record_path(config_dir: Path) -> Path:
    return _manager_root(config_dir) / "active.json"


def _config_from_package_root(package_root: Path) -> Path | None:
    root = _absolute_lexical(package_root)
    manager: Path | None = None
    if root.parent.name.casefold() == "codex-windows-prevention":
        manager = root.parent
    elif root.parent.name.casefold() == "revisions" and root.parent.parent.name.casefold() == "codex-windows-prevention":
        manager = root.parent.parent
    if manager is None or manager.parent.name.casefold() != "hooks":
        return None
    return manager.parent.parent


def _resolve_config_dir(value: Path | None = None) -> Path:
    if value is not None:
        return _absolute_lexical(value)
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return _absolute_lexical(Path(codex_home))
    installed = _config_from_package_root(ROOT)
    return installed if installed is not None else _absolute_lexical(Path.home() / ".codex")


def _resolve_source(value: Path | None) -> Path:
    if value is None:
        return ROOT.resolve()
    return (value if value.is_absolute() else ROOT / value).resolve()


def _managed_block(install_root: Path) -> str:
    return (
        f"{MANAGED_MARKER}\n"
        "For Windows commands, check the execution surface, working directory, runtime, literal paths, syntax, and expected result count. Use profile-free non-interactive PowerShell for cmdlets. Report failures and verify the replacement. Keep the existing Wippy Makefile and local port rules.\n"
        f"Read the detailed preflight at `{install_root / 'skills' / 'windows-command-preflight' / 'SKILL.md'}` and command recipes at `{install_root / 'recipes.md'}`.\n"
        f"{END_MARKER}\n"
    )


def _extract_managed_block(text: str) -> tuple[int, int, str]:
    if text.count(MANAGED_MARKER) != 1 or text.count(END_MARKER) != 1:
        raise ValueError("Managed AGENTS block is missing or duplicated")
    start = text.index(MANAGED_MARKER)
    end_marker = text.index(END_MARKER, start)
    if end_marker < start:
        raise ValueError("Managed AGENTS block is malformed")
    end = end_marker + len(END_MARKER)
    if text[end:end + 2] == "\r\n":
        end += 2
    elif text[end:end + 1] in {"\r", "\n"}:
        end += 1
    return start, end, text[start:end].replace("\r\n", "\n").replace("\r", "\n")


def _extract_owned_root(command: object) -> Path | None:
    if not isinstance(command, str):
        return None
    try:
        tokens = [token.strip("\"'") for token in shlex.split(command, posix=False)]
    except ValueError as error:
        if re.search(r"(?i)codex-(?:windows-prevention|command-guard).*bootstrap\.py", command):
            raise ValueError("Malformed toolkit handler command") from error
        return None
    path_pattern = re.compile(
        r"(?i)^([a-z]:\\.*\\(?:codex-windows-prevention\\(?:v24|revisions\\[0-9a-f]{64})|codex-command-guard\\v23))\\bootstrap\.py$"
    )
    for token in tokens:
        normalized = token.replace("/", "\\")
        match = path_pattern.fullmatch(normalized)
        if match is not None:
            return _absolute_lexical(Path(match.group(0))).parent
        if re.search(r"(?i)codex-(?:windows-prevention|command-guard).*bootstrap\.py", normalized):
            raise ValueError("Malformed toolkit handler script path")
    return None


def _managed_handler_command(command: object, install_root: Path) -> bool:
    if not isinstance(command, str):
        return False
    try:
        parts = [part.strip("\"'") for part in shlex.split(command, posix=False)]
    except ValueError:
        return False
    if len(parts) != 3 or parts[1].casefold() != "-b":
        return False
    if not re.fullmatch(r"(?i)python(?:w|[0-9.]*)?\.exe", Path(parts[0]).name):
        return False
    script = _absolute_lexical(Path(parts[2]))
    expected = _absolute_lexical(install_root / "bootstrap.py")
    return os.path.normcase(str(script)) == os.path.normcase(str(expected))


def _owned_handlers(hooks_obj: dict[str, Any]) -> tuple[dict[str, list[tuple[dict[str, Any], dict[str, Any]]]], set[Path]]:
    by_event: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    roots: set[Path] = set()
    hooks = hooks_obj.get("hooks")
    if not isinstance(hooks, dict):
        return by_event, roots
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        found: list[tuple[dict[str, Any], dict[str, Any]]] = []
        entries = hooks.get(event, [])
        if not isinstance(entries, list):
            raise ValueError(f"hooks.{event} must be a list")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                continue
            for handler in entry["hooks"]:
                if not isinstance(handler, dict):
                    continue
                candidates = [_extract_owned_root(handler.get(key)) for key in ("command", "commandWindows")]
                roots.update(root for root in candidates if root is not None)
                if any(root is not None for root in candidates):
                    found.append((entry, handler))
        by_event[event] = found
    for event, entries in hooks.items():
        if event in by_event or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                continue
            for handler in entry["hooks"]:
                if isinstance(handler, dict) and any(_extract_owned_root(handler.get(key)) is not None for key in ("command", "commandWindows")):
                    raise ValueError(f"Toolkit handler found in unsupported hook event: {event}")
    return by_event, roots


def _owned_handler_snapshot(hooks_obj: dict[str, Any]) -> dict[str, dict[str, Any]]:
    handlers, _ = _owned_handlers(hooks_obj)
    snapshot: dict[str, dict[str, Any]] = {}
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        if len(handlers.get(event, [])) != 1:
            raise ValueError(f"Cannot record ambiguous {event} handler fields")
        entry, handler = handlers[event][0]
        if handler.get("type") != "command":
            raise ValueError(f"Owned {event} handler has an unsupported type")
        snapshot[event] = {
            "matcher_present": "matcher" in entry,
            "matcher": entry.get("matcher"),
            "handler_fields": {key: value for key, value in handler.items() if key not in {"command", "commandWindows"}},
        }
    return snapshot


def _verify_owned_handler_snapshot(hooks_obj: dict[str, Any], snapshot: object) -> None:
    if not isinstance(snapshot, dict):
        raise ValueError("Owned handler snapshot is invalid")
    handlers, _ = _owned_handlers(hooks_obj)
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        expected = snapshot.get(event)
        if not isinstance(expected, dict) or len(handlers.get(event, [])) != 1:
            raise ValueError(f"Owned {event} handler snapshot is missing or ambiguous")
        entry, handler = handlers[event][0]
        if handler.get("type") != "command":
            raise ValueError(f"Owned {event} handler type changed")
        if expected.get("matcher_present") != ("matcher" in entry) or expected.get("matcher") != entry.get("matcher"):
            raise ValueError(f"Owned {event} matcher changed")
        actual_fields = {key: value for key, value in handler.items() if key not in {"command", "commandWindows"}}
        if expected.get("handler_fields") != actual_fields:
            raise ValueError(f"Owned {event} handler fields changed")


def _replace_block(text: str, current_root: Path, new_root: Path) -> str:
    start, end, block = _extract_managed_block(text)
    if block != _managed_block(current_root):
        raise ValueError("Managed AGENTS block changed after installation")
    newline = "\r\n" if "\r\n" in text else "\n"
    return text[:start] + _managed_block(new_root).replace("\n", newline) + text[end:]


def _legacy_install_record(config_dir: Path, install_root: Path) -> dict[str, Any] | None:
    transaction_root = _manager_root(config_dir) / "transactions"
    if not transaction_root.is_dir():
        return None
    matches: list[tuple[Path, dict[str, Any]]] = []
    for metadata_path in transaction_root.glob("*/transaction.json"):
        try:
            _reject_reparse_components(metadata_path, owned_root=_manager_root(config_dir))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if metadata.get("version") != VERSION or metadata.get("kind") == "revision_update":
            continue
        if metadata.get("install_root") != str(install_root):
            continue
        package_files = metadata.get("package_files")
        if isinstance(package_files, dict):
            try:
                _verify_owned_tree(install_root, package_files, owned_root=config_dir)
            except ValueError as error:
                stale_inventory = (
                    str(error) == "Owned package inventory changed"
                    or str(error).startswith((
                        "Owned package file changed:",
                        "Owned package contains unknown file:",
                        "Owned package contains unknown directory:",
                    ))
                )
                if stale_inventory:
                    continue
                raise
            matches.append((metadata_path.parent, metadata))
    if len(matches) != 1:
        return None
    transaction_path, record = matches[0]
    package_files = record["package_files"]
    file_records = record.get("files")
    hooks_record = file_records.get(str(config_dir / "hooks.json")) if isinstance(file_records, dict) else None
    if not isinstance(hooks_record, dict):
        raise ValueError("Prior hooks transaction record is invalid")
    hooks_backup = transaction_path / "hooks.json.before"
    if hooks_record.get("before_exists", True):
        hooks_before = json.loads(_decode(_read(hooks_backup)))
        if _digest(_read(hooks_backup)) != hooks_record.get("before"):
            raise ValueError("Prior hooks backup changed")
    else:
        if hooks_record.get("before") is not None:
            raise ValueError("Prior hooks absence record is invalid")
        hooks_before = {"hooks": {}}
    if not isinstance(hooks_before, dict):
        raise ValueError("Prior hook snapshot is invalid")
    expected_hooks, _ = _replace_owned_hook_table(hooks_before, install_root)
    reconstructed = _owned_handler_snapshot(expected_hooks)
    recorded = record.get("owned_handlers")
    if recorded is not None and recorded != reconstructed:
        raise ValueError("Recorded owned hook fields do not match the transaction plan")
    record = {**record, "owned_handlers": recorded if isinstance(recorded, dict) else reconstructed}
    return record


def _load_install_record(config_dir: Path, install_root: Path) -> tuple[dict[str, Any], bool]:
    active_path = _active_record_path(config_dir)
    try:
        _reject_reparse_components(active_path, owned_root=config_dir)
        record = json.loads(active_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        legacy = _legacy_install_record(config_dir, install_root)
        if legacy is None:
            raise ValueError("Installed package has no verifiable ownership record")
        files = legacy.get("files", {})
        skill = str(config_dir / "skills" / "windows-command-preflight" / "SKILL.md") in files
        return {
            "package_root": str(install_root),
            "package_files": legacy["package_files"],
            "skill_owned": skill,
            "owned_handlers": legacy["owned_handlers"],
        }, False
    if not isinstance(record, dict) or record.get("format") != "codex-windows-prevention-active-v1":
        raise ValueError("Active install record is invalid")
    if record.get("package_root") != str(install_root) or not isinstance(record.get("package_files"), dict):
        raise ValueError("Active install record does not match the active package")
    _verify_owned_tree(install_root, record["package_files"], owned_root=config_dir)
    if not isinstance(record.get("skill_owned"), bool):
        raise ValueError("Active install skill ownership is invalid")
    return record, True


def status(config_dir: Path | None = None) -> dict[str, Any]:
    config = _resolve_config_dir(config_dir)
    hooks_path = config / "hooks.json"
    agents_path = config / "AGENTS.md"
    if not config.exists() and not hooks_path.exists() and not agents_path.exists():
        return {"outcome": "missing", "config_dir": str(config), "writes": 0}
    if not hooks_path.is_file() or not agents_path.is_file():
        return {"outcome": "conflicting", "config_dir": str(config), "reason": "configuration files are incomplete", "writes": 0}
    try:
        hooks_obj = json.loads(_decode(_read(hooks_path)))
        if not isinstance(hooks_obj, dict):
            raise ValueError("hooks.json must contain an object")
        handlers, roots = _owned_handlers(hooks_obj)
        agents_text = _decode(_read(agents_path))
        if not roots and MANAGED_MARKER not in agents_text:
            return {"outcome": "missing", "config_dir": str(config), "writes": 0}
        if len(roots) != 1 or any(len(handlers.get(event, [])) != 1 for event in ("SessionStart", "UserPromptSubmit", "PreToolUse")):
            return {"outcome": "conflicting", "config_dir": str(config), "reason": "owned hooks are missing or duplicated", "writes": 0}
        root = next(iter(roots))
        if _config_from_package_root(root) != config:
            return {"outcome": "conflicting", "config_dir": str(config), "reason": "hook target is outside the active config", "writes": 0}
        record, _ = _load_install_record(config, root)
        if "owned_handlers" in record:
            _verify_owned_handler_snapshot(hooks_obj, record["owned_handlers"])
        block = _extract_managed_block(_decode(_read(agents_path)))[2]
        if block != _managed_block(root):
            return {"outcome": "modified", "config_dir": str(config), "package_root": str(root), "reason": "managed AGENTS block changed", "writes": 0}
        if record["skill_owned"]:
            skill_path = config / "skills" / "windows-command-preflight" / "SKILL.md"
            if _read(skill_path) != _skill_pointer_bytes(root):
                return {"outcome": "modified", "config_dir": str(config), "package_root": str(root), "reason": "managed skill pointer changed", "writes": 0}
        expected_command = record.get("hook_command")
        if isinstance(expected_command, str):
            for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
                handler = handlers[event][0][1]
                if handler.get("command") != expected_command or ("commandWindows" in handler and handler["commandWindows"] != expected_command):
                    return {"outcome": "modified", "config_dir": str(config), "package_root": str(root), "reason": f"managed {event} handler changed", "writes": 0}
        for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
            handler = handlers[event][0][1]
            if handler.get("type") != "command":
                return {"outcome": "modified", "config_dir": str(config), "package_root": str(root), "reason": f"managed {event} handler type changed", "writes": 0}
            if not _managed_handler_command(handler.get("command"), root):
                return {"outcome": "modified", "config_dir": str(config), "package_root": str(root), "reason": f"managed {event} command shape changed", "writes": 0}
            if "commandWindows" in handler and not _managed_handler_command(handler["commandWindows"], root):
                return {"outcome": "modified", "config_dir": str(config), "package_root": str(root), "reason": f"managed {event} Windows command shape changed", "writes": 0}
        return {"outcome": "installed", "config_dir": str(config), "package_root": str(root), "package_sha256": _package_id(record["package_files"]), "skill_owned": record["skill_owned"], "writes": 0}
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        return {"outcome": "modified", "config_dir": str(config), "reason": type(error).__name__, "writes": 0}


def _verify_transaction_files(transaction: Path, files: dict[str, dict[str, Any]], written: set[str], *, verify_backups: bool = True) -> None:
    for path_text, details in files.items():
        _reject_reparse_components(Path(path_text))
        existed_before = details.get("before_exists", True)
        if not isinstance(existed_before, bool):
            raise RuntimeError(f"Transaction existence flag is invalid: {Path(path_text).name}")
        if existed_before and verify_backups:
            backup_path = transaction / details["backup"]
            if _digest(_read(backup_path)) != details["before"]:
                raise RuntimeError(f"Transaction backup changed: {details['backup']}")
        path = Path(path_text)
        if path_text in written:
            expected = details.get("after")
            if not isinstance(expected, str) or not _matches_file_state(path, exists=True, digest=expected):
                raise RuntimeError(f"Configuration changed during install: {path.name}")
        elif existed_before:
            if not _matches_file_state(path, exists=True, digest=details.get("before")):
                raise RuntimeError(f"Configuration changed during install: {path.name}")
        elif not _matches_file_state(path, exists=False):
            raise RuntimeError(f"Configuration file appeared during install: {path.name}")


def _new_hook_entry(event: str, command: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"hooks": [{"type": "command", "command": command, "commandWindows": command}]}
    if event == "PreToolUse":
        entry["matcher"] = "^(?:" + "|".join(re.escape(name) for name in sorted(SUPPORTED_TOOLS)) + ")$"
    return entry


def _replace_owned_hook_table(original: dict[str, Any], install_root: Path) -> tuple[dict[str, Any], dict[str, int]]:
    if "hooks" not in original:
        original["hooks"] = {}
    hooks = original.get("hooks")
    if not isinstance(hooks, dict):
        raise ValueError("hooks.json must contain an object named hooks")
    root = install_root.resolve()
    command = subprocess.list2cmdline([sys.executable, "-B", str(root / "bootstrap.py")])
    current_target = str(root / "bootstrap.py").replace("/", "\\").casefold()
    replaced: dict[str, int] = {}
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        if event not in hooks:
            hooks[event] = []
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
                    and (
                        re.search(r"(?i)codex-command-guard[\\/]v23[\\/]bootstrap\.py(?:\"|')?\s*$", value)
                        or value.rstrip("\"' ").replace("/", "\\").casefold().endswith(current_target)
                    )
                    for value in command_values
                )
                if owned:
                    found.append((entry_index, hook_index, hook))
        if len(found) > 1:
            raise ValueError(f"Expected at most one exact toolkit hook handler for {event}, found {len(found)}")
        if not found:
            entries.append(_new_hook_entry(event, command))
            replaced[event] = len(entries) - 1
            continue
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


def install(config_dir: Path | None = None, source: Path | None = None, expected_hooks_hash: str | None = None, expected_agents_hash: str | None = None, plan_only: bool = False, expected_skill_sha256: str | None = None) -> dict[str, Any]:
    """Install with full preflight, snapshots, owned-change rollback on failure."""
    config_dir = _resolve_config_dir(config_dir)
    _reject_reparse_components(config_dir)
    hooks_path = config_dir / "hooks.json"
    agents_path = config_dir / "AGENTS.md"
    source = _resolve_source(source)
    if not source.is_dir():
        raise ValueError("Candidate source directory is missing")
    _reject_reparse_components(hooks_path, owned_root=config_dir)
    _reject_reparse_components(agents_path, owned_root=config_dir)
    original_hooks = _snapshot_config_file(hooks_path, expected_hooks_hash)
    original_agents = _snapshot_config_file(agents_path, expected_agents_hash)
    skill_path: Path | None = None
    original_skill: bytes | None = None
    updated_skill: bytes | None = None
    skill_candidate = config_dir / "skills" / "windows-command-preflight" / "SKILL.md"
    _reject_reparse_components(skill_candidate, owned_root=config_dir)
    try:
        skill_info = skill_candidate.lstat()
    except FileNotFoundError:
        if expected_skill_sha256 is not None:
            raise ValueError(f"Precondition failed for {skill_candidate}: file is missing.")
        skill_path = skill_candidate
    else:
        if not stat.S_ISREG(skill_info.st_mode):
            raise ValueError("Existing preflight skill is not a regular file")
        if expected_skill_sha256 is not None:
            skill_path = skill_candidate
            original_skill = _expected_hash(skill_candidate, expected_skill_sha256)
    if source == config_dir.resolve() or config_dir.resolve() in source.parents:
        raise ValueError("Source and destination layout is unsafe")
    if original_hooks is None:
        hooks_obj: dict[str, Any] = {"hooks": {}}
    else:
        parsed_hooks = json.loads(_decode(original_hooks))
        if not isinstance(parsed_hooks, dict):
            raise ValueError("hooks.json must contain a JSON object")
        hooks_obj = parsed_hooks
    agents_text = _decode(original_agents) if original_agents is not None else ""
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
        f"{MANAGED_MARKER}\n"
        "For Windows commands, check the execution surface, working directory, runtime, literal paths, syntax, and expected result count. Use profile-free non-interactive PowerShell for cmdlets. Report failures and verify the replacement. Keep the existing Wippy Makefile and local port rules.\n"
        f"Read the detailed preflight at `{install_root / 'skills' / 'windows-command-preflight' / 'SKILL.md'}` and command recipes at `{install_root / 'recipes.md'}`.\n"
        f"{END_MARKER}\n"
    )
    newline = "\r\n" if "\r\n" in agents_text else "\n"
    separator = "" if not agents_text or agents_text.endswith(("\n", "\r")) else newline
    agents_bom = b"\xef\xbb\xbf" if original_agents is not None and original_agents.startswith(b"\xef\xbb\xbf") else b""
    updated_agents = agents_bom + (agents_text + separator + block.replace("\n", newline)).encode("utf-8")
    updated_hooks_raw = _json_bytes(updated_hooks)
    package_hashes = {
        filename: _digest(_read(source / filename))
        for filename in source_files
    }
    plan = {
        "outcome": "planned",
        "changes": [
            {"path": str(install_root), "operation": "create package files", "file_count": len(source_files)},
            {"path": str(hooks_path), "operation": "add or update one toolkit handler per event", "events": replaced_hooks},
            {"path": str(agents_path), "operation": "append short Windows preflight pointer"},
        ],
        "preserved": "all other hook entries, matchers, GitKraken entries, and hook state remain as found",
        "activation": "Hook trust review and any enable action remain user controlled. Existing disabled state is preserved.",
        "trusted_hash_changes": 0,
        "candidate_commands_executed": False,
    }
    if skill_path is not None:
        operation = "create a short pointer to installed detailed guidance" if original_skill is None else "replace existing skill with a short pointer to installed detailed guidance"
        plan["changes"].append({"path": str(skill_path), "operation": operation})
    if plan_only:
        return plan
    transaction_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    transaction = config_dir / "hooks" / "codex-windows-prevention" / "transactions" / transaction_id
    files = {
        str(hooks_path): {"before_exists": original_hooks is not None, "before": _digest(original_hooks) if original_hooks is not None else None, "after": _digest(updated_hooks_raw), "backup": "hooks.json.before"},
        str(agents_path): {"before_exists": original_agents is not None, "before": _digest(original_agents) if original_agents is not None else None, "after": _digest(updated_agents), "backup": "AGENTS.md.before"},
    }
    if skill_path is not None and updated_skill is not None:
        files[str(skill_path)] = {"before_exists": original_skill is not None, "before": _digest(original_skill) if original_skill is not None else None, "after": _digest(updated_skill), "backup": "SKILL.md.before"}
    _verify_transaction_files(transaction, files, set(), verify_backups=False)
    transaction.mkdir(parents=True, exist_ok=False)
    snapshot = {
        "version": VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "include_skill": skill_path is not None,
        "files": files,
        "install_root": str(install_root),
        "config_dir": str(config_dir),
        "package_files": package_hashes,
        "owned_handlers": _owned_handler_snapshot(updated_hooks),
    }
    if original_hooks is not None:
        (transaction / "hooks.json.before").write_bytes(original_hooks)
    if original_agents is not None:
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
        if original_hooks is None:
            _write_new(hooks_path, updated_hooks_raw)
        else:
            _write_atomic(hooks_path, updated_hooks_raw)
        written.append(hooks_path)
        written_text = {str(path) for path in written}
        _verify_transaction_files(transaction, files, written_text)
        if original_agents is None:
            _write_new(agents_path, updated_agents)
        else:
            _write_atomic(agents_path, updated_agents)
        written.append(agents_path)
        written_text = {str(path) for path in written}
        _verify_transaction_files(transaction, files, written_text)
        if skill_path is not None and updated_skill is not None:
            if original_skill is None:
                _write_new(skill_path, updated_skill)
            else:
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
                    if details.get("before_exists", True):
                        backup_path = transaction / details["backup"]
                        backup = _read(backup_path)
                        if _digest(backup) != details["before"]:
                            residual.append(str(path))
                            continue
                        _write_atomic(path, backup)
                    else:
                        _reject_reparse_components(path, owned_root=config_dir)
                        if _matches_file_state(path, exists=True, digest=expected):
                            path.unlink()
                        else:
                            residual.append(str(path))
                else:
                    residual.append(str(path))
            except (OSError, ValueError):
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


def update(config_dir: Path | None = None, source: Path | None = None, *, plan_only: bool = False) -> dict[str, Any]:
    """Switch an owned install to an immutable, content-addressed package revision."""
    config = _resolve_config_dir(config_dir)
    _reject_reparse_components(config)
    candidate = _resolve_source(source)
    if not candidate.is_dir():
        raise ValueError("Candidate source directory is missing")
    candidate_files = _package_hashes(candidate)
    package_id = _package_id(candidate_files)
    hooks_path = config / "hooks.json"
    agents_path = config / "AGENTS.md"
    active_path = _active_record_path(config)
    _reject_reparse_components(hooks_path, owned_root=config)
    _reject_reparse_components(agents_path, owned_root=config)
    original_hooks = _read(hooks_path)
    original_agents = _read(agents_path)
    hooks_obj = json.loads(_decode(original_hooks))
    if not isinstance(hooks_obj, dict):
        raise ValueError("hooks.json must contain a JSON object")
    handlers, roots = _owned_handlers(hooks_obj)
    if len(roots) != 1 or any(len(handlers.get(event, [])) != 1 for event in ("SessionStart", "UserPromptSubmit", "PreToolUse")):
        raise ValueError("Update requires one active toolkit handler per event")
    current_root = next(iter(roots))
    if _config_from_package_root(current_root) != config:
        raise ValueError("Active package path does not match the selected configuration directory")
    record, had_record = _load_install_record(config, current_root)
    if "owned_handlers" in record:
        _verify_owned_handler_snapshot(hooks_obj, record["owned_handlers"])
    agents_text = _decode(original_agents)
    _, _, current_block = _extract_managed_block(agents_text)
    if current_block != _managed_block(current_root):
        raise ValueError("Managed AGENTS block changed after installation")
    package_files = record["package_files"]
    if not isinstance(package_files, dict):
        raise ValueError("Active package inventory is invalid")
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        _, handler = handlers[event][0]
        if handler.get("type") != "command":
            raise ValueError(f"Owned {event} handler has an unsupported type")
        command_root = _extract_owned_root(handler.get("command"))
        if command_root != current_root:
            raise ValueError(f"Owned {event} command changed after installation")
        if not _managed_handler_command(handler.get("command"), current_root):
            raise ValueError(f"Owned {event} command shape changed after installation")
        windows_value = handler.get("commandWindows")
        if windows_value is not None and _extract_owned_root(windows_value) != current_root:
            raise ValueError(f"Owned {event} Windows command changed after installation")
        if windows_value is not None and not _managed_handler_command(windows_value, current_root):
            raise ValueError(f"Owned {event} Windows command shape changed after installation")
        expected_command = record.get("hook_command")
        if isinstance(expected_command, str) and (handler.get("command") != expected_command or (windows_value is not None and windows_value != expected_command)):
            raise ValueError(f"Owned {event} handler fields changed after installation")
    skill_path = config / "skills" / "windows-command-preflight" / "SKILL.md"
    skill_owned = record["skill_owned"]
    original_skill: bytes | None = None
    if skill_owned:
        _reject_reparse_components(skill_path, owned_root=config)
        original_skill = _read(skill_path)
        if original_skill != _skill_pointer_bytes(current_root):
            raise ValueError("Toolkit-owned skill pointer changed after installation")
    active_before: bytes | None = None
    try:
        _reject_reparse_components(active_path, owned_root=config)
        active_before = _read(active_path)
    except FileNotFoundError:
        if had_record:
            raise ValueError("Active install record disappeared")
    if package_id == _package_id(package_files):
        return {"outcome": "already_current", "config_dir": str(config), "package_root": str(current_root), "package_sha256": package_id, "writes": 0}
    new_root = _absolute_lexical(_manager_root(config) / "revisions" / package_id)
    if new_root == current_root:
        return {"outcome": "already_current", "config_dir": str(config), "package_root": str(current_root), "package_sha256": package_id, "writes": 0}
    _reject_reparse_components(new_root, owned_root=config)
    command = subprocess.list2cmdline([sys.executable, "-B", str(new_root / "bootstrap.py")])
    hooks_updated = json.loads(json.dumps(hooks_obj))
    updated_handlers, updated_roots = _owned_handlers(hooks_updated)
    if updated_roots != {current_root}:
        raise ValueError("Owned hook inventory changed during update preflight")
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
        _, handler = updated_handlers[event][0]
        handler["command"] = command
        if "commandWindows" in handler:
            handler["commandWindows"] = command
    hooks_after = _json_bytes(hooks_updated)
    agents_bom = b"\xef\xbb\xbf" if original_agents.startswith(b"\xef\xbb\xbf") else b""
    agents_after = agents_bom + _replace_block(agents_text, current_root, new_root).encode("utf-8")
    skill_after = _skill_pointer_bytes(new_root) if skill_owned else None
    active_after = _json_bytes({
        "format": "codex-windows-prevention-active-v1",
        "package_root": str(new_root),
        "package_sha256": package_id,
        "package_files": candidate_files,
        "hook_command": command,
        "owned_handlers": _owned_handler_snapshot(hooks_updated),
        "skill_owned": skill_owned,
    })
    transaction_root = _manager_root(config) / "transactions"
    transaction_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    transaction = transaction_root / transaction_id
    file_snapshots: dict[str, dict[str, Any]] = {}

    def add_snapshot(path: Path, before: bytes | None, after: bytes, backup_name: str) -> None:
        file_snapshots[str(path)] = {
            "before_exists": before is not None,
            "before": _digest(before) if before is not None else None,
            "after": _digest(after),
            "backup": backup_name,
        }

    add_snapshot(hooks_path, original_hooks, hooks_after, "hooks.json.before")
    add_snapshot(agents_path, original_agents, agents_after, "AGENTS.md.before")
    if skill_owned and skill_after is not None:
        add_snapshot(skill_path, original_skill, skill_after, "SKILL.md.before")
    add_snapshot(active_path, active_before, active_after, "active.json.before")
    plan = {
        "outcome": "planned",
        "config_dir": str(config),
        "current_package_root": str(current_root),
        "package_root": str(new_root),
        "package_sha256": package_id,
        "changes": list(file_snapshots),
        "preserved": "unrelated settings, hook entries, prompt prose, and user-owned skills remain unchanged",
        "candidate_commands_executed": False,
    }
    if plan_only:
        return plan
    _verify_transaction_files(transaction, file_snapshots, set(), verify_backups=False)
    transaction.mkdir(parents=True, exist_ok=False)
    for path_text, details in file_snapshots.items():
        before = _read(Path(path_text)) if details["before_exists"] else None
        if before is not None:
            (transaction / details["backup"]).write_bytes(before)
    metadata = {
        "version": VERSION,
        "kind": "revision_update",
        "record_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config_dir": str(config),
        "previous_root": str(current_root),
        "previous_package_files": package_files,
        "install_root": str(new_root),
        "package_files": candidate_files,
        "package_created": False,
        "files": file_snapshots,
    }
    _write_atomic(transaction / "plan.json", _json_bytes(plan))
    _write_atomic(transaction / "transaction.json", _json_bytes(metadata))
    package_created = False
    try:
        _verify_transaction_files(transaction, file_snapshots, set())
        if new_root.exists():
            _verify_owned_tree(new_root, candidate_files, owned_root=config)
        else:
            new_root.mkdir(parents=True, exist_ok=False)
            package_created = True
            metadata["package_created"] = True
            _write_atomic(transaction / "transaction.json", _json_bytes(metadata))
            for filename, digest in candidate_files.items():
                target = new_root / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(candidate / filename, target)
                if _digest(_read(target)) != digest:
                    raise OSError(f"Package read-back mismatch for {filename}")
            _verify_owned_tree(new_root, candidate_files, owned_root=config)
        writes: list[tuple[Path, bytes, bytes | None]] = [(hooks_path, hooks_after, original_hooks), (agents_path, agents_after, original_agents)]
        if skill_owned and skill_after is not None and original_skill is not None:
            writes.append((skill_path, skill_after, original_skill))
        writes.append((active_path, active_after, active_before))
        written_paths: set[str] = set()
        for path, after, before in writes:
            _verify_transaction_files(transaction, file_snapshots, written_paths)
            _verify_owned_tree(current_root, package_files, owned_root=config)
            _verify_owned_tree(new_root, candidate_files, owned_root=config)
            _reject_reparse_components(path, owned_root=config)
            current = _read(path) if path.exists() else None
            if current != before:
                raise RuntimeError(f"Configuration changed during update: {path.name}")
            if before is None:
                _write_new(path, after)
            else:
                _write_atomic(path, after)
            if _read(path) != after:
                raise OSError(f"Update read-back mismatch: {path.name}")
            written_paths.add(str(path))
            _verify_transaction_files(transaction, file_snapshots, written_paths)
        _verify_owned_tree(current_root, package_files, owned_root=config)
        _verify_owned_tree(new_root, candidate_files, owned_root=config)
        _verify_transaction_files(transaction, file_snapshots, written_paths)
    except BaseException as error:
        residual: list[str] = []
        for path_text, details in file_snapshots.items():
            path = Path(path_text)
            try:
                _reject_reparse_components(path, owned_root=config)
                if not _matches_file_state(path, exists=True, digest=details["after"]):
                    continue
                if details["before_exists"]:
                    backup_path = transaction / details["backup"]
                    _reject_reparse_components(backup_path, owned_root=transaction)
                    backup = _read(backup_path)
                    if _digest(backup) != details["before"]:
                        residual.append(str(path))
                    else:
                        _write_atomic(path, backup)
                else:
                    path.unlink()
            except (OSError, ValueError):
                residual.append(str(path))
        try:
            _reject_reparse_components(new_root, owned_root=config)
            if package_created and new_root.exists():
                _verify_owned_tree(new_root, candidate_files, allow_incomplete=True, owned_root=config)
                shutil.rmtree(new_root)
        except (OSError, ValueError):
            residual.append(str(new_root))
        raise RuntimeError(f"Update failed: {type(error).__name__}; residual paths: {residual}; transaction: {transaction}") from error
    return {**plan, "outcome": "updated", "transaction": str(transaction), "trust_review": "required through normal Codex hook trust flow"}


def _rollback_revision_update(transaction_dir: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    if metadata.get("record_version") != 1 or not isinstance(metadata.get("files"), dict):
        raise ValueError("Revision update transaction is unsupported")
    config = Path(metadata.get("config_dir", ""))
    if not config.is_absolute():
        raise ValueError("Transaction config directory must be absolute")
    config = _absolute_lexical(config)
    _reject_reparse_components(config)
    expected_parent = _absolute_lexical(_manager_root(config) / "transactions")
    if transaction_dir.parent != expected_parent:
        raise ValueError("Transaction directory is outside its supported config destination")
    install_root = _absolute_lexical(Path(metadata.get("install_root", "")))
    previous_root = _absolute_lexical(Path(metadata.get("previous_root", "")))
    expected_base = _manager_root(config)
    if _config_from_package_root(install_root) != config or install_root.parent.name.casefold() != "revisions":
        raise ValueError("Updated package path is outside its supported revision directory")
    if _config_from_package_root(previous_root) != config:
        raise ValueError("Previous package path is outside its supported config destination")
    package_files = metadata.get("package_files")
    previous_files = metadata.get("previous_package_files")
    if not isinstance(package_files, dict) or _package_id(package_files) != install_root.name:
        raise ValueError("Updated package inventory is invalid")
    if not isinstance(previous_files, dict):
        raise ValueError("Previous package inventory is invalid")
    package_created = metadata.get("package_created")
    if not isinstance(package_created, bool):
        raise ValueError("Updated package creation flag is invalid")
    _verify_owned_tree(install_root, package_files, owned_root=config)
    _verify_owned_tree(previous_root, previous_files, owned_root=config)
    hooks_path = _absolute_lexical(config / "hooks.json")
    agents_path = _absolute_lexical(config / "AGENTS.md")
    skill_path = _absolute_lexical(config / "skills" / "windows-command-preflight" / "SKILL.md")
    active_path = _absolute_lexical(_active_record_path(config))
    allowed = {str(hooks_path), str(agents_path), str(active_path)}
    if str(skill_path) in metadata["files"]:
        allowed.add(str(skill_path))
    if set(metadata["files"]) != allowed:
        raise ValueError("Transaction contains unsupported update files")
    restore: list[tuple[Path, bytes | None, bool, Path, dict[str, Any]]] = []
    for path_text, details in metadata["files"].items():
        path = _absolute_lexical(Path(path_text))
        if path_text not in allowed or not isinstance(details, dict):
            raise ValueError("Transaction file record is invalid")
        _reject_reparse_components(path, owned_root=config)
        if not _matches_file_state(path, exists=True, digest=details.get("after")):
            raise ValueError(f"Rollback precondition failed for {path}; installed bytes changed")
        existed = details.get("before_exists")
        if not isinstance(existed, bool):
            raise ValueError(f"Transaction existence flag is invalid for {path}")
        backup = None
        if existed:
            backup_path = transaction_dir / details.get("backup", "")
            _reject_reparse_components(backup_path, owned_root=transaction_dir)
            backup = _read(backup_path)
            if _digest(backup) != details.get("before"):
                raise ValueError(f"Transaction backup check failed for {path}")
        elif details.get("before") is not None:
            raise ValueError(f"Transaction prior state is invalid for {path}")
        restore.append((path, backup, existed, backup_path if existed else transaction_dir / details.get("backup", ""), details))
    restored: set[Path] = set()
    try:
        for path, backup, existed, backup_path, details in restore:
            for candidate, _, candidate_existed, candidate_backup, candidate_details in restore:
                if candidate in restored:
                    if candidate_existed:
                        matches = _matches_file_state(candidate, exists=True, digest=candidate_details.get("before"))
                    else:
                        matches = _matches_file_state(candidate, exists=False)
                else:
                    matches = _matches_file_state(candidate, exists=True, digest=candidate_details.get("after"))
                if not matches:
                    raise ValueError(f"Rollback target changed after preflight: {candidate}")
                if candidate_existed:
                    _reject_reparse_components(candidate_backup, owned_root=transaction_dir)
                    if _digest(_read(candidate_backup)) != candidate_details.get("before"):
                        raise ValueError(f"Transaction backup changed after preflight: {candidate.name}")
            _verify_owned_tree(install_root, package_files, owned_root=config)
            _verify_owned_tree(previous_root, previous_files, owned_root=config)
            _reject_reparse_components(path, owned_root=config)
            if existed:
                if backup is None:
                    raise ValueError(f"Transaction backup is missing for {path}")
                _write_atomic(path, backup)
            else:
                if not _matches_file_state(path, exists=True, digest=details.get("after")):
                    raise ValueError(f"Rollback target changed after preflight: {path}")
                path.unlink()
            restored.add(path)
    except BaseException as error:
        raise RuntimeError(f"Rollback incomplete after {type(error).__name__}; restored paths: {[str(path) for path in restored]}") from error
    for path, backup, existed, _, _ in restore:
        if existed:
            if backup is None or _read(path) != backup:
                raise OSError(f"Rollback read-back mismatch for {path}")
        elif path.exists():
            raise OSError(f"Rollback read-back mismatch for {path}")
    removed_revision: str | None = None
    if package_created:
        _reject_reparse_components(install_root, owned_root=config)
        _verify_owned_tree(install_root, package_files, owned_root=config)
        shutil.rmtree(install_root)
        removed_revision = str(install_root)
    return {"outcome": "rolled_back", "restored": [str(path) for path, _, _, _, _ in restore], "removed_revision": removed_revision}


def rollback(transaction_dir: Path) -> dict[str, Any]:
    transaction_dir = _absolute_lexical(transaction_dir)
    _reject_reparse_components(transaction_dir)
    metadata = json.loads((transaction_dir / "transaction.json").read_text(encoding="utf-8"))
    if metadata.get("version") != VERSION or not isinstance(metadata.get("files"), dict):
        raise ValueError("Transaction metadata is unsupported")
    if metadata.get("kind") == "revision_update":
        return _rollback_revision_update(transaction_dir, metadata)
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
    preflight: list[tuple[Path, bytes, bytes | None, str | None, Path, bool]] = []
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
        existed_before = data.get("before_exists", True)
        if not isinstance(existed_before, bool):
            raise ValueError(f"Transaction existence flag is invalid for {path}")
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
        if existed_before:
            _reject_reparse_components(backup_path, owned_root=transaction_dir)
            backup = _read(backup_path)
            if _digest(backup) != data.get("before"):
                raise ValueError(f"Transaction backup check failed for {path}")
            before_hash = data.get("before")
            if not isinstance(before_hash, str):
                raise ValueError(f"Transaction prior hash is invalid for {path}")
        else:
            if data.get("before") is not None:
                raise ValueError(f"Transaction prior state is invalid for {path}")
            backup = None
            before_hash = None
        preflight.append((path, current, backup, before_hash, backup_path, existed_before))
    restored: list[Path] = []
    try:
        restored_set: set[Path] = set()
        for path, expected_current, backup, before_hash, backup_path, existed_before in preflight:
            for candidate, candidate_current, candidate_backup, candidate_before, candidate_backup_path, candidate_existed in preflight:
                if candidate in restored_set and not candidate_existed:
                    matches = _matches_file_state(candidate, exists=False)
                else:
                    expected_live = candidate_backup if candidate in restored_set else candidate_current
                    matches = expected_live is not None and _matches_file_state(candidate, exists=True, digest=_digest(expected_live))
                if not matches:
                    raise ValueError(f"Rollback target changed after preflight: {candidate}")
                if candidate_existed and (candidate_backup is None or _digest(_read(candidate_backup_path)) != candidate_before):
                    raise ValueError(f"Rollback backup changed after preflight: {candidate.name}")
            _verify_owned_tree(install_root, expected_package, owned_root=config_dir)
            _reject_reparse_components(path, owned_root=config_dir)
            if existed_before:
                if backup is None:
                    raise ValueError(f"Transaction backup is missing for {path}")
                _write_atomic(path, backup)
            else:
                if not _matches_file_state(path, exists=True, digest=_digest(expected_current)):
                    raise ValueError(f"Rollback target changed after preflight: {path}")
                path.unlink()
            restored.append(path)
            restored_set.add(path)
        for path, _, backup, _, _, existed_before in preflight:
            if existed_before:
                if backup is None or _digest(_read(path)) != _digest(backup):
                    raise OSError(f"Read-back mismatch for {path}")
            elif not _matches_file_state(path, exists=False):
                raise OSError(f"Read-back mismatch for {path}")
    except BaseException as error:
        raise RuntimeError(f"Rollback incomplete after {type(error).__name__}; restored paths: {[str(p) for p in restored]}") from error
    _reject_reparse_components(install_root, owned_root=config_dir)
    if install_root.exists():
        _verify_owned_tree(install_root, expected_package, owned_root=config_dir)
        shutil.rmtree(install_root)
    return {"outcome": "rolled_back", "restored": [str(path) for path in restored]}


def _emit(value: Any) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")


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
    status_parser = sub.add_parser("status")
    status_parser.add_argument("--config-dir", type=Path)
    update_parser = sub.add_parser("update")
    update_parser.add_argument("--config-dir", type=Path)
    update_parser.add_argument("--source", type=Path)
    update_parser.add_argument("--plan-only", action="store_true")
    install_parser = sub.add_parser("install")
    install_parser.add_argument("--config-dir", type=Path)
    install_parser.add_argument("--source", type=Path)
    install_parser.add_argument("--expected-hooks-sha256")
    install_parser.add_argument("--expected-agents-sha256")
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
        elif args.action == "status":
            output = status(args.config_dir)
        elif args.action == "update":
            output = update(args.config_dir, args.source, plan_only=args.plan_only)
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
