#!/usr/bin/env python3
"""Fail-closed entry point for the v24 global Codex command guard."""

from __future__ import annotations

import json
import sys


def _payload(raw_input: str) -> dict[str, object]:
    try:
        value = json.loads(raw_input)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def failure_response(raw_input: str, error: BaseException) -> dict[str, object]:
    event_name = _payload(raw_input).get("hook_event_name")
    detail = type(error).__name__
    if event_name == "SessionStart":
        return {
            "continue": False,
            "stopReason": "Global command guard v24 could not load.",
            "systemMessage": (
                "GLOBAL-GUARD-INTERNAL-001: v24 failed to load "
                f"({detail}). Repair v24 before using tools."
            ),
        }
    if event_name == "UserPromptSubmit":
        return {
            "decision": "block",
            "reason": (
                "PROMPT-GUARD-INTERNAL-001: v24 failed to inspect the prompt "
                f"({detail}). Repair v24 before resubmitting."
            ),
        }
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "COMMAND-GUARD-INTERNAL-001: v24 failed to inspect the tool call "
                f"({detail}). Repair v24 before retrying."
            ),
        }
    }


def main() -> int:
    raw_input = sys.stdin.read()
    try:
        import guard
        return guard.run(raw_input)
    except BaseException as error:
        output = failure_response(raw_input, error)
        sys.stdout.write(json.dumps(output, separators=(",", ":")))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
