# Windows command prevention for Codex

## Why it exists

Codex can choose the wrong Windows shell or runtime, or mishandle paths and
quotes. Repeating failed commands wastes time and tokens. This toolkit helps
Codex construct and check commands before it runs them.

## Prevention comes first

A short global Codex prompt points to the Windows preflight skill. The skill and
tested recipes guide command construction, runtime selection, paths, quoting,
editing, and process lifecycle.

| Part | Purpose |
| --- | --- |
| Prompt, skill, and recipes | Prevent command errors before execution. |
| `windows_prevention.py` CLI | Check the environment, recommend commands, and validate scripts. |
| Hooks | Serve as the last boundary and pass valid calls silently. |

These rules apply to Codex. They do not set policy for other Process Manager
clients.

## Quick start

Requires Windows and Python, with no third-party Python packages. Run these
commands from the toolkit directory:

```powershell
python windows_prevention.py doctor
python windows_prevention.py recommend --list-recipes
python windows_prevention.py install --help
```

`recommend` offers recipes and checks command text against known rules.
`validate` checks a reviewed script with the selected
PowerShell parser. Neither command runs the proposed command or script.

## Install and rollback

The installer upgrades an existing v23 hook set only. It requires an explicit
Codex configuration directory and the current hashes for `hooks.json` and
`AGENTS.md`. It checks inputs, saves byte-exact backups, preserves unrelated
hook entries and trust state, and reads changed files back. Fresh setups need
reviewed hook entries. Review installed hooks through Codex's normal trust
flow. Rollback restores only owned files that still match their recorded
hashes.

Static hooks cannot prove test coverage, command results, executable
availability, output content, or runtime behavior. See [recipes.md](recipes.md)
for command and parser details, [evidence.md](evidence.md) for test and research
records, [NOTICE.md](NOTICE.md) for provenance, and [LICENSE](LICENSE) for the
license terms.

[Process Manager for Windows](https://github.com/AndrewKirkovski/claude-code-bg-process-manager-windows)
is a separate shared service for command execution, routing, output
normalization, and process control. Its client guidance does not define Codex
policy.
