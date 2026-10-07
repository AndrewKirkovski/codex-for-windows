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

Requires Windows and Python 3.10 or newer. No third-party Python packages are
needed. Run these commands from the toolkit directory:

```powershell
python windows_prevention.py doctor
python windows_prevention.py recommend --list-recipes
python windows_prevention.py install --config-dir "$HOME\.codex" --plan-only
python windows_prevention.py install --config-dir "$HOME\.codex"
```

`recommend` offers recipes and checks command text against known rules.
`validate` checks a reviewed script with the selected
PowerShell parser. Neither command runs the proposed command or script.

## Install and rollback

No earlier hook installation is required. The installer creates missing hook,
prompt, and skill files. It also supports existing settings and upgrades v23
hooks in place. If you use `CODEX_HOME`, pass that directory instead of
`$HOME\.codex`.

The installer checks for concurrent changes, saves byte-exact backups, and
preserves unrelated hooks, prompt text, settings, and trust state. An existing
preflight skill stays unchanged unless you supply its current hash. Review new
or changed hooks through Codex's normal trust flow. Installation does not grant
trust or enable disabled hooks.

The install result includes a transaction path. Use it to undo the install:

```powershell
python windows_prevention.py rollback --transaction "<transaction path>"
```

Rollback restores prior bytes and removes files that the installer created.
It refuses to overwrite later changes. Optional hash checks are available
through `install --help`.

Static hooks cannot prove test coverage, command results, executable
availability, output content, or runtime behavior. See [recipes.md](recipes.md)
for command and parser details, [evidence.md](evidence.md) for test and research
records, [NOTICE.md](NOTICE.md) for provenance, and [LICENSE](LICENSE) for the
license terms.

[Process Manager for Windows](https://github.com/AndrewKirkovski/claude-code-bg-process-manager-windows)
is an optional shared service for command execution, routing, output
normalization, and process control.
