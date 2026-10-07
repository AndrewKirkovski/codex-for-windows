# Windows command prevention for Codex

Codex can choose the wrong Windows shell or runtime, or mishandle paths and
quotes. The toolkit provides instructions for constructing Windows commands
and hooks that reject known errors before execution.

## What it does

| Part | Purpose |
| --- | --- |
| Short global prompt | Points Codex to the detailed Windows skill. |
| Skill and recipes | Guide paths, quoting, runtimes, edits, tests, and process control. |
| CLI | Checks commands, detects the installation, and manages updates and rollback. |
| Hooks | Reject known command errors and produce no output for valid calls. |

`recommend` and `validate` inspect commands or scripts without executing them.

## Install

Requires Windows and Python 3.10 or newer.

Download the complete toolkit folder and run from that folder:

```powershell
python windows_prevention.py doctor
python windows_prevention.py install --plan-only
python windows_prevention.py install
```

Commands use `CODEX_HOME`, the configuration detected from an installed copy,
or `$HOME\.codex`, in that order. `--config-dir` selects another directory.

Installation creates missing files and preserves unrelated hooks, prompt
text, settings, and existing user skills. Review new or changed hooks through
Codex's normal trust flow. Disabled hooks remain disabled.

## Check installation

Check the active installation without writing files:

```powershell
python windows_prevention.py status
```

## Update

Download and review a newer toolkit folder, then update from it:

```powershell
python windows_prevention.py update --source "<reviewed toolkit folder>" --plan-only
python windows_prevention.py update --source "<reviewed toolkit folder>"
```

Updates keep the previous package for rollback. An identical update writes
nothing. The update stops if installed toolkit files or its hook definitions
have changed.

## Rollback

Install and update return a transaction path. Use it to undo that operation:

```powershell
python windows_prevention.py rollback --transaction "<transaction path>"
```

Rollback restores saved files and removes files created by installation.
It stops if a file has changed since the install or update.

## Details and limits

Hooks cannot prove test coverage, command results, output content, or process
health. See [recipes](recipes.md), [verification evidence](evidence.md),
[attribution](NOTICE.md), and [MIT license](LICENSE).

[Process Manager for Windows](https://github.com/AndrewKirkovski/claude-code-bg-process-manager-windows)
is optional. It handles command routing, output, and process control.
