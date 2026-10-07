# Windows command prevention for Codex

## Why it exists

Codex can choose the wrong Windows shell or runtime, or mishandle paths and
quotes. Repeating failed commands wastes time and tokens. This toolkit helps
Codex construct and check commands before execution.

## What it does

| Part | Purpose |
| --- | --- |
| Short global prompt | Points Codex to the detailed Windows skill. |
| Skill and recipes | Guide paths, quoting, runtimes, edits, tests, and process control. |
| CLI | Checks commands, detects the installation, and manages updates and rollback. |
| Hooks | Provide a final boundary and pass valid calls silently. |

The rules apply to Codex. They do not set policy for other clients.
`recommend` and `validate` inspect commands or scripts without executing them.

## Install

Requires Windows and Python 3.10 or newer. No earlier hooks, Git installation,
or third-party Python packages are required. Keep the whole toolkit folder;
the CLI uses its bundled files. Run from that folder:

```powershell
python windows_prevention.py doctor
python windows_prevention.py install --plan-only
python windows_prevention.py install
```

Commands use `CODEX_HOME`, the configuration detected from an installed copy,
or `$HOME\.codex`, in that order. `--config-dir` selects another directory.

Installation creates missing files and preserves unrelated hooks, prompt
text, settings, and existing user skills. It also supports v23 migration.
Review new or changed hooks through Codex's normal trust flow. Installation
does not grant trust or enable disabled hooks.

## Check, update, and undo

Check the active installation without writing files:

```powershell
python windows_prevention.py status
```

Download and review a newer toolkit folder, then update from it:

```powershell
python windows_prevention.py update --source "<reviewed toolkit folder>" --plan-only
python windows_prevention.py update --source "<reviewed toolkit folder>"
```

Updates keep the previous package for rollback. An identical update writes
nothing. Changed owned files or conflicting hooks stop the update before
writes. The toolkit does not download or run new code automatically.

Install and update return a transaction path. Use it to undo that operation:

```powershell
python windows_prevention.py rollback --transaction "<transaction path>"
```

Rollback restores prior bytes and removes installer-created files only while
their recorded state still matches. It refuses to overwrite later changes.

## Details and limits

Hooks cannot prove test coverage, command results, output content, or process
health. See [recipes](recipes.md), [verification evidence](evidence.md),
[attribution](NOTICE.md), and [MIT license](LICENSE).

[Process Manager for Windows](https://github.com/AndrewKirkovski/claude-code-bg-process-manager-windows)
is optional. It handles command routing, output, and process control.
