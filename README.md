# Codex Windows prevention toolkit

This Python standard library package helps prevent invalid Windows command
construction. It provides environment checks, command recommendations,
static validation, guarded installation, and rollback.

Run `python windows_prevention.py doctor` to check Python, PowerShell, parser,
and executable metadata availability. Run `python windows_prevention.py
recommend --payload <json-file>` to classify a known hook payload. Command text
is redacted unless `--show-command` is set. Run
`python windows_prevention.py validate --fixtures fixtures/behavior.json` to
check synthetic behavior fixtures. These commands do not execute candidate
commands or scripts.

Use `python windows_prevention.py recommend --list-recipes` to list command
recipes. Pass `--recipe <id>` to display one recipe. For PowerShell literals,
double embedded single quotes. Native program examples use separate argument
values. Replace placeholders with verified inputs before running a recipe.

The PowerShell helper uses the native parser and reports diagnostic IDs and
source locations. It omits parser messages because they can contain private
source text. Metadata checks use PowerShell command discovery without invoking
the discovered command.

Installation requires an explicit Codex configuration directory and the exact
current SHA-256 values for `hooks.json` and `AGENTS.md`. The installer checks
all inputs before writing, saves byte-exact backups, copies the package,
replaces the three owned v23 hook definitions in place, and reads the results
back. It preserves unrelated hook entries and event state. It does not alter
trust hashes. Review the installed hooks through Codex's normal trust flow;
enabling hooks remains a user action. Rollback restores the saved files only
when the installed files and package still match their recorded hashes.

To update an existing discovered preflight skill, pass its exact current hash
as `--expected-skill-sha256`. The installer replaces it with a short pointer to
the installed detailed skill. That file is backed up and included in rollback.
Without this option, the existing skill stays unchanged. The automated installer
upgrades one existing v23 guard per event. Fresh configurations need reviewed
hook entries under the normal Codex configuration and trust flow.

The hook can classify command text and recognized payload shapes. It cannot
prove schemas, test coverage, executable availability, output existence, or
runtime behavior from a command string alone. `validate` reports missing
prerequisites separately from invalid syntax and unsupported shapes. The
behavior fixtures are synthetic contract examples, not findings from the
historical audit.

The package includes adapted files from a local v23 command guard baseline.
See `NOTICE.md` for provenance limits and `LICENSE` for the MIT terms that
apply to this toolkit. The v23 source hashes are retained for attribution.

Use [Process Manager for Windows](https://github.com/AndrewKirkovski/claude-code-bg-process-manager-windows)
for hidden native commands, script routing, output capture, and process control.
Use its separate `working_dir` and `env` fields. Use `prepare_command` when the
server advertises it and a route is uncertain. Simple tested commands can run
directly. See [recipes.md](recipes.md) for alternatives when it is absent and
[evidence.md](evidence.md) for tests, report references, and external research.
