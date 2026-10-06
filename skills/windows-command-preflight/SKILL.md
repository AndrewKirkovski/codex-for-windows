---
name: windows-command-preflight
description: Prevent invalid Windows command construction before execution. Use before the first shell, managed-process, inventory, build, test, runtime, or repository-check command on Windows, and whenever changing execution surfaces, runtimes, path forms, or parallel orchestration after a failure.
---

# Windows Command Preflight

Construct the complete valid command before the first tool call. A downstream
hook is a last-resort safety boundary, not command planning.

## First-Call Decision

1. Select the execution surface before formatting the command.
2. Confirm every explicit path operand exists unless absence is the fact being
   tested.
3. Resolve the runtime required by the project and by native dependencies.
4. Decide how zero results and independent failures will be represented.
5. Define the observable postcondition before execution.

After changing a shell, path representation, runtime, or tool, revalidate the
whole replacement command. Do not repair only the token named by the latest
error.

## Execution Surface

Use the ordinary host PowerShell surface for local cmdlets such as
`Get-Content`; do not submit a bare PowerShell cmdlet to the managed runner.
For source reads use:

`Get-Content -LiteralPath <file> -Encoding UTF8 -ErrorAction Stop`

The managed runner supports resolved native executables and direct `.bat`,
`.cmd`, and `.ps1` targets. Preserve a verified absolute Windows executable
path and quote it when required. Do not replace it with a PATH lookup merely to
avoid quoting, and do not add `cmd` or PowerShell wrappers around supported
targets.

Unresolved commands or commands requiring shell syntax may reach Bash
fallback. Keep PowerShell cmdlets and shell-sensitive payloads out of that
route. Put nontrivial scripts and write logic in reviewed files. Review authored
inline code before use. Internal encoded transport in a verified runner is
allowed; it is not a reason to reject an otherwise valid call.

## Process Manager use in Codex

When Codex uses Process Manager, use `sync_run` for one-shot commands and
`bg_run` for long-lived processes. Do not use `bg_list` as routine preflight
for short commands or source edits. Check a known listener port with `bg_port_check`, which gives
an advisory snapshot. Otherwise inspect live processes only to resolve a
lifecycle or duplicate-process question. Use persisted logs to view unchanged
command output again. These rules guide Codex and do not set policy for other
Process Manager clients.

## Source Editing

Use `apply_patch` by default for small manual edits. Use a reviewed CLI editor
saved in a file and run it through the managed runner for structured or
multi-file edits, formatters, code generation, or when a demonstrated patch
tool failure prevents a safe edit. Do not create a one-off helper script for a
small edit that `apply_patch` can handle.

Read the exact current file first. Use exact literal paths and the runtime that
owns the project. Guard each manual replacement with an expected occurrence
count or SHA-256 hash. Review saved CLI editors and their inputs before running
them. Use UTF-8 without BOM by default, preserve the existing newline contract,
and read back the exact output. CLI and Process Manager calls remain subject to
the Codex sandbox and write approval; they do not provide a way around those
controls.

## Repository Inventories

Do not pass assumed `src`, `test`, or `tests` directories as mandatory `rg`
operands. If repository ignore semantics must remain exact, first enumerate
which optional literal roots exist and pass only those roots. If the inventory
intentionally defines its own include set, search one guaranteed existing root
with a quoted `rg -g` or `rg --glob`; positive globs override ignore rules, so
these forms are not semantically interchangeable. Literal bracketed lifecycle
filenames such as `[in-progress]report.md` are paths, not positional globs.

Place every ripgrep option before the `--` end-of-options marker. Use `--` only
to protect a pattern or literal operand that could be mistaken for an option;
never append `-g`, `--glob`, `--type`, or another option after it.

Handle ripgrep status explicitly: 0 means matches, 1 means a valid zero result,
and values above 1 are errors. When independent inventories run in parallel,
retain each outcome separately so one failure does not discard unrelated
evidence. Never treat output from a failed inventory as complete evidence.

## Runtime and Native Addons

Before the first Node, Python, package, or repository checker, select a
project-compatible runtime from project metadata, a project-local runtime, the
workspace dependency provider, or a verified absolute path. Do not assume that
managed-runner PATH resolution also applies to an ordinary shell.

Command routing does not prove project compatibility. Before an owning Node
suite loads an existing native addon, run a minimal non-mutating load probe
with the selected runtime. The load probe is the gate. When diagnosing a
mismatch, record `process.execPath`, `process.version`,
`process.versions.modules`, and `process.versions.napi`. Node-API addons can
remain ABI-stable across Node major versions, so do not reject a runtime from
its Node major or module ABI number alone. Do not run `npm rebuild` or reinstall
dependencies merely to fit another runtime without explicit authorization;
those are mutations and can execute lifecycle scripts. If no compatible
runtime is available, stop before the predictable suite failure.

## Build Ownership

For Wippy runtime projects, the Makefile is the single source of truth. Determine runtime ownership from the effective checkout's runtime configuration, application source, and declared workflow; a repository name, Wippy dependency, web-host role, parent checkout, or existing Windows wrapper does not establish ownership. On Windows, create a missing `.bat` or `.ps1` equivalent from the Makefile contract, using Wippy KB or official Wippy documentation where needed. Preserve target dependencies, arguments, environment, working directory, outputs, and failure propagation. An installed Make executable does not remove this Windows-adapter requirement. Package-source repositories, web hosts, and non-Wippy runtime repositories use their declared entrypoints. If a runtime project's Makefile is missing or contradictory, resolve the intended contract from repository evidence and the user's requirements before creating an independent workflow.

## Proof and Parallelism

Multiple read-only proofs may share one call only when each failure propagates
and each output remains attributable. Do not use a chain where a later command
can mask an earlier nonzero status. Do not mandate PowerShell 7 `&&` in Windows
PowerShell 5.1. In parallel orchestration, use settled results or per-call
catches only for independent evidence that must all remain visible; use
fail-fast aggregation for dependent work where any failure invalidates the
aggregate. Neither choice cancels already-started work.

Exit 0 or absence of stderr is not the final proof. Verify the intended file,
output, test coverage, count, route, or other task-specific postcondition.

## Toolkit and Recipes

Use [the Windows command recipes](../../recipes.md) for inspected patterns for
source reads, literal and glob searches, native commands, script syntax checks,
structured data, result counts, prerequisites, tests, and process control.

Use `windows_prevention.py doctor` to inspect local runtime metadata. Multiple
lookup results require an explicit choice of a verified executable. Keep local
machine paths in an ignored profile, not in portable instructions.

Use `recommend --list-recipes` or `recommend --recipe <id>` for a small recipe.
Use `recommend --payload <file>` to check known hook rules. A `clear_unverified`
result means no known rule found a violation. It does not prove the command,
runtime, prerequisites, or outputs. Use `prepare_command` only for uncertain
managed routes when that tool is available. Simple verified templates need no
extra preview call.

Use `validate --powershell-file <file> --powershell-executable <absolute-exe>`
for a syntax-only check with the selected PowerShell parser. Choose the runtime
that will execute the script. Process Manager's direct `.ps1` route uses Windows
PowerShell 5.1. Select PowerShell 7 only when the execution call uses that
interpreter explicitly. Without an override, validation uses Windows PowerShell
5.1 on Windows. Check the returned interpreter path and version.
The tool does not execute that file. Parser validity does
not prove that the candidate can read its inputs or produce the required
outputs. Keep diagnostics separate from JSON data and verify producer status
before consuming structured output.

Before a dependent write, verify each prerequisite. After the write, inspect
the exact output. When a lookup requires one result, verify the count is one
before using it. For tests, verify the selected owning suites and positive test
count, including required generated files or build steps from the project
workflow. A wrong filter or zero-test report is incomplete evidence even if
the process exits 0.

Behavior fixtures contain synthetic observations with passing replacements.
They test the validator contract. They are not evidence that a task ran those
checks. The hook cannot prove schema validity, test coverage, process health,
or output content from a command string.

Keep shared-write and approval decisions in the task conversation. Command
analysis does not grant approval or infer consent. Installation needs exact
current hashes, inspected changes, byte-exact backups, and read-back checks.
Hook trust and disabled-hook state remain under the normal Codex review flow.
