# Windows command recipes

Choose the execution surface first. Replace each placeholder with a verified
value. These recipes do not execute the command you want to review. Use
`prepare_command` for uncertain managed runner routes, when that tool is
available. Simple verified native commands need no preview call.

## Read source text

Use profile-free host PowerShell for local cmdlets.

```powershell
Get-Content -LiteralPath '<existing-file>' -Encoding UTF8 -ErrorAction Stop
```

Use a single-quoted literal for a caller value and double each embedded single
quote. A JSON string is not shell quoting. For byte-level validation, use
`[Text.UTF8Encoding]::new($false, $true)` in a reviewed script. A successful
`Get-Content` call does not prove that malformed bytes were rejected.

## Search files

Put ripgrep options before the end-of-options marker.

```text
rg -n -F -- <literal-pattern> <existing-directory>
rg -n --glob <filename-glob> -- <pattern> <existing-directory>
```

Keep native argv values in separate fields when a tool accepts argv. For the
managed runner's command string, quote the verified absolute executable path
and each argument using its supported Windows parser. Do not add a PowerShell
call operator to the managed runner command.

Check optional literal roots before using them as operands. Positive globs
override ignore rules, so a glob inventory can differ from an inventory over
existing literal roots. Exit 0 means matches. Exit 1 means a valid zero result.
An exit greater than 1 means a failed search, and its output is partial evidence.

## Edit source and JSON

Read the exact current file before an edit. Use `apply_patch` or a structured
editor with an expected occurrence count or SHA-256 guard. Select UTF-8 without
BOM unless the file's protocol requires another encoding. Preserve Unicode and
the existing newline contract. Keep large replacement bodies in reviewed files.
After the write, read back the bytes, review the diff, and use the owning parser.
If a write fails, require a verified output before any dependent check or run.

Use a JSON serializer, such as `json.dumps(value, ensure_ascii=False)`, instead
of manual escaping. Read JSON with strict UTF-8 decoding, parse it, and check
the expected object shape and required keys. A syntactically valid JSON file
does not prove that it matches the application schema.

## Run native programs and scripts

```text
"<absolute-native-executable>" <arguments>
"<absolute-reviewed-script.cmd>" <arguments>
"<absolute-reviewed-script.ps1>" <arguments>
```

The managed runner resolves native programs directly and chooses the fixed
Windows interpreter for supported scripts. Shell operators can select Bash.
Keep PowerShell cmdlets out of that fallback. Keep complex programs in reviewed
files. Verify the selected runtime against the project contract and existing
native modules before running the owning suite.

## Check script syntax without execution

```text
python -B windows_prevention.py validate --powershell-file <reviewed-script.ps1> --powershell-executable "<absolute-powershell-executable>"
```

Select the interpreter that will execute the script. Process Manager's direct
`.ps1` route uses Windows PowerShell 5.1. To execute with PowerShell 7, call its
verified executable explicitly and pass the reviewed file through `-File`.
Validation defaults to Windows PowerShell 5.1 on Windows. Check the reported
interpreter path and version before using the result.

The helper uses the selected native PowerShell parser. A parser-level valid
result proves syntax for that parser version. It does not prove paths, permissions, outputs,
runtime behavior, or test coverage. For Python files, use `compile` with bytes
read from the file in a reviewed checker. Do not create bytecode merely to check
syntax.

## Keep structured data separate from diagnostics

A producer should write JSON to stdout and diagnostics to stderr. A consumer
must verify the producer's exit code before parsing stdout. The managed runner
combines both streams in its log, so use a reviewed producer or structured
connector when stream identity is required. Do not parse a combined log as JSON.

```python
result = subprocess.run(argv, capture_output=True, text=True,
                        encoding='utf-8', check=False,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
if result.returncode != 0:
    raise RuntimeError('Producer failed')
data = json.loads(result.stdout)
```

## Verify result counts and prerequisites

First, collect lookup results. Second, check that the count matches the required
count. If the task requires one result, both zero and multiple results need a
reported outcome. Do not silently choose the first executable, device, file, or
process.

First, verify each prerequisite. Second, perform the dependent action. Third,
verify each required output exists and contains the intended data. A failed
prerequisite must stop dependent work. An exit 0 without the required outputs
does not establish completion.

The behavior fixture validator accepts explicit observations for lookup
cardinality, prerequisite results, required outputs, and result kinds. Those
observations must come from actual checks. A command hook cannot infer them.

## Select and verify tests

Read the project's declared test entrypoint and filter syntax. Confirm the
selected files or test names before running a narrow filter. Verify the report
contains the expected owning suites and a positive test count. A zero-test
report or a filter matching unrelated suites is incomplete evidence, even when
the command exits 0. Build required supervisors or generated fixtures first
when the declared pretest contract requires them.

## Control processes

Use the managed runner for non-interactive commands. Use a stable managed name
for a persistent process. Before starting a known listener, inspect the port.
Use a narrow alive process query when resolving a lifecycle conflict. Before
stopping a process, verify its identity and task ownership. A listener or a PID
does not prove application health. Verify the application's intended workload
or readiness behavior after startup.

Authored non-interactive child processes must stay hidden. Node uses
`windowsHide: true`. Python uses `CREATE_NO_WINDOW` on Windows. Visible browsers,
terminals, and other requested interactive tools keep their visible behavior.

## Work without Process Manager

Use a connector or the profile-free host PowerShell surface for reads and
edits. For native commands with difficult arguments, use a small reviewed
Python script. Python 3.10 or newer accepts separate argv, cwd, and env values.
Check its syntax with `compile` before running it. This avoids shell parsing.

```python
result = subprocess.run([verified_executable, *verified_arguments],
                        cwd=verified_checkout, env=verified_environment,
                        capture_output=True, text=True, encoding='utf-8',
                        check=False,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
```

For a PowerShell script, pass the verified interpreter, `-NoLogo`, `-NoProfile`,
`-NonInteractive`, `-File`, and the script path as separate argv values. Check
syntax with that interpreter first. Preserve stdout, stderr, and exit status.
PowerShell 5.1 and 7 differ in native argument handling. Do not assume an empty
argument or an embedded quote survives a native call through PowerShell 5.1.
For persistent processes, use a supported process supervisor or tool session.
Verify its stop and restart behavior before relying on it.
