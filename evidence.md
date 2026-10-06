# Evidence and scope

The source reports describe different audits. They do not establish a combined
failure count. `audit_summary.json` preserves their scope. The primary audit
flagged 75 records across 182 turns and 1,289 command records. Flags include
expected search results and unresolved cases. They are not 75 confirmed errors.
The Attention report groups confirmed examples under W01 through W14. Its exact
total is unknown. `evidence-references.json` retains the original execution IDs,
classifications, and record line references. It omits command text and private
diagnostics. W IDs are local to each report and must not be merged by number.

The Attention report adds useful requirements for test selection, lookup counts,
failed prerequisite writes, missing outputs, CLI contracts, schema inspection,
and mixed output formats. These requirements belong in prompt rules and checked
recipes. The behavior fixtures test explicit observations; a hook cannot infer
those facts from command text alone.

## Verification

The review corrections passed 77 toolkit tests on Python 3.10. The runner
correction passed 91 tests across the same five owning files and built
successfully. Seven fresh MCP checks confirmed that preview remains read-only.
The eight added installer and parser tests ran without skips. They include
three real Windows junction checks, rollback after a working-directory change,
and separate parsing with real PowerShell 5.1 and 7 without candidate execution.

The guard now checks visible nested PowerShell and CMD bodies for root removal.
It also checks commands after a script invocation. PowerShell `-File` arguments
remain data. More than three levels of further shell nesting require separate
reviewed steps or a direct reviewed script. The guard does not read scripts or
prove their behavior. Known filesystem cmdlets receive the managed-runner
surface check; dashed native program and script names do not receive it.

Validation selects the fixed Windows PowerShell interpreter by default, which
matches the runner's direct `.ps1` route. An explicit absolute executable selects
PowerShell 7. Rollback checks the owned path and its ancestors for reparse points
before reading backups, walking the package, restoring globals, or removing it.
Install records absolute paths so a later working-directory change is safe.
Missing Git Bash produces the sanitized `interpreter_missing` preview problem.

The retained baseline is 14 live command checks, 55 owning runner tests, and
44 v23 guard tests. The implemented runner build passed 90 owning tests across
five files. Seven fresh MCP checks confirmed preview dispatch, existing command
inputs, selected routes, sanitized errors, secret omission, and no candidate
execution, files, or process records. The runner commit is
`d41ef5a3c8d7c0abed14dcf282a62dbb6d35e1ef` on
`codex/windows-command-prevention`. Public main reviewed before implementation
was `6d10ebef70d70fcc9d247b3c799ba9383704244d`; the local starting revision was
`58e2f580854eec01e6f135a64e0b10adf7584943`.

The final toolkit passed 67 tests in a clean copy. All 12 recipe IDs return nonempty
instructions. Nine paired behavior fixtures include a working replacement.
Real PowerShell 5.1 and 7 parsed valid and invalid scripts without executing
them. Transaction tests preserve unrelated hooks, restore a failed install,
preserve concurrent user edits, and reject rollback after package changes.
Windows CI repeats the suite on Python 3.10 and 3.13 with both PowerShell shells.
Remote CI results and active desktop hook coverage require separate evidence.

Local installation verified all 28 package files, exact transaction backups,
and preservation of unrelated hooks and original prompt text. `config.toml`
remained byte-exact before normal trust review. Four installed event probes
confirmed silent valid calls, rejection with a replacement, and the two context
responses. Actual rollback restored the prompt, hooks, and discovered skill
byte for byte and removed only the verified owned package. The configuration
also remained unchanged through that rollback.

The initial repository passed 62 tests before the optional skill update. Five
added tests cover the skill hash, exact rollback, and concurrent changes.
A fallback probe used
Python subprocess directly, without Process Manager normalization. It preserved
13 values with spaces, Unicode, an empty argument, embedded quotes, trailing
backslashes, and shell characters. Separate cwd and env values were verified.
Profile-free saved-script reads passed on both PowerShell 5.1 and 7. The fallback
set `CREATE_NO_WINDOW`. The recipes cover source reads and edits, JSON, scripts,
searches, checks, tests, counts, prerequisites, outputs, and process control.

## External research

A [Codex issue report](https://github.com/openai/codex/issues/9581) describes
PowerShell syntax sent through CMD, quote loss, and working directory drift.
Its author reports better results from short launch lines and saved scripts,
but also warns that oversized helper programs create more work. This supports
small reusable recipes with explicit runtimes and working directories. The
report concerns Codex 0.87.0 and does not prove a current Codex defect.

[Microsoft's parsing documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing?view=powershell-7.5)
confirms that PowerShell 7.3 changed native argument passing. Embedded quotes
and empty strings need version-specific checks. Batch files can still use the
legacy route. A new PowerShell version alone does not make every command safe.

A [later Windows hooks report](https://github.com/openai/codex/issues/38168)
describes an embedded quote regression and a short file-wrapper workaround on
Codex 0.147.0. Treat it as a reported fault, not a verified fault on this host.
The local hook launcher uses the selected Python executable and a saved file.
Verify actual hook behavior after trust review; a completion label alone is
insufficient evidence.

[Codex's hook documentation](https://learn.chatgpt.com/docs/hooks) requires
review of each changed non-managed hook definition before it can run. The
installer preserves trust state and leaves that review to the normal interface.
Hooks are a secondary boundary. They do not replace command preparation.
