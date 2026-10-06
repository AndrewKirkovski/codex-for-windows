# Changes

## Guard 24 review fixes

- Reject package-path junctions before rollback follows or removes a target.
- Store absolute install paths so rollback works from another directory.
- Select the PowerShell validation runtime explicitly. Default to Windows
  PowerShell 5.1 for the direct managed script route on Windows.
- Inspect visible PowerShell and cmd command bodies with the existing rules.
- Accept native and script targets with dashed names in the managed runner.
- Report a missing Git Bash prerequisite clearly in Process Manager preview.
- Use `apply_patch` for small manual edits and reviewed saved CLI editors for
  structured or generated edits, with sandbox and read-back checks preserved.

## Guard 24

- Add prevention recipes, environment checks, command recommendations, and
  syntax-only validation. Keep simple verified commands available.
- Accept the observed Codex shell and managed-runner hook payloads.
- Add guarded installation, exact backups, optional discovered skill update,
  readback checks, and rollback that preserves user changes.
- Retain sanitized report references and the v23 guard's source attribution.
- Add Windows CI and tests for command rules, prerequisites, output contracts,
  test selection, lookup counts, and install transactions.

The separate Process Manager change adds read-only command preview and removes
wrapper initialization progress XML. Its existing execution inputs stay intact.
