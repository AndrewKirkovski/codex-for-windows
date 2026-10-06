import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import os
import shutil

import windows_prevention as toolkit
import guard

ROOT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_config(base):
    config = Path(base) / 'codex'
    config.mkdir()
    hooks = {}
    for event in ('SessionStart', 'UserPromptSubmit', 'PreToolUse'):
        hooks[event] = [{'matcher': 'preserved', 'hooks': [
            {'type': 'command', 'command': 'py -3 -B C:/test/codex-command-guard/v23/bootstrap.py', 'commandWindows': 'py -3 -B C:/test/codex-command-guard/v23/bootstrap.py', 'timeout': 8},
            {'type': 'command', 'command': 'gitkraken existing hook', 'timeout': 9},
        ]}]
    (config / 'hooks.json').write_text(json.dumps({'hooks': hooks}), encoding='utf-8')
    (config / 'AGENTS.md').write_bytes(b'Existing runtime and Wippy rules.\r\n')
    (config / 'config.toml').write_bytes(b'preserved-state-fixture')
    return config


def install(config):
    return toolkit.install(config, ROOT, digest(config / 'hooks.json'), digest(config / 'AGENTS.md'))


class ReviewTests(unittest.TestCase):
    def test_hook_uses_canonical_and_supported_command_fields(self):
        cases = [
            {'tool_name': 'Bash', 'tool_input': {'command': 'rm -rf /'}},
            {'tool_name': 'exec_command', 'tool_input': {'cmd': 'rm -rf /'}},
            {'tool_name': 'mcp__process_manager__sync_run', 'tool_input': {'args': {'command': 'rm -rf /'}}},
        ]
        for payload in cases:
            with self.subTest(tool=payload['tool_name']):
                ids = {finding.rule_id for finding in guard.classify(payload)}
                self.assertIn('DESTRUCTIVE-ROOT-001', ids)
                self.assertNotIn('SHELL-PAYLOAD-UNRESOLVED-001', ids)
        patch_payload = {'tool_name': 'apply_patch', 'tool_input': {'command': '*** Begin Patch\n*** End Patch\n'}}
        self.assertEqual([], guard.classify(patch_payload))

    @unittest.skipUnless(os.name == 'nt', 'Native PowerShell parsing requires Windows')
    def test_native_parsers_never_execute_candidate_and_reject_invalid_syntax(self):
        runtimes = [shutil.which(name) for name in ('powershell.exe', 'pwsh.exe')]
        runtimes = [value for value in runtimes if value]
        self.assertTrue(runtimes, 'A Windows parser runtime must be available')
        with tempfile.TemporaryDirectory() as temp:
            sentinel = Path(temp) / 'must-not-exist.txt'
            candidate = Path(temp) / 'candidate.ps1'
            literal = toolkit.safe_powershell_literal(str(sentinel))
            candidate.write_text('Set-Content -LiteralPath ' + literal + ' -Value executed\n', encoding='ascii')
            invalid = Path(temp) / 'invalid.ps1'
            invalid.write_text('if ( {\n', encoding='ascii')
            for runtime in runtimes:
                with self.subTest(runtime=Path(runtime).name):
                    self.assertEqual('valid', toolkit._parse_powershell(candidate, runtime)['outcome'])
                    self.assertFalse(sentinel.exists())
                    result = toolkit._parse_powershell(invalid, runtime)
                    self.assertEqual('invalid', result['outcome'])
                    self.assertTrue(result['diagnostics'])

    def test_nested_managed_command_uses_its_own_working_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            fixtures = guard._copy_contract_fixtures(Path(temp))
            payload = {'tool_name': 'mcp__process_manager__sync_run', 'cwd': str(fixtures / 'plain-project'), 'tool_input': {
                'working_dir': str(fixtures / 'plain-project'),
                'args': {'command': 'npm exec vite -- build', 'working_dir': str(fixtures / 'wippy-project')},
            }}
            ids = {finding.rule_id for finding in guard.classify(payload)}
            self.assertIn('WIPPY-MAKEFILE-BUILD-ONLY-001', ids)
            payload['tool_name'] = 'unknown'
            self.assertEqual([], guard.classify(payload))

    def test_plan_does_not_write_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            before = {p.name: p.read_bytes() for p in config.iterdir()}
            result = toolkit.install(config, ROOT, digest(config / 'hooks.json'), digest(config / 'AGENTS.md'), plan_only=True)
            self.assertEqual('planned', result['outcome'])
            self.assertEqual(before, {p.name: p.read_bytes() for p in config.iterdir()})

    def test_install_preserves_nested_hooks_and_exact_state(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            result = install(config)
            table = json.loads((config / 'hooks.json').read_text(encoding='utf-8'))['hooks']
            for entries in table.values():
                self.assertEqual('preserved', entries[0]['matcher'])
                self.assertEqual(8, entries[0]['hooks'][0]['timeout'])
                self.assertEqual('gitkraken existing hook', entries[0]['hooks'][1]['command'])
                self.assertIn('-B', entries[0]['hooks'][0]['commandWindows'])
            self.assertEqual(b'preserved-state-fixture', (config / 'config.toml').read_bytes())
            toolkit.rollback(Path(result['transaction']))

    def test_failed_agents_write_restores_hooks(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            hooks_before = (config / 'hooks.json').read_bytes()
            agents_before = (config / 'AGENTS.md').read_bytes()
            original_write = toolkit._write_atomic
            def fail_agents(path, data):
                if path == config / 'AGENTS.md':
                    raise OSError('simulated write failure')
                original_write(path, data)
            with patch.object(toolkit, '_write_atomic', side_effect=fail_agents):
                with self.assertRaises(RuntimeError):
                    install(config)
            self.assertEqual(hooks_before, (config / 'hooks.json').read_bytes())
            self.assertEqual(agents_before, (config / 'AGENTS.md').read_bytes())
            self.assertFalse((config / 'hooks/codex-windows-prevention/v24').exists())

    def test_changed_package_refuses_rollback_before_globals_write(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            result = install(config)
            before = {(config / name): (config / name).read_bytes() for name in ('hooks.json', 'AGENTS.md')}
            package = config / 'hooks/codex-windows-prevention/v24/guard.py'
            package.write_bytes(package.read_bytes() + b'\n# later user change\n')
            with self.assertRaises(ValueError):
                toolkit.rollback(Path(result['transaction']))
            for path, expected in before.items():
                self.assertEqual(expected, path.read_bytes())

    def test_concurrent_agents_change_is_preserved_on_install_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            hooks_before = (config / 'hooks.json').read_bytes()
            original_write = toolkit._write_atomic
            changed = b'User concurrent change.\n'
            def change_after_hooks(path, data):
                original_write(path, data)
                if path == config / 'hooks.json':
                    (config / 'AGENTS.md').write_bytes(changed)
            with patch.object(toolkit, '_write_atomic', side_effect=change_after_hooks):
                with self.assertRaises(RuntimeError):
                    install(config)
            self.assertEqual(hooks_before, (config / 'hooks.json').read_bytes())
            self.assertEqual(changed, (config / 'AGENTS.md').read_bytes())


if __name__ == '__main__':
    unittest.main()
