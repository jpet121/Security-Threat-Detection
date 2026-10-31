"""Frozen source-derived prospective black-box CLI acceptance tests.

Not executed during PEHAVOS handoff; tests intentionally depend on the future app.
Never edit these or source fixtures to force a Codex PASS.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
RULES = PROJECT / 'rules' / 'default.toml'


def invocation(lines, *, gzip_input=False, inputs=None):
    """A genuine filesystem/CLI operation, no patched services."""
    temporary = tempfile.TemporaryDirectory()
    base = Path(temporary.name)
    files = []
    if inputs is not None:
        for number, content in enumerate(inputs):
            f = base / ('evidence_' + str(number) + '.log')
            f.write_bytes(content)
            files.append(f)
    else:
        f = base / ('evidence.log.gz' if gzip_input else 'evidence.log')
        if gzip_input:
            import gzip
            f.write_bytes(gzip.compress(lines.encode('utf-8')))
        else:
            f.write_text(lines, encoding='utf-8')
        files = [f]
    old_hashes = {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    output = base / 'audit-output'
    cmd = [sys.executable, '-m', 'security_log_auditor']
    for f in files:
        cmd.extend(['--input', str(f)])
    cmd.extend(['--rules', str(RULES), '--output', str(output)])
    env = dict(os.environ)
    env['PYTHONPATH'] = str(PROJECT / 'src') + os.pathsep + env.get('PYTHONPATH', '')
    result = subprocess.run(cmd, cwd=PROJECT, env=env, capture_output=True, text=True, timeout=45)
    for f in files:
        assert hashlib.sha256(f.read_bytes()).hexdigest() == old_hashes[str(f)], 'audit modified source'
    findings_file = output / 'findings.jsonl'
    findings = [json.loads(line) for line in findings_file.read_text(encoding='utf-8').splitlines() if line.strip()] if findings_file.exists() else []
    manifest_file = output / 'manifest.json'
    manifest = json.loads(manifest_file.read_text(encoding='utf-8')) if manifest_file.exists() else {}
    return temporary, base, result, findings, manifest


class FrozenSecurityLogOracles(unittest.TestCase):
    def run_single(self, line):
        context, base, result, findings, manifest = invocation(line + '\n')
        self.addCleanup(context.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((base / 'audit-output' / 'summary.md').is_file())
        self.assertTrue(manifest.get('source_inventory'), manifest)
        self.assertIn('unique_matched_events', manifest)
        self.assertIn('total_rule_matches', manifest)
        return findings, manifest

    def test_ssh_failed_password_positive_s01(self):
        findings, manifest = self.run_single('Oct 17 02:03:04 edge-a sshd[312]: Failed password for invalid user organizer from 198.51.100.7 port 55522 ssh2')
        self.assertTrue(any(f['classification'] == 'failed_authentication' for f in findings))
        self.assertTrue(any(f['line_start'] == 1 and f['line_end'] == 1 for f in findings))

    def test_ssh_accepted_password_not_failed_s02(self):
        findings, _ = self.run_single('Oct 17 02:03:05 edge-a sshd[312]: Accepted password for organizer from 198.51.100.7 port 55522 ssh2')
        self.assertFalse(any(f['classification'] == 'failed_authentication' for f in findings))

    def test_generic_http_401_is_not_login_failure_s03(self):
        findings, _ = self.run_single('198.51.100.7 - - [17/Oct/2026:02:03:06 +0000] "GET /health HTTP/1.1" 401 12')
        self.assertFalse(any(f['classification'] == 'failed_authentication' for f in findings))

    def test_benign_semicolon_not_injection_s05(self):
        findings, _ = self.run_single('198.51.100.5 - - [17/Oct/2026:02:05:00 +0000] "GET /search?q=hello%3Bworld HTTP/1.1" 200 45')
        self.assertFalse(any(f['classification'] == 'suspected_injection' for f in findings))

    def test_encoded_command_substitution_s06(self):
        findings, _ = self.run_single('198.51.100.8 - - [17/Oct/2026:02:06:00 +0000] "GET /diagnostics?host=%24%28id%29 HTTP/1.1" 400 0')
        self.assertTrue(any(f['classification'] == 'suspected_injection' for f in findings))
        self.assertTrue(all('compromised' not in str(f).lower() for f in findings))
        self.assertTrue(all(f.get('rule_hits') for f in findings))

    def test_secret_redaction_in_all_ordinary_outputs_s19(self):
        line = '198.51.100.8 - - [17/Oct/2026:02:06:00 +0000] "GET /diagnostics?token=SECRET_SAMPLE_TOKEN&host=%24%28id%29 HTTP/1.1" 400 0'
        context, base, result, _, _ = invocation(line + '\n')
        self.addCleanup(context.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('SECRET_SAMPLE_TOKEN', result.stdout + result.stderr)
        for path in (base / 'audit-output').rglob('*'):
            if path.is_file() and path.suffix in ('.jsonl', '.csv', '.md', '.json', '.html'):
                self.assertNotIn('SECRET_SAMPLE_TOKEN', path.read_text(encoding='utf-8'))

    def test_gzip_physical_hash_synthetic(self):
        context, _, result, findings, manifest = invocation('Oct 17 02:03:04 edge-a sshd[312]: Failed password for organizer from 198.51.100.7 port 55522 ssh2\n', gzip_input=True)
        self.addCleanup(context.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(f['classification'] == 'failed_authentication' for f in findings))
        self.assertTrue(any(src.get('raw_sha256') for src in manifest['source_inventory']))

    def test_unreadable_selected_source_not_complete_s16(self):
        if os.geteuid() == 0:
            self.skipTest('Unix root bypasses ordinary file permission denial; run under unprivileged CI')
        context = tempfile.TemporaryDirectory()
        self.addCleanup(context.cleanup)
        base = Path(context.name)
        file = base / 'evidence.log'
        file.write_text('Oct 17 00:00:00 web sshd[2]: Failed password for x from 198.51.100.8 port 123 ssh2\n')
        file.chmod(0)
        try:
            cmd = [sys.executable, '-m', 'security_log_auditor', '--input', str(file), '--rules', str(RULES), '--output', str(base / 'out')]
            env = dict(os.environ); env['PYTHONPATH'] = str(PROJECT / 'src') + os.pathsep + env.get('PYTHONPATH', '')
            result = subprocess.run(cmd, cwd=PROJECT, env=env, capture_output=True, text=True, timeout=45)
            self.assertNotEqual(result.returncode, 0)
            manifest_file = base / 'out' / 'manifest.json'
            if manifest_file.exists():
                self.assertNotEqual(json.loads(manifest_file.read_text()).get('run_state'), 'complete')
        finally:
            file.chmod(0o600)

    def test_bad_rules_rejected_before_scan_s17(self):
        context = tempfile.TemporaryDirectory()
        self.addCleanup(context.cleanup)
        base = Path(context.name)
        source = base / 'evidence.log'
        source.write_text('test\n')
        bad_rule = base / 'invalid.toml'
        bad_rule.write_text('schema_version = [ invalid\n', encoding='utf-8')
        env = dict(os.environ); env['PYTHONPATH'] = str(PROJECT / 'src') + os.pathsep + env.get('PYTHONPATH', '')
        result = subprocess.run([sys.executable, '-m', 'security_log_auditor', '--input', str(source), '--rules', str(bad_rule), '--output', str(base / 'out')], cwd=PROJECT, env=env, capture_output=True, text=True, timeout=45)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.strip())
        self.assertNotIn('SECRET_SAMPLE_TOKEN', result.stderr)

    def test_deterministic_substantive_replay_s24(self):
        evidence = 'Oct 17 02:03:04 edge-a sshd[312]: Failed password for organizer from 198.51.100.7 port 55522 ssh2\n'
        context_one, _, result_one, findings_one, manifest_one = invocation(evidence)
        context_two, _, result_two, findings_two, manifest_two = invocation(evidence)
        self.addCleanup(context_one.cleanup)
        self.addCleanup(context_two.cleanup)
        self.assertEqual(result_one.returncode, 0, result_one.stderr)
        self.assertEqual(result_two.returncode, 0, result_two.stderr)
        def stable(findings):
            return [(x['classification'], x.get('fields_redacted'), [(h['rule_id'], h['rule_version']) for h in x['rule_hits']]) for x in findings]
        self.assertEqual(stable(findings_one), stable(findings_two))
        self.assertEqual(manifest_one['records_examined'], manifest_two['records_examined'])
        self.assertEqual(manifest_one['total_rule_matches'], manifest_two['total_rule_matches'])

    def test_rule_counts_never_less_than_event_counts_s20(self):
        findings, manifest = self.run_single('198.51.100.8 - - [17/Oct/2026:02:06:00 +0000] "GET /diagnostics?host=%24%28id%29 HTTP/1.1" 400 0')
        self.assertGreaterEqual(manifest['total_rule_matches'], manifest['unique_matched_events'])
        self.assertEqual(manifest['unique_matched_events'], len({(f['source_id'], f['line_start'], f['line_end']) for f in findings}))


if __name__ == '__main__':
    unittest.main()
