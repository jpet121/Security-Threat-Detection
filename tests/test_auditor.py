"""Real filesystem integration and explicit failure seams; no runtime patching."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stderr
import io
import gzip
import json
import sqlite3
import unittest
import regex

from security_log_auditor.config import load, LIMITS
from security_log_auditor.parsing import parse, timestamp, inspect, normalize
from security_log_auditor.safety import safe, records, enumerate_sources, open_source
from security_log_auditor.runner import run
from security_log_auditor.reports import Store
from security_log_auditor.cli import main

ROOT = Path(__file__).resolve().parents[1]
SSH = 'Oct 17 02:03:04 edge-a sshd[312]: Failed password for invalid user organizer from 198.51.100.7 port 55522 ssh2'
HTTP = '198.51.100.8 - - [17/Oct/2026:02:06:00 +0000] "GET /diagnostics?token=hidden123&host=%24%28id%29 HTTP/1.1" 400 0'
APP = '2026-10-17T02:03:07Z auth event=organizer_admin_login_failed account=manager42 ip=198.51.100.7 server=edge-a'


class FailingStore:
    def __init__(self, path, limit):
        self.closed = False
    def add(self, event):
        raise sqlite3.OperationalError('disk full')
    def close(self):
        self.closed = True


def interrupt(path):
    raise KeyboardInterrupt()


class AuditorTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.cfg = load(ROOT / 'rules/default.toml')

    def execute(self, text, **kwargs):
        source = self.base / 'input.log'
        source.write_bytes(text.encode() if isinstance(text, str) else text)
        output = self.base / ('out' + str(len(list(self.base.glob('out*')))))
        code, manifest = run([source], output, kwargs.pop('config', self.cfg), **kwargs)
        actual = output if output.exists() else Path(manifest['partial_output'])
        findings = [json.loads(v) for v in (actual / 'findings.jsonl').read_text().splitlines()] if (actual / 'findings.jsonl').exists() else []
        return code, manifest, findings, actual

    def test_app_and_ssh_fields(self):
        code, manifest, findings, out = self.execute(APP + '\n' + SSH)
        self.assertEqual(code, 0)
        self.assertEqual(manifest['records_examined'], 2)
        self.assertEqual(findings[0]['fields_redacted']['account'], 'manager42')
        self.assertEqual(findings[1]['fields_redacted']['account'], 'organizer')
        self.assertIsNone(findings[1]['utc_instant'])
        self.assertEqual(findings[0]['source_id'], manifest['source_inventory'][0]['source_id'])
        self.assertTrue((out / 'clusters.jsonl').exists())

    def test_positive_and_benign_context(self):
        lines = [HTTP, '2026-10-17T02:08:00Z web request.query="host=router;cat /etc/passwd" status=403',
                 '2026-10-17T02:08:01Z app logger=docs message="help explains $(command) syntax"',
                 '198.51.100.5 - - [17/Oct/2026:02:05:00 +0000] "GET /search?q=hello%3Bworld HTTP/1.1" 200 45',
                 SSH.replace('Failed password', 'Accepted password'),
                 HTTP.replace('token=hidden123&host=%24%28id%29', 'q=failed').replace('400 0', '401 0')]
        code, manifest, findings, _ = self.execute('\n'.join(lines))
        self.assertEqual(code, 0)
        self.assertEqual(len(findings), 2)
        self.assertEqual(manifest['unclassified_records'], 4)

    def test_normalization_edges(self):
        for text, issue in [('hi%ZZ', 'malformed_percent'), ('%FF', 'invalid_percent_utf8'), ('%252528id%252529', 'decode_depth')]:
            self.assertEqual(normalize(text, LIMITS)[1], issue)
        self.assertEqual(normalize('a' * 11, LIMITS | {'field_chars': 10})[1], 'field_limit')
        self.assertEqual(normalize('x', LIMITS), (['x'], None))
        code, manifest, _, _ = self.execute(HTTP.replace('%24%28id%29', '%ZZ'))
        self.assertEqual(code, 2)
        self.assertEqual(manifest['manual_review_records'], 1)

    def test_time_policies(self):
        cases = [(None, None, None, 'missing'), ('garbage', None, None, 'invalid'),
                 ('2026-01-01T00:00:00', None, None, 'missing_offset'),
                 ('Oct 17 02:03:04', None, None, 'missing_year_and_offset'),
                 ('Oct 17 02:03:04', 'UTC', 2026, 'operator_timezone'),
                 ('2026-11-01T01:30:00', 'America/Chicago', None, 'ambiguous_or_nonexistent_local_time'),
                 ('2026-03-08T02:30:00', 'America/Chicago', None, 'ambiguous_or_nonexistent_local_time')]
        for raw, tz, year, state in cases:
            self.assertEqual(timestamp(raw, tz, year)[1], state)
        self.assertEqual(timestamp('2026-10-17T04:03:04+02:00')[0], timestamp('2026-10-17T02:03:04Z')[0])
        self.assertEqual(timestamp('17/Oct/2026:04:03:04 +0200')[0], timestamp('2026-10-17T02:03:04Z')[0])
        self.assertLess(timestamp('2026-10-17T02:03:04Z')[0], timestamp('2026-10-17T02:03:04.1Z')[0])

    def test_window_and_unknown_retention(self):
        code, manifest, findings, _ = self.execute(APP + '\n' + SSH, start=timestamp('2026-10-18T00:00:00Z')[0])
        self.assertEqual(code, 0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(manifest['filtered_records'], 1)
        _, manifest, _, _ = self.execute(APP, end=timestamp('2026-10-16T00:00:00Z')[0])
        self.assertEqual(manifest['filtered_records'], 1)

    def test_multiline_prefixes_and_bad_bytes(self):
        code, manifest, findings, _ = self.execute(('container | ' + APP + '\n  stack trace\n').encode() + b'\xff\ntrailer\n')
        self.assertEqual(code, 2)
        self.assertEqual(findings[0]['line_end'], 2)
        self.assertEqual(manifest['records_examined'], 3)
        self.assertEqual(manifest['parse_failures'], 2)

    def test_bounds(self):
        cfg = replace(self.cfg, limits=self.cfg.limits | {'line_bytes': 128, 'event_bytes': 256})
        code, manifest, findings, _ = self.execute('x' * 1000 + '\n' + APP, config=cfg)
        self.assertEqual(code, 2)
        self.assertEqual(manifest['parse_failures'], 1)
        self.assertEqual(len(findings), 1)
        cfg = replace(self.cfg, limits=self.cfg.limits | {'line_bytes': 200, 'event_bytes': 256})
        code, manifest, _, _ = self.execute(APP + '\n' + ' ' * 10 + 'x' * 170 + '\n', config=cfg)
        self.assertEqual(code, 2)
        cfg = replace(self.cfg, limits=self.cfg.limits | {'expanded_bytes': 5})
        code, manifest, _, _ = self.execute(APP, config=cfg)
        self.assertEqual(code, 3)
        self.assertEqual(manifest['run_state'], 'incomplete')

    def test_corrupt_gzip_and_empty(self):
        path = self.base / 'broken.gz'
        path.write_bytes(gzip.compress((SSH + '\n').encode())[:-7])
        code, manifest = run([path], self.base / 'out', self.cfg)
        self.assertEqual(code, 3)
        self.assertIsNotNone(manifest['source_inventory'][0]['raw_sha256'])
        self.assertFalse((self.base / 'out').exists())
        code, manifest, _, _ = self.execute('')
        self.assertEqual(code, 0)
        self.assertEqual(manifest['records_examined'], 0)

    def test_missing_and_symlinks_and_fifo(self):
        inputs = self.base / 'inputs'; inputs.mkdir()
        (inputs / 'link').symlink_to('/etc/passwd')
        (inputs / 'directory-link').symlink_to('/etc', target_is_directory=True)
        (inputs / 'sub').mkdir(); (inputs / 'sub' / 'ok').write_text(APP)
        code, manifest = run([inputs, self.base / 'missing'], self.base / 'out', self.cfg)
        self.assertEqual(code, 3)
        self.assertEqual(len(manifest['source_inventory']), 4)
        self.assertEqual(manifest['unique_matched_events'], 1)
        import os
        fifo = self.base / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(OSError):
            open_source(fifo)
        with self.assertRaises(OSError):
            open_source(inputs / 'link')
        with self.assertRaises(OSError):
            open_source(inputs / 'directory-link' / 'passwd')

    def test_output_validation(self):
        folder = self.base / 'logs'; folder.mkdir()
        with self.assertRaises(ValueError):
            enumerate_sources([folder], folder / 'out')
        with self.assertRaises(ValueError):
            enumerate_sources([folder], self.base / 'out')
        with self.assertRaises(ValueError):
            enumerate_sources([self.base / 'out' / 'x'], self.base / 'out')
        with self.assertRaises(ValueError):
            run([folder], folder, self.cfg)

    def test_injected_faults(self):
        code, manifest, _, _ = self.execute(APP, store_factory=FailingStore)
        self.assertEqual(code, 3)
        self.assertEqual(manifest['errors'][0]['code'], 'OperationalError')
        code, manifest, _, _ = self.execute(APP, opener=interrupt)
        self.assertEqual(code, 3)
        self.assertEqual(manifest['errors'][0]['code'], 'KeyboardInterrupt')

    def test_regex_timeout_and_multiple_hits(self):
        rule = replace(self.cfg.rules[-1], pattern=regex.compile('(a+)+$'))
        cfg = replace(self.cfg, rules=(rule,), limits=self.cfg.limits | {'regex_seconds': .000001})
        event = parse('2026-10-17T02:08:00Z request.query="' + 'a' * 2000 + '!"', self.cfg)
        self.assertIn('regex_timeout', inspect(event, cfg)[1])
        cfg = replace(self.cfg, rules=(replace(self.cfg.rules[-1], enabled=False),))
        self.assertEqual(inspect(event, cfg), ([], []))
        line = HTTP.replace('%24%28id%29', '%24%28id%29%3Bcat%20/etc/passwd')
        _, manifest, findings, _ = self.execute(line)
        self.assertEqual(manifest['unique_matched_events'], 1)
        self.assertEqual(manifest['total_rule_matches'], 2)
        self.assertEqual(len(findings[0]['rule_hits']), 2)

    def test_clusters(self):
        lines = [APP.replace('manager42', 'user' + str(i)).replace('edge-a', 'edge-' + str(i)) for i in range(6)]
        lines += [APP] * 6 + [HTTP]
        code, manifest, findings, output = self.execute('\n'.join(lines))
        self.assertEqual(code, 0)
        groups = [json.loads(v) for v in (output / 'clusters.jsonl').read_text().splitlines()]
        self.assertEqual({g['kind'] for g in groups}, {'repeated_account', 'password_spray', 'cross_server_burst', 'temporal_proximity'})
        self.assertEqual(manifest['unique_matched_events'], 13)
        self.assertEqual(len(findings), 13)

    def test_redaction_and_controls(self):
        for text in ['token=hidden123', 'token="hidden123"', 'Authorization: Bearer hidden123', 'Cookie: sid=hidden123', 'token%3Dhidden123', 'session_id=hidden123']:
            self.assertNotIn('hidden123', safe(text))
        self.assertEqual(safe({'token': 'hidden123'}), {'token': '[REDACTED]'})
        self.assertIn('\\u001b', safe('\x1b[31m'))
        self.assertNotIn('hidden123', safe('%252525252574oken=hidden123'))
        code, _, _, output = self.execute(HTTP)
        self.assertEqual(code, 0)
        for path in output.iterdir():
            self.assertNotIn('hidden123', path.read_text())

    def test_config_errors(self):
        base = (ROOT / 'rules/default.toml').read_text()
        cases = ['schema_version=2', base.replace('line_bytes = 65536', 'line_bytes = -1'),
                 base.replace('line_bytes = 65536', 'line_bytes = 1.5'),
                 base.replace('line_bytes = 65536', 'line_bytes = 16777217'),
                 base.replace('[groups]', '[groups]\nunknown = 5'),
                 base.replace('schema_version = 1', 'schema_version = 1\n[console]\nunknown = "a"'),
                 base.replace('schema_version = 1', 'schema_version = 1\n[console]\ntimestamp = "a"'),
                 base.replace('id = "shell.substitution"', 'id = "shell.command-chain"'),
                 base.replace('priority = "high"', 'priority = 5'),
                 base.replace('classification = "suspected_injection"', 'classification = "something"'),
                 base.replace('formats = ["http", "console"]', 'formats = ["bad"]'),
                 base.replace('fields = ["event"]', 'fields = ["request.body"]'),
                 base.replace('fields = ["event"]', 'fields = ["unknown"]'),
                 base.replace('fields = ["request.query", "request.path", "request.body", "request.header", "request.user_agent", "request.referer"]', 'fields = ["auth_message"]'),
                 base.replace('priority = "review"', 'unknown = "review"'),
                 base.replace("pattern = '^organizer_admin_login_failed$'", "pattern = '" + 'a' * 8200 + "'")]
        path = self.base / 'bad.toml'
        for text in cases:
            path.write_text(text)
            with self.subTest(text=text[:40]), self.assertRaises((ValueError, regex.error)):
                load(path)
        path.write_bytes(b'x' * 1048577)
        with self.assertRaises(ValueError):
            load(path)

    def test_cli_validation(self):
        path = self.base / 'input'; path.write_text(APP)
        for extra in [['--timezone', 'NoSuch/Zone'], ['--syslog-year', '0'], ['--from', 'bad'],
                      ['--from', '2026-10-19T00:00:00Z', '--to', '2026-10-18T00:00:00Z'], ['--rules', str(self.base / 'missing')]]:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(['--input', str(path), '--output', str(self.base / 'out')] + extra), 64)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--input', str(path), '--output', str(self.base / 'out'), '--timezone', 'UTC']), 0)

    def test_module_entrypoint(self):
        import runpy
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runpy.run_module('security_log_auditor', run_name='__main__')

    def test_remaining_parser_boundaries(self):
        self.assertIsNone(parse(HTTP.replace('/diagnostics?token=hidden123&host=%24%28id%29', 'http://[invalid'), self.cfg))
        self.assertEqual(normalize('%2541', LIMITS), (['%2541', '%41', 'A'], None))
        path = self.base / 'rules'; path.write_text('schema_version = 1')
        with self.assertRaises(ValueError):
            load(path)

    def test_progress_disk_and_permission_failure(self):
        steps = iter([0, 10, 11])
        messages = []
        self.execute(APP, tick=lambda: next(steps), progress=messages.append)
        self.assertTrue(any('Examined 1' in m for m in messages))
        class DiskStore:
            def __init__(self, path, limit):
                path.write_bytes(b'x' * 100)
            def write(self, output, manifest, config):
                return {}
            def add(self, event):
                pass
            def close(self):
                pass
        cfg = replace(self.cfg, limits=self.cfg.limits | {'disk_bytes': 50})
        code, manifest, _, _ = self.execute(APP, config=cfg, store_factory=DiskStore)
        self.assertEqual(code, 3)
        folder = self.base / 'unreadable'; folder.mkdir(); folder.chmod(0)
        try:
            paths = enumerate_sources([folder], self.base / 'result')
            self.assertIn(folder, paths)
        finally:
            folder.chmod(0o700)

    def test_fault_propagation_and_mutation(self):
        class TimedOutPattern:
            def search(self, *args, **kwargs):
                raise TimeoutError()
        cfg = replace(self.cfg, console=self.cfg.console | {'timestamp': TimedOutPattern()})
        code, manifest, _, _ = self.execute(APP, config=cfg)
        self.assertEqual(code, 2)
        self.assertEqual(manifest['parse_failures'], 1)
        class MutatingStream:
            def __init__(self, path):
                self.path = path
                self.stream = path.open('rb')
                self.reads = 0
            def __getattr__(self, key):
                return getattr(self.stream, key)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def readline(self, size):
                block = self.stream.readline(size)
                if not self.reads:
                    with self.path.open('ab') as f:
                        f.write(b'\nextra\n')
                self.reads += 1
                return block
        code, manifest, _, _ = self.execute(APP, opener=MutatingStream)
        self.assertEqual(code, 3)
        def failed_publish(stage, output):
            raise OSError('cannot publish')
        code, manifest, _, _ = self.execute(APP, publisher=failed_publish)
        self.assertEqual(code, 3)
        class LostStage:
            def __init__(self, path, limit):
                path.parent.rmdir()
                raise OSError('lost output filesystem')
        code, manifest, _, _ = self.execute(APP, store_factory=LostStage)
        self.assertEqual(code, 3)

    def test_report_size_failure(self):
        store = Store(self.base / 'db', 100000)
        try:
            store.add({'finding_id': 's1:1', 'utc_instant': None, 'source_id': 's1', 'line_start': 1,
                       'classifications': ['suspected_injection'], 'fields_redacted': {}, 'payload': 'x' * 100})
            with self.assertRaises(OSError):
                store.write(self.base, {'run_state': 'complete'}, replace(self.cfg, limits=self.cfg.limits | {'disk_bytes': 10}))
        finally:
            store.close()

    def test_decompression_limit_while_draining(self):
        cfg = replace(self.cfg, limits=self.cfg.limits | {'line_bytes': 10, 'expanded_bytes': 20})
        with self.assertRaises(OSError):
            list(records(io.BytesIO(b'x' * 1000), cfg))

    def test_publication_preserves_existing_results(self):
        from security_log_auditor.runner import publish_output
        stage = self.base / 'stage'; stage.mkdir()
        (stage / 'findings.jsonl').write_text('data')
        (stage / 'manifest.json').write_text('complete')
        out = self.base / 'published'; out.mkdir()
        (out / 'manifest.json').write_text('original')
        with self.assertRaises(FileExistsError):
            publish_output(stage, out)
        self.assertEqual((out / 'manifest.json').read_text(), 'original')
        def broken_move(source, target):
            raise OSError('disk failure')
        with self.assertRaises(OSError):
            publish_output(stage, self.base / 'new', mover=broken_move)
        self.assertFalse((self.base / 'new' / 'manifest.json').exists())

    def test_corrupted_deflate(self):
        path = self.base / 'invalid.gz'; path.write_bytes(b'\x1f\x8b\x08\x00' + b'\x00' * 6 + b'\xff' * 20)
        code, manifest = run([path], self.base / 'out', self.cfg)
        self.assertEqual(code, 3)
        self.assertEqual(manifest['run_state'], 'incomplete')

    def test_invalid_timestamp_review(self):
        code, manifest, findings, _ = self.execute(APP.replace('10-17', '99-99'))
        self.assertEqual(code, 2)
        self.assertEqual(manifest['manual_review_records'], 1)
        self.assertIsNone(findings[0]['utc_instant'])

    def test_output_parent_alias_rejected(self):
        logs = self.base / 'logs'; logs.mkdir()
        (logs / 'sample').write_text(APP)
        alias = self.base / 'alias'; alias.symlink_to(logs, target_is_directory=True)
        with self.assertRaises(ValueError):
            run([logs], alias / 'out', self.cfg)
        self.assertFalse((logs / 'out').exists())
