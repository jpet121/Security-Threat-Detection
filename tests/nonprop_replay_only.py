"""Regressions for independent DEF-01/02 and documented format decisions."""
from pathlib import Path
from tempfile import TemporaryDirectory
import errno
import hashlib
import json
import unittest
from security_log_auditor.config import load
from security_log_auditor.parsing import console_fields, parse, inspect
from security_log_auditor.runner import run, publish_output, rename_noreplace

ROOT = Path(__file__).resolve().parents[1]
CFG = load(ROOT / 'rules/default.toml')
PREFIX = '2026-10-17T02:08:00Z web '


class RemediationTests(unittest.TestCase):
    def audit(self, text):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        source = base / 'console.log'; source.write_text(text + '\n')
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        code, manifest = run([source], base / 'results', CFG)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
        return code, manifest, base

    def test_escaped_quotes_preserve_complete_input(self):
        line = PREFIX + r'request.query="note=\"safe\";cat /etc/passwd" status=403'
        event = parse(line, CFG)
        self.assertEqual(event.fields['request.query'], 'note="safe";cat /etc/passwd')
        self.assertTrue(any(h['rule_id'] == 'shell.command-chain' for h in inspect(event, CFG)[0]))
        code, manifest, base = self.audit(line)
        self.assertEqual(code, 0)
        self.assertEqual(manifest['unique_matched_events'], 1)
        finding = json.loads((base / 'results/findings.jsonl').read_text())
        self.assertEqual(finding['fields_redacted']['request.query'], 'note="safe";cat /etc/passwd')
        self.assertEqual(finding['line_start'], 1)
        self.assertEqual(finding['line_end'], 1)

    def test_malformed_fields_are_reviewed(self):
        cases = [r'request.query="safe";cat /etc/passwd', r'request.query="safe" ;cat /etc/passwd',
                 'request.query="unterminated', 'request.query="trailing\\', r'request.query="unknown\q"',
                 'request.query=abc"def', r'request.query=abc\def',
                 'request.query="safe" request.query="$(id)"', 'request.query=$(id) request.query=safe',
                 'broken"prefix request.query="safe"', 'request.query="safe\n  ;cat /etc/passwd"']
        for body in cases:
            with self.subTest(body=body):
                code, manifest, base = self.audit(PREFIX + body)
                self.assertEqual(code, 2)
                self.assertEqual(manifest['parse_failures'], 1)
                self.assertEqual(manifest['manual_review_records'], 1)
                self.assertEqual(manifest['unique_matched_events'], 0)
                self.assertTrue((base / 'results/manual_review.jsonl').read_text().strip())

    def test_empty_backslash_and_field_context(self):
        self.assertEqual(console_fields(r'logger empty="" bare= request.query="C:\\logs;cat /etc/passwd"'),
                         {'empty': '', 'bare': '', 'request.query': 'C:\\logs;cat /etc/passwd'})
        event = parse(PREFIX + 'message="documentation explains $(id)"', CFG)
        self.assertEqual(inspect(event, CFG), ([], []))
        event = parse(PREFIX + 'event=organizer_admin_login_failed\n  human-readable continuation', CFG)
        self.assertEqual(event.fields['event'], 'organizer_admin_login_failed')


    def test_publickey_failure_source_semantics(self):
        for method in ['password', 'publickey']:
            for suffix in ['', ' [preauth]']:
                text = f'Oct 17 02:03:04 edge-a sshd[312]: Failed {method} for invalid user organizer from 2001:db8::1 port 55522 ssh2{suffix}'
                event = parse(text, CFG)
                self.assertEqual(event.fields['account'], 'organizer')
                self.assertEqual(event.fields['ip'], '2001:db8::1')
                self.assertTrue(any(h['rule_id'] == f'ssh.failed-{method}' for h in inspect(event, CFG)[0]))
                event = parse(text.replace('Failed', 'Accepted'), CFG)
                self.assertEqual(inspect(event, CFG), ([], []))
        code, manifest, _ = self.audit('Oct 17 02:03:04 edge-a sshd[312]: Failed publickey for user1 from 198.51.100.4 port 123 ssh2')
        self.assertEqual(code, 0)
        self.assertEqual(manifest['unique_matched_events'], 1)

    def test_raw_http_fragment_goes_to_review(self):
        line = '198.51.100.8 - - [17/Oct/2026:02:06:00 +0000] "GET /diagnostics?q=safe#%24%28id%29 HTTP/1.1" 400 0'
        code, manifest, _ = self.audit(line)
        self.assertEqual(code, 2)
        self.assertEqual(manifest['manual_review_records'], 1)
        self.assertEqual(manifest['parse_failures'], 1)
        event = parse(line.replace('#', '%23'), CFG)
        self.assertTrue(inspect(event, CFG)[0])

    def stage(self, base):
        stage = base / 'results.partial-test'; stage.mkdir()
        artifacts = {'findings.jsonl': 'findings', 'summary.md': 'summary', 'clusters.jsonl': 'groups',
                     'manifest.json': '{"run_state":"complete"}'}
        for name, content in artifacts.items():
            (stage / name).write_text(content)
        return stage, base / 'results', artifacts

    def test_first_middle_last_moves_never_expose_final_path(self):
        for failure in [1, 2, 4]:
            with self.subTest(failure=failure), TemporaryDirectory() as tmp:
                stage, final, artifacts = self.stage(Path(tmp))
                count = 0
                def moving(source, destination):
                    nonlocal count
                    count += 1
                    self.assertFalse(final.exists())
                    if count == failure:
                        raise OSError(errno.ENOSPC, 'disk full')
                    return source.rename(destination)
                with self.assertRaises(OSError):
                    publish_output(stage, final, mover=moving)
                self.assertFalse(final.exists())
                retained = {p.name: p.read_text() for p in Path(tmp).rglob('*') if p.is_file()}
                self.assertEqual(retained, artifacts)
                self.assertTrue(all('.partial-' in str(p) for p in Path(tmp).rglob('*') if p.is_file()))

    def test_interrupt_before_commit_and_commit_failure(self):
        for exception in [KeyboardInterrupt, OSError]:
            with self.subTest(exception=exception), TemporaryDirectory() as tmp:
                stage, final, _ = self.stage(Path(tmp))
                def refuse_commit(source, destination):
                    self.assertFalse(final.exists())
                    raise exception()
                with self.assertRaises(exception):
                    publish_output(stage, final, commit=refuse_commit)
                self.assertFalse(final.exists())

    def test_atomic_collision_including_empty_directory_and_symlink(self):
        for kind in ['empty', 'populated', 'symlink']:
            with self.subTest(kind=kind), TemporaryDirectory() as tmp:
                stage, final, _ = self.stage(Path(tmp))
                def concurrent_commit(source, destination):
                    if kind == 'symlink':
                        destination.symlink_to(Path(tmp) / 'other')
                    else:
                        destination.mkdir()
                        if kind == 'populated':
                            (destination / 'original').write_text('original')
                    rename_noreplace(source, destination)
                with self.assertRaises(FileExistsError):
                    publish_output(stage, final, commit=concurrent_commit)
                if kind == 'populated':
                    self.assertEqual((final / 'original').read_text(), 'original')
                elif kind == 'symlink':
                    self.assertTrue(final.is_symlink())
                else:
                    self.assertEqual(list(final.iterdir()), [])

    def test_unsupported_atomic_commit_and_cleanup_failure(self):
        with TemporaryDirectory() as tmp:
            stage, final, _ = self.stage(Path(tmp))
            with self.assertRaises(OSError) as context:
                rename_noreplace(stage, final, library=object())
            self.assertEqual(context.exception.errno, errno.ENOTSUP)
            def commit_with_leftover(source, destination):
                rename_noreplace(source, destination)
                (stage / 'leftover').write_text('concurrent staging file')
            publish_output(stage, final, commit=commit_with_leftover)
            self.assertEqual(json.loads((final / 'manifest.json').read_text())['run_state'], 'complete')

    def test_runner_exposes_all_publication_partial_locations(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp); source = base / 'log'
            source.write_text(PREFIX + 'event=organizer_admin_login_failed')
            def faulty_publication(stage, output):
                moves = 0
                def fail_second(source, destination):
                    nonlocal moves
                    moves += 1
                    if moves == 2:
                        raise OSError(errno.ENOSPC, 'disk full')
                    return source.rename(destination)
                publish_output(stage, output, mover=fail_second)
            code, manifest = run([source], base / 'results', CFG, publisher=faulty_publication)
            self.assertEqual(code, 3)
            self.assertFalse((base / 'results').exists())
            self.assertTrue(Path(manifest['publication_partial']).is_dir())
            saved = json.loads((Path(manifest['partial_output']) / 'manifest.json').read_text())
            self.assertEqual(saved['run_state'], 'incomplete')
            self.assertEqual(saved['publication_partial'], manifest['publication_partial'])
