"""Independent PEHAVOS red tests. Does not modify original implementation/frozen tests.

Usage: python independent_regressions.py /path/to/extracted/Security-Threat-Detection-0.1.0
Expected until remediation: 2 FAILED assertions.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if len(sys.argv) < 2:
    raise SystemExit('Usage: python independent_regressions.py /path/to/extracted/package')
PROJECT = Path(sys.argv.pop(1)).resolve()
if not (PROJECT / 'src/security_log_auditor/runner.py').exists():
    raise SystemExit('The project argument must name the extracted package root')


class IndependentContractRegressions(unittest.TestCase):
    def test_R01_escaped_console_quote_must_not_silently_hide_injection(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            source = base / 'console.log'
            # This is raw log TEXT, NOT code being executed.
            source.write_text(r'2026-10-17T02:08:00Z web request.query="note=\"safe\";cat /etc/passwd" status=403' + '\n', encoding='utf-8')
            dest = base / 'output'
            env = dict(os.environ, PYTHONPATH=str(PROJECT / 'src'))
            proc = subprocess.run([
                sys.executable, '-m', 'security_log_auditor', '--input', str(source),
                '--rules', str(PROJECT / 'rules/default.toml'), '--output', str(dest)
            ], text=True, capture_output=True, env=env, timeout=30)
            self.assertIn(proc.returncode, (0, 2), proc.stderr)
            manifest = json.loads((dest / 'manifest.json').read_text())
            findings = [json.loads(l) for l in (dest / 'findings.jsonl').read_text().splitlines() if l]
            review = [json.loads(l) for l in (dest / 'manual_review.jsonl').read_text().splitlines() if l]
            self.assertTrue(any('suspected_injection' in f['classifications'] for f in findings) or review,
                            f'Silent loss: findings={findings!r}, manual_review={review!r}, state={manifest["run_state"]!r}')

    def test_R02_interrupted_publication_must_not_leave_unmarked_final_results(self):
        sys.path.insert(0, str(PROJECT / 'src'))
        from security_log_auditor.runner import publish_output
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            stage, final = base / 'results.partial-test', base / 'results'
            stage.mkdir()
            for item in ['findings.jsonl', 'clusters.jsonl', 'summary.md', 'manifest.json']:
                (stage / item).write_text('test', encoding='utf-8')
            counter = [0]
            def fail_on_second_move(source, destination):
                counter[0] += 1
                if counter[0] == 2:
                    raise OSError('injected file publication failure')
                return source.rename(destination)
            with self.assertRaises(OSError):
                publish_output(stage, final, mover=fail_on_second_move)
            if final.exists():
                manifest = final / 'manifest.json'
                self.assertTrue(manifest.exists() and 'incomplete' in manifest.read_text(),
                                f'Unmarked final-looking directory contains {[p.name for p in final.iterdir()]}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
