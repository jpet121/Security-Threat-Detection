import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from security_log_auditor.config import load
from security_log_auditor.runner import run

ROOT = Path(__file__).resolve().parents[1]


class LabeledBundleTests(unittest.TestCase):
    def test_labeled_synthetic_corpus(self):
        expected = {('auth.log', n, 'failed_authentication') for n in range(1, 6)} | {
            ('access.log', 1, 'suspected_injection'), ('access.log', 4, 'suspected_injection'),
            ('console.log', 1, 'failed_authentication')}
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / 'audit'
            code, manifest = run([ROOT / 'examples/logs'], out, load(ROOT / 'rules/default.toml'))
            self.assertEqual(code, 0)
            findings = [json.loads(line) for line in (out / 'findings.jsonl').read_text().splitlines()]
            observed = {(Path(f['source_path_display_safe']).name, f['line_start'], c) for f in findings for c in f['classifications']}
            self.assertEqual(observed, expected)
            self.assertEqual(manifest['records_examined'], 12)
            self.assertEqual(manifest['unique_matched_events'], 8)
            self.assertEqual(manifest['unclassified_records'], 4)
