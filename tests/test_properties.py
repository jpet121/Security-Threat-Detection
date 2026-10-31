"""Generative falsification against simple independent expected semantics."""
import json
from pathlib import Path
import unittest
from urllib.parse import quote
from hypothesis import given, settings, strategies as st
from security_log_auditor.config import load, LIMITS
from security_log_auditor.parsing import normalize, parse, inspect
from security_log_auditor.safety import safe

ROOT = Path(__file__).resolve().parents[1]
CFG = load(ROOT / 'rules/default.toml')


class PropertyTests(unittest.TestCase):
    @settings(max_examples=300, derandomize=True, deadline=None)
    @given(st.text(max_size=300))
    def test_hostile_unicode_safe_display(self, text):
        result = safe(text)
        self.assertTrue(all(c.isprintable() for c in result))
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertNotIn('\x1b', result)

    @settings(max_examples=200, derandomize=True, deadline=None)
    @given(st.sampled_from(['id', 'whoami', 'cat /etc/passwd', 'echo test']), st.integers(0, 2))
    def test_encoded_command_substitution(self, command, depth):
        payload = '$(' + command + ')'
        for _ in range(depth):
            payload = quote(payload, safe='')
        event = parse('2026-10-17T00:00:00Z request.query="cmd=' + payload + '"', CFG)
        hits, issues = inspect(event, CFG)
        self.assertTrue(any(h['rule_id'] == 'shell.substitution' for h in hits))
        self.assertEqual(issues, [])

    @settings(max_examples=250, derandomize=True, deadline=None)
    @given(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789', min_size=1, max_size=60), st.sampled_from([';', '$', '|', '&', '']))
    def test_punctuation_negative_neighbor(self, text, punctuation):
        event = parse('2026-10-17T00:00:00Z request.query="q=' + text + punctuation + '"', CFG)
        self.assertEqual(inspect(event, CFG), ([], []))

    @settings(max_examples=200, derandomize=True, deadline=None)
    @given(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789', min_size=10, max_size=50), st.integers(0, 2))
    def test_query_secret_encodings(self, secret, depth):
        value = 'token=' + secret + '&host=$(id)'
        for _ in range(depth):
            value = quote(value, safe='')
        self.assertNotIn(secret, safe(value))

    @settings(max_examples=250, derandomize=True, deadline=None)
    @given(st.text(alphabet='abc0123%AZ', max_size=500))
    def test_normalization_bounded(self, text):
        variants, issue = normalize(text, LIMITS)
        self.assertLessEqual(len(variants), LIMITS['decode_depth'] + 1)
        self.assertEqual(variants[0], text)
        self.assertTrue(all(len(v) <= len(text) for v in variants))
        self.assertIn(issue, [None, 'malformed_percent', 'invalid_percent_utf8', 'decode_depth'])
