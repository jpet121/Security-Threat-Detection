"""Only test-source fixture self-consistency; not target application acceptance."""
import hashlib
import json
from pathlib import Path
import unittest

class FrozenFixtureSelfCheck(unittest.TestCase):
    def test_fixture_identity_and_complete_scenarios(self):
        root = Path(__file__).resolve().parents[1]
        d = json.loads((root / 'tests' / 'FROZEN_SCENARIOS.json').read_text())
        source = (root / 'source' / 'contract.xml').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), d['source_contract_sha256'])
        self.assertEqual(len(d['scenarios']), 36)
        self.assertEqual(len({s['id'] for s in d['scenarios']}), 36)
        self.assertTrue(all(s['expected'] and s['propositions'] for s in d['scenarios']))

if __name__ == '__main__':
    unittest.main()
