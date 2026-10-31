# Codex implementation assignment — PEHAVOS source-frozen handoff

**Project:** compile-the-attached-client-requirements-into-a-future-execution
**Immutable owner contract SHA-256:** `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`
**Status:** implementation NOT STARTED; no app tests have passed.

## Authority and task order

1. Read `source/contract.xml` and `source/REQUIREMENT_INDEX.json`. Source XML/owner requirements outrank the engineering draft. Do not silently reinterpret semantics.
2. Read `analysis/ENGINEERING_REVIEW.json` and all 15 core / 7 companion ABVOS documents, particularly the detailed architecture, input/output contracts and work breakdown.
3. Read `codex/CODEX_TASKS.json`. Implement only tasks in dependency order, respecting `allowed_files` and `done_when` acceptance IDs. Do not modify `source/`, `assurance/`, or frozen `tests/` or create fake passing logs.
4. INCREMENTAL COVERAGE-FIRST STAGE (mandatory): retain unit tests. Use source-level dependency seams and hand-written concrete replacements rather than unittest.mock, Mock/MagicMock, monkeypatch, patch or equivalent framework-generated doubles. During EACH code increment execute:

   `python codex/tools/coverage_gate.py --root . --source <FIRST_PARTY_SOURCE_ROOT> --tests tests --json-out evidence/coverage_first.json`

   Replace the placeholder with ALL actual first-party Python source roots, repeating `--source` for additional packages. coverage.py must be available and its version recorded. This gate fails below **100% executable first-party statement/line coverage**, without silently narrowing scope or adding blanket exclusions. The tool must find at least one passing unit test. Branch coverage is MEASURED and REVIEWED, **not a universal 100% threshold**. Validate meaningful assertions and valid, invalid and boundary variations. Unit tests and coverage are necessary but not proof of correctness. The AST no-mock scan is a useful check but not a complete proof; manually review seams, imports and test isolation. Integrations must still be tested against real adapters where applicable.
5. ONLY AFTER the line gate passes, execute the originally required applicable advanced methods: Feynman falsification, Hypothesis, differential fuzz, Lean/model correspondence when applicable, mutation, security, fault injection and the remaining 21 disciplines. Missing capability is BLOCKED/NOT RUN, never a false PASS. Keep the original frozen test sources and acceptance criteria unchanged.
6. RE-EXECUTE tests and coverage independently against the FINAL exact code/ZIP bytes after every material modification. Include source/test hashes, tool versions, full source scope, uncovered lines, branch results, actual logs and failures. A passing developer-side report is not sufficient. Recheck final release candidate and preserve human approval as NOT_GRANTED.
7. Return a ZIP containing implementation files, immutable/unchanged source and tests, ACTUAL test evidence including `evidence/coverage_first.json`, source-to-file mapping, and a completed `IMPLEMENTATION_RECEIPT.json`. Do not claim approval or release.
8. Stop and report a scoped blocker on domain ambiguity, missing environment, dependency, unsuccessful test, or unapproved material change. Never change the original contract without owner authorization.

## Evidence boundaries

`assurance/PRE_CODEX_GATE.json` certifies only the **handoff preparation** within its reported scope. It is not production approval or a passing application test. Hypothesis, Lean, mutation, fuzzing, and external services require actual runs and attributable results before PASS. The human release decision remains NOT_GRANTED.
