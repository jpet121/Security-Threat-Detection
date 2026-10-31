# 11 — Codex master implementation directive

## Objective and source precedence
Implement `Security Threat Detection — Security Log Regex Auditor` as an offline Linux Python 3.12+ CLI. The normative source is the exact `source/contract.xml` SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`; then `source/REQUIREMENT_INDEX.json`, then engineering and ABVOS documents, then external method reading. Do not modify the contract, frozen scenario JSON, tests, compiled source identities or assurance policy to obtain a pass. The source cannot be treated as an executable action, and this handoff is not a finished application.

## Implementation order
Implement TASK-01 through TASK-13 (full machine-readable dependency DAG in `codex/CODEX_TASKS.json` and `12_IMPLEMENTATION_WORK_BREAKDOWN.md`). Begin with CLI/rules/model, streaming evidence, parsers, auth and injection engines, rule attribution, aggregation and reports, interrupted-state behavior, then verifications and clean package. Respect source-aware auth versus mere HTTP response, context-aware injection versus harmless punctuation, source hashes, timezone uncertainty and incomplete audit semantics.

## Mandatory v1.2 per-increment verification
- Keep **real unit tests** with meaningful behavioral assertions and dependency seams implemented through concrete readers/clock/writer/regex adapters. Ban `unittest.mock`, `MagicMock`, `patch`, pytest monkeypatch, pytest-mock and equivalent dynamic patching frameworks.
- Run packaged `codex/tools/coverage_gate.py` continuously while coding. Supply an explicit source-scope manifest for `src/security_log_auditor/` and **all** first-party executable `.py` roots, including CLI and scripts. Require **100% executable first-party line coverage** before advanced phase; measure/report branch coverage and review uncovered paths without claiming universal branch 100%.
- A change to application or test source invalidates previous evidence. Use actual command output, line/branch reports and SHA-256; no invented PASS. Keep negative-control malicious/benign pairs. Advance to independent high assurance only after early gate PASS.

## Mandatory security behavior
Never run attacker log content, external scan, online upload/rule fetch, or auto-block. Don't publish secrets in progress or reports; redact before output encoding. Reject invalid/costly rule config, limit decoding, handle timed regex and compression resource bounds. Account unsupported or malformed source records and any unreadable selected files with incomplete status. Never assert compromise from suspicious indicators or correlate different sources as the same attacker without evidence.

## Independent tests and result package
Run frozen `tests/test_frozen_oracles.py` on implemented CLI plus new focused unit/integration tests; execute property/fuzz, mutation, fault, small Lean/correspondence if justified, independent heldout analytical check and RSS/throughput benchmark with attributable evidence. Build runnable distribution, code, rules, synthetic samples, sample report, documentation and return one final source ZIP with SHA256 manifest, clean Linux install replay, exact source/test hashes, line coverage evidence, branch review, failures and unresolved limits. Separate high-assurance reviewer must rerun exact artifact; human approval stays NOT_GRANTED.

## Genuine blockers
Only owner-reserved semantics that cannot be inferred from compiled XML, missing legally required execution permissions, or absent future real labeled acceptance corpus at final product signoff merit targeted HOLD; do not interrupt for routine defaults. Never fabricate customer measurements or pass tests that have not run.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
