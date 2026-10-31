# 10 — Source-frozen acceptance and test strategy

## Test authority / execution separation
Oracles derive from original immutable XML clauses and independently written scenario fixtures, not from Codex's implementation choices. `analysis/ENGINEERING_REVIEW.json` includes 92 prospective Axxx criteria traced to 92 Rxxx and Pxxx items. `tests/FROZEN_SCENARIOS.json` contains 36 concrete positive, negative, malformed and failure fixtures. `tests/test_frozen_oracles.py` is executable acceptance code targeting a future CLI, intentionally **not yet run** because application does not exist. Any actual app test pass claim must include run ID, tested final source hashes, command, stdout and exit code.

## Required precedence
1. Author meaningful `unittest` assertions and explicit constructor/port seams; no framework mocks/patching.
2. After every implementation increment, run shipped `codex/tools/coverage_gate.py` against **all executable first-party Python roots**, with exact roots declared and justified. Gate needs **100% statement/line coverage**, branch percentages measured and reviewed. Exclusion needs owner-reviewed rationale.
3. Only after verified early gate, launch Feynman falsification, Hypothesis property/stateful, differential fuzzing, small Lean accounting model/correspondence, mutation, malicious input, fault injection, LIGO-style independent confirmation, end-to-end and clean-install regression as applicable.
4. Independent final reviewer checks exact returned ZIP hashes and reruns coverage and assurance against only its contents. Human release decision remains ungranted until direct approval.

## Executable neighbor cases
S01 SSH Failed password must classify; S02 Accepted password does not. S03 HTTP 401 alone does not equal actual organizer login failure; S04 explicit configured admin failure does. S05 lone semicolon benign; S06 URL encoded `$()` and S07 command metacharacter+command in attacker field suspect only; S08 documentation string outside relevant input must not. S09 malformed percent encoding accounted. S10/S23 untrusted timestamp must not be manufactured. S11/S19 redacted token and ANSI escaped. S15/S16/S18 incomplete, not success. S20 one event multiple hits; S24 deterministic substantive re-run. S33–S34 are future labeled/benchmark work, **not evaluated results**.

## Frozen source-specific scenario matrix
| Fixture | Purpose | Independent expected class | Source P IDs |
|---|---|---|---|
| S01 | SSH real failure | failed_authentication | P014, P015, P016, P017, P047, P074 |
| S02 | SSH success neighbor | no_failed_authentication | P014, P015, P074, P091 |
| S03 | HTTP 401 neighbor | no_failed_authentication | P015, P016, P074 |
| S04 | Explicit admin failure | failed_authentication | P014, P016, P017, P074 |
| S05 | Benign punctuation | not_suspected_injection | P026, P076, P091 |
| S06 | Hostile command substitution | suspected_injection | P024, P025, P026, P028, P029, P030, P076, P077 |
| S07 | Hostile conjunctive pattern | suspected_injection | P024, P025, P026, P027, P076 |
| S08 | Non-input mentions attack | no_supported_injection | P024, P026, P091 |
| S09 | Malformed escapes | manual_review | P013, P028, P029, P077 |
| S10 | Missing timestamp | undated_event | P033, P034, P078 |
| S11 | Quoted fields/terminal escape | safe_display | P057, P058, P062, P082 |
| S12 | Duplicate evidence | two_provenance_records | P023, P048, P053, P080 |
| S13 | Cross-host burst | grouping_candidate | P019, P021, P022, P038, P040, P075 |
| S14 | Spray candidate | grouping_candidate | P020, P022, P036, P040, P075 |
| S15 | Corrupt gzip | incomplete_audit | P009, P011, P063, P064, P070, P078 |
| S16 | Unreadable file | incomplete_audit | P011, P063, P064, P070, P081 |
| S17 | Invalid regex | rejected_before_audit | P043, P045, P079 |
| S18 | Interrupt and resume | partial_not_final | P055, P063, P064, P070, P081 |
| S19 | Secret in URL | redacted_suspected | P057, P058, P082 |
| S20 | Multi-rule one event | one_unique_multiple_rules | P027, P047, P053 |
| S21 | Malformed UTF8 | accounted_unclassified | P011, P013, P078 |
| S22 | Long hostile input | bounded_reject | P010, P013, P045, P079, P086 |
| S23 | Unknown tz | timestamp_ambiguous | P032, P033, P034, P093 |
| S24 | Repeat run | same_substantive_findings | P055, P056, P081 |
| S25 | Directory symlink | safe_selection | P005, P059, P060, P062 |
| S26 | Source remains immutable | source_preservation | P048, P059, P081, P092 |
| S27 | No network | offline_success | P031, P046, P060, P061 |
| S28 | Corrupt config | rejected_before_audit | P041, P042, P043, P044 |
| S29 | Bounded normalization | manual_review | P028, P029, P077 |
| S30 | Malformed multiline | unclassified | P008, P012, P013, P078 |
| S31 | Timezone ordering | same_absolute_time | P032, P033, P056, P080 |
| S32 | Noisy response | no_auth_failure | P015, P016, P091 |
| S33 | Real samples later | evaluation_required | P072, P083, P084, P089, P090 |
| S34 | Weekend-size load | benchmark_required | P085, P086, P094 |
| S35 | CLI status distinction | distinct_status | P063, P064, P068, P069, P070 |
| S36 | One command report | report_bundle | P049, P050, P052, P054, P087, P088, P089 |

## Metrics and falsification
From analyst-labeled heldout records calculate TP, TN, FP, FN by detection class and group, precision=TP/(TP+FP) and recall=TP/(TP+FN) when denominators positive; otherwise declare undefined. Report per-layout failure and unclassified counts and source coverage. Do not invent numeric threshold for acceptable false-positive rate or memory consumption: spec asks to measure/disclose. Challenge the classifier by searching nearest benign cases and unknown formats; reject-all and alert-all cannot pass the paired S01/S02 and S05/S06 examples.

## Traceability and evidence
Acceptance source anchors in Axxx, full audit matrix in PRD, machine-readable 21 disciplines in engineering JSON. The formal proof model covers small arithmetic/state invariants, not actual regex correctness or a theorem that the real tool is secure. App acceptance needs real client sanitized and analyst annotated corpus (P072); synthetic samples alone are insufficient for final detection performance claims. Current status: READY_NOT_EXECUTED.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
