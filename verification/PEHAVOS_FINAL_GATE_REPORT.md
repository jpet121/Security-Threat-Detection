# PEHAVOS v0.1.1 — Final acceptance-gate continuation

**Date:** 2026-10-31  
**Candidate:** Security Threat Detection 0.1.1  
**Authority:** original compiler XML; original frozen executable and scenario tests  
**Decision:** `REMEDIATION_VERIFIED / FULL_TARGET_RUNTIME_BLOCKED / CUSTOMER_ACCEPTANCE_OPEN / PRODUCTION_NOT_APPROVED`

## Summary

This is a new independent continuation of the preceding v0.1.1 reverification. It neither modifies the original v0.1.0 review and ZIP nor supersedes the historical NOT APPROVED record. No confirmed new functional correctness defect was identified in the executed scope. Both original independent regressions pass unchanged. The full 55-test target-runtime replay **has not been completed independently** because Python 3.12.14 and Hypothesis are unavailable and dependency download was blocked by DNS/network restrictions in the independent container.

## Authority and immutable baselines

- External original compiled XML SHA-256: `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050` — identical to both candidate copies.
- Original v0.1.0 ZIP SHA-256: `643ac24332b7eb6e79d83592391bf05214364fad18bb1ed5edf79efa77541c94`.
- Frozen scenarios and two frozen executable test files: byte-identical between main suite and handoff baseline.
- No source or frozen-test edits were used for this continuation. Verification was conducted on an isolated extracted copy of the candidate.

## Fresh independent execution (Linux, unprivileged user)

| Category | Tests executed | Result |
|---|---:|---|
| Core test suite (`test_auditor.py`) | 26 | 26 PASS |
| Frozen acceptance oracles | 11 | 11 PASS |
| Frozen fixture integrity | 1 | 1 PASS |
| Non-property remediation cases | 10 | 10 PASS |
| Labeled sample bundle | 1 | 1 PASS |
| Original independent DEF-01/DEF-02 regressions, unchanged | 2 | 2 PASS |

**49** candidate non-property tests were replayed successfully across separate invocations, plus **2** unchanged original independent regression tests. The ten remediation tests were run from a non-property-only auxiliary copy, not from the original `test_remediation.py`; the original was not changed. The missing six Hypothesis property tests are **not** represented as independently executed. Independent line/branch coverage of 100% was established in the preceding reverification, but was not remeasured in this continuation; see `PRIOR_v0_1_1_INDEPENDENT_REPORT.md`.

Environment: Linux Python **3.13.5**, `regex` **2026.5.9**, running as `nobody`, not Python 3.12.14 with `regex==2026.4.4`. Exact-target compatibility requires the portable replay script and a supported installation of that interpreter.

## New independent capacity checks

All synthetic runs used 40 source files, completed with exit code 0, and reconciled expected input records, unique findings and JSONL finding counts. Workloads were generated independently of the developer's reference benchmark, using deterministic identical-per-host cases and a mixed failure/benign case.

| Workload | Source records | Elapsed seconds | Peak process RSS (MiB) | Count reconciliation |
|---|---:|---:|---:|---|
| mixed | 20,000 | 5.09 | 98.1 | PASS |
| mixed | 200,000 | 22.11 | 103.8 | PASS |
| dense | 400 | 0.28 | 98.3 | PASS |
| dense | 1,600 | 1.80 | 103.3 | PASS |
| dense | 6,400 | 28.00 | 103.7 | PASS |

- For the mixed workloads, 20,000 -> 200,000 records (10×) increased measured peak RSS by approximately 5.7 MiB in this container. That is evidence of reasonably bounded memory over the tested range, not a proof for arbitrarily large logs.
- For dense workloads, 1,600 -> 6,400 events (4×) increased elapsed time from approximately 1.80 s to 28.00 s (about 15.6×). This corroborates the earlier capacity concern, not a specified performance-SLA failure.
- Absolute RSS includes approximately 93 MiB from this execution environment's Python process startup; do not compare these numbers directly to developer measurements on a different runtime. Benchmarks were run with variable host contention, so they are diagnostic, not controlled throughput certification.
- No customer incident corpus, representative customer machine, approved maximum latency or accepted memory budget was supplied. Synthetic throughput must not be represented as validated production capacity.

## Outstanding formal gates

1. **Exact-runtime property testing:** Run the complete original 55 tests, original two independent regressions, and v1.2 coverage-first gate on unprivileged Linux Python 3.12.14 with `regex==2026.4.4` and Hypothesis 6.170.14. Do not replace or edit frozen tests to make them pass. An executable procedure is included at `scripts/run_full_55_on_ubuntu.sh`.
2. **Real-format evidence (P072):** Get appropriately sanitized actual log layouts, with independently provided analyst labels and explicit source handling approval.
3. **Detection measures (P083, P090):** Produce false-positive/false-negative counts and representative unknown/unsupported-formats accounting against the labels. The small synthetic test is insufficient.
4. **Performance (P085):** Establish documented realistic volume, concurrency/event density, investigator host, maximum runtime and RSS envelope; benchmark that envelope. Consider targeted engineering optimization if dense correlation time is unacceptable.
5. **Human analyst acceptance (P089):** An analyst unfamiliar with the test corpus follows the instructions and evaluates the resulting evidence and manually reviewed records. Human production authorization remains a separate decision.

## Verdict and practical disposition

**No additional Codex defect-remediation round is justified by the executed correctness evidence.** However, non-linear dense-event correlation is an actionable engineering risk. If required throughput cannot be met, Codex should receive a narrowly scoped performance task without changing the frozen tests or authoritative source. The candidate may be described publicly as a verified-development **portfolio project with disclosed limitations**, but should not be labeled independently production-certified or customer-accepted.

The next immediate action is the exact-runtime replay. That requires an Ubuntu/Linux host with the stated interpreter, an approved dependency installation route, and this candidate's unmodified project files. Attach its generated `PEHAVOS_011_TARGET_REPLAY_EVIDENCE.zip` for independent review. Customer-label acceptance cannot be completed without the underlying evidence and analyst participation.
