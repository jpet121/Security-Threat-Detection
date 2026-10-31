# PEHAVOS Independent Verification — Security Threat Detection 0.1.0

**Decision: NOT APPROVED — remediation required.**  
**Verification scope:** Supplied implementation ZIP vs supplied independent compiled XML and frozen handoff tests.  
**Source preservation:** Original user ZIP, XML, compiler receipt, frozen fixtures, and frozen tests were never modified. Verification ran against a separately extracted working copy.

## Executive result

The supplied XML and both archived contract copies are byte-identical. The archived frozen scenarios and executable oracles are byte-identical to each other; external compiler receipt matches the archived receipt. All 24 artifacts covered by the implementation receipt's checksum map matched their stated SHA-256 hashes. The program executed successfully in a separate CLI smoke test from its installed distribution wheel.

**The original frozen executable suite passed 11/11 as an unprivileged Linux user.** The 39 tests excluding the five Hypothesis property tests passed 39/39 as that same user. Independent coverage measurement with those 39 tests reached **530/530 executable statements and 208/208 branches (100% line and branch)** across all eight application modules. High coverage does not prove correctness; independent contract-driven red tests confirmed two defects, both reproducible without modifying code or frozen tests.

The environment for independent execution was **Python 3.13.5 with regex 2026.5.9**, not the developer's claimed Python 3.12.14 with pinned regex 2026.4.4. The included wheel installed and ran when installed `--no-deps`, using the environment's existing regex library. Python 3.12/pinned-wheel-specific execution remains a release validation gap. Hypothesis was unavailable and an offline package retrieval failed; the five supplied Hypothesis tests were not independently executed. The developer's original 44-test claim is *not* independently re-certified in full.

## Blocking confirmed defects

### DEF-01 — Escaped quotes silently truncate a security-sensitive console field (High)

- **Contract coverage affected:** P012 (multiline/format semantics without inventing), P013 (unreliably parsed records must be flagged rather than silently discarded), P024–P027 (context-aware inspection and explainable injection findings), P090 (detect suspicious indicators with limitations).
- **Evidence:** `src/security_log_auditor/parsing.py` uses `KV = re.compile(r'(?<!\S)([\w.]+)=(?:"([^"\r\n]*)"|([^\s]+))')` and a regex-only field extraction that stops at a backslash-escaped quote. The parser accepts the record as a valid console event and ignores the rest of the field, including an injection indicator.
- **Reproduction:** `2026-10-17T02:08:00Z web request.query="note=\"safe\";cat /etc/passwd" status=403` (the shell command text is purely inert test data).
- **Observed:** CLI exit 0, run_state `complete`, 1 examined, 0 findings, 0 manual-review records. Direct parser extracted request.query as `note=\`, discarding `;cat /etc/passwd`. The equivalent unescaped quoted field is detected as `shell.command-chain`.
- **Expected:** Either safely parse escaped quoted fields and detect the suspicious command, or mark the record as unreliable/unclassified for manual review; never silently claim a clean scan.
- **Regression:** `independent_regressions.py::test_R01_escaped_console_quote_must_not_silently_hide_injection` — confirmed failing.

### DEF-02 — Interrupted artifact publication leaves unmarked output in final directory (High)

- **Contract coverage affected:** P063 (truthful incomplete status) and P064 (distinct partial/final results), plus P055 (safe non-append/repeat behavior).
- **Evidence:** `src/security_log_auditor/runner.py`, `publish_output`, creates the final directory *before* moving multiple staged files. On a move failure, it removes the destination manifest but does not remove or quarantine previously moved files, nor remove the final directory.
- **Reproduction:** Invoke the built-in `mover` seam with a deterministic failure on the second move. No mock library or patching was used.
- **Observed:** The final-looking `results` directory existed containing `summary.md`, while the `.partial-*` directory still contained remaining artifacts, including `manifest.json`. The final directory contained no explicit incomplete marker.
- **Expected:** A failed publication cannot leave unmarked partial results under the reserved final output path. Use an atomic directory-level commit where supported, or cleanly roll back/quarantine the final directory and preserve a conspicuously labeled partial state.
- **Regression:** `independent_regressions.py::test_R02_interrupted_publication_must_not_leave_unmarked_final_results` — confirmed failing.

## Scope and additional observations

- **SSH public-key failure coverage (review required):** A representative `Failed publickey for ...` SSH record produces zero findings with exit 0. The default documented rule supports `Failed password` only. P014 broadly describes genuine SSH authentication failures; P015 specifically discusses failed-password evidence. The owner must decide whether public-key failures are in required scope. If in scope, add a source-aware rule and positive/negative cases. This is logged as a coverage decision, **not** an additional confirmed defect.
- **HTTP request target fragment handling (review required):** A raw logged request target containing `#%24%28id%29` yielded no alert, because `urlsplit` excludes fragments from parsed path/query. Normal HTTP request targets generally should not contain URI fragments; decide whether anomalous raw targets must go to manual review. Do not treat this observation as proof of a general URL parser failure.
- **Correlation complexity (risk):** `Store.groups` performs several interval aggregation queries per timed authentication finding, and overlapping high-density windows could be expensive. Synthetic burst probes at 200, 400, 800, and 1,600 records completed, but no high-density weekend-size stress certification was run. Assess scalability of grouping with realistic bursts.
- **No-mocking policy:** No `unittest.mock`, `MagicMock`, or equivalent mocking import/usage was found in first-party application tests via static scan. Existing seam-based fault tests and the new independent regressions use real data, filesystem operations, and deterministic failing adapters.
- **Disclosure of limitations:** Existing documentation correctly distinguishes suspected commands from proven execution and discloses source layout, timestamp, encoding, false-positive, and redaction limitations. This is a source review finding; not a proof of comprehensive security coverage.

## Test and evidence matrix

| Check | Independent result | Evidence |
|---|---|---|
| External source XML vs implementation and handoff XML | PASS — SHA-256 identical | `integrity.json` |
| External compiler receipt vs archived receipt | PASS — byte-identical | `integrity.json` |
| Frozen JSON and executable oracle vs handoff copies | PASS — byte-identical | `integrity.json` |
| Implementation receipt SHA-256 file list | PASS — 24/24 | `integrity.json` |
| Frozen acceptance oracles, non-root Linux | PASS — 11/11 | `evidence/frozen_tests_unprivileged.log` |
| All non-Hypothesis tests, non-root Linux | PASS — 39/39 | `evidence/core_tests_unprivileged.log` |
| Independent line/branch coverage, 39 tests | PASS — 100% / 100% | `evidence/coverage_summary.txt`, `evidence/coverage_full.json` |
| Additional frozen concrete scenario samples S01–S11 | PASS — inspected output classes/review, no mismatch observed | execution notes in this report |
| Isolated application wheel install and CLI smoke | PASS, unpinned runtime dependency | `evidence/wheel_install.log`, `evidence/wheel_smoke.log` |
| Independent contract-driven red tests | FAIL — 2/2 fail as expected | `evidence/independent_red_tests.log`, `independent_regressions.py` |
| Five Hypothesis property tests | NOT RUN — dependency missing | `evidence/hypothesis_dependency_attempt.log` |
| Python 3.12 with pinned regex wheel | NOT RUN — CPython 3.12 unavailable here | execution environment disclosure |
| Independent real-data sensitivity/false-positive study | BLOCKED — labeled client data not provided | P072, P083, P090 |
| Representative busy-weekend workload, host/resource acceptance | BLOCKED — real benchmark corpus/host not provided | P085–P086 |
| Analyst unfamiliar-case acceptance test | BLOCKED — customer analyst/bundle not available | P089 |
| Human production sign-off | NOT GRANTED | User approval boundary |

**Supplemental memory sanity check:** Independent synthetic benign HTTP streams of 20,000 and 100,000 events both completed with exact record counts. Wall times were 2.29s and 7.14s; maximum RSS was 100,752 KiB and 101,016 KiB respectively. These are small, low-finding workloads on this container and do *not* establish bounded memory under all attacker-controlled records or a busy-weekend customer corpus (`evidence/independent_small_benchmark.json`).

## Release blockers and recommended order

1. Correct DEF-01 without silently rewriting original log bytes. Add a regression for escaped quotes, malformed/unbalanced escaping, and attempted attack text outside/after a parsed field. Unsupported or ambiguous source formats must be reported for review.
2. Correct DEF-02 using atomic publication/rollback semantics and explicit failed-state evidence. Test failures on first, middle, and last artifact moves, disk-full, and destination collision. Never leave unlabeled partial content at the final output path.
3. Keep the original frozen XML, scenarios, and executable tests byte-identical. Add new tests rather than editing the frozen baseline. Rerun the full coverage-first gate after changes; enforce the no-mocking policy.
4. Verify 44/44 (or new total) including actual Hypothesis tests in a Python 3.12-compatible environment with the pinned `regex==2026.4.4` dependency; rerun package-install and filesystem fault tests.
5. Decide public-key SSH and anomalous HTTP raw-target policy against client scope, record supported format boundaries, then run new tests.
6. Obtain sanitized customer layouts, independent analyst labels, genuine representative load, and human sign-off; report measured precision, false positives, omissions, memory/throughput, and investigation-package reproducibility.

**Approval judgment:** The preserved requirements and frozen oracle integrity are verified; the independent non-property tests and coverage gate are clean. Nevertheless, **the two independently reproduced contract defects prevent certification**. No code repairs were made during this verification. A corrected build should return to PEHAVOS for another independent pass.
