# 12 — Codex implementation work breakdown and dependencies

## Ordered phase DAG
The below plan respects compiler dependencies at the business capability level, with parser/context checks preceding detection, coverage and final benchmark before release packaging. Each task's exact file allowlist, acceptance IDs and v1.2 locked early gate are in `codex/CODEX_TASKS.json`.

| Task | Prerequisites | Required implementation / deliverable | Mapped acceptance IDs |
|---|---|---|---|
| TASK-01 | None | Freeze contract and define models, config version/schema and integration seams; implement strictly validated CLI arguments, zero output on invalid config. | A001, A041, A042, A043, A044, A065, A066, A069 |
| TASK-02 | TASK-01 | Build authorized local file selector and streaming plain/gzip bytes reader; preserve per-file SHA and read failure dispositions; no symlink escapes. | A003, A005, A009, A010, A011, A048, A059, A094 |
| TASK-03 | TASK-02 | Implement explicit syslog/SSH, documented Apache/Nginx combined/common and configurable console event boundaries; line/range and lossless raw-offset provenance. | A006, A007, A008, A012, A013, A033, A034 |
| TASK-04 | TASK-03 | Implement contextual authentication classification including actual failed SSH and configured organizer-admin failures, and prevent HTTP 401 false positive. | A014, A015, A016, A017, A018, A074 |
| TASK-05 | TASK-03 | Design threat-specific configurable regex detection with per-operation timeouts, input limits and bounded URL decoding; never invoke log content as commands. | A024, A025, A026, A027, A028, A029, A030, A031, A045, A046 |
| TASK-06 | TASK-04,TASK-05 | Create exact original-file/line/rule provenance, secret-safe excerpt transformation, and correct unique-event versus rule-hit accounting. | A023, A047, A048, A053, A057, A058, A062 |
| TASK-07 | TASK-06 | Implement streaming or spill-to-disk windows and chronological merge for account repeats, spray patterns and cross-server bursts; disallow inference of identity. | A019, A020, A021, A022, A032, A035, A036, A037, A038, A040 |
| TASK-08 | TASK-06,TASK-07 | Implement isolated per-run temp directory with redacted JSONL/CSV/Markdown, machine manifest with every source disposition and incomplete/failure states. | A049, A050, A052, A054, A055, A056, A063, A064 |
| TASK-09 | TASK-08 | Harden CLI progress, status codes, interruption handling and diagnostics; verify no network, source mutation or executable log content. | A059, A060, A061, A068, A069, A070, A081 |
| TASK-10 | TASK-09 | Execute independent frozen acceptance, negative controls, no-mock unit tests and early full-scope line gate; investigate failing fixture semantics. | A072, A073, A074, A075, A076, A077, A078, A079, A080, A081, A082 |
| TASK-11 | TASK-10 | After early coverage PASS, run Hypothesis/stateful/differential/falsification/mutation/Lean scope and independent evaluation on real labeled samples. | A072, A083, A084, A090, A091, A092, A093 |
| TASK-12 | TASK-10 | Benchmark busy-weekend representative size and scaling with peak RSS, disclose no universal throughput target and known detection limits. | A083, A084, A085, A086 |
| TASK-13 | TASK-11,TASK-12 | Build clean offline-capable wheel installation, verify exact artifact behavior and docs, record file and source identity, prepare separate independent recheck. | A087, A088, A089, A092, A094 |

## Dependency gates and repair policy
For each TASK: implement minimal correct production behavior with meaningful `unittest` assertions, use concrete seam instances instead of mocking, execute coverage gate on all first-party Python roots and obtain 100% executable line coverage. Record branch coverage and review; do not set universal 100% branch. If tests fail, repair application and **re-run** first-party coverage evidence before proceeding. Do not edit the frozen oracles. Unit test isolated parser and matchers alongside real gzip/filesystem integration, no fixture-only false pass. The executable coverage gate ships with the ZIP rather than depending on an oral instruction.

## Phased release
**Foundations:** TASK-01 through -03 (strict config, streaming, parsing). **Core classification:** -04 through -06 (auth, regex and provenance). **Aggregation/outputs:** -07 through -09 (clusters/report/CLI). **Coverage-first then assurance:** -10 and -11, plus -12 performance. **Packaging and clean validation:** -13. Dependency conflict or false PASS is a hard stop; human does not need to approve each ordinary task. Final Codex artifact cannot be certified by this pre-Codex host.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
