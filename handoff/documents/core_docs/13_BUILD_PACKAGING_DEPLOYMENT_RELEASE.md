# 13 — Build, packaging, distribution and release contract

## Environment and installation
Target Python >=3.12 on Linux. Source distribution and wheel should include CLI, `rules/default.toml`, synthetic fixtures, operator instructions and versioned machine-readable schemas. Pin `regex` dependency that provides per-operation timeout; verify version, wheel provenance, hashes, local architecture compatibility, and document how to stage dependencies offline before auditing. Do not fetch anything during an incident scan. `tomllib` reads TOML without requiring a YAML parser. Use clean venv and explicitly verified build tooling, not hidden installer side effects.

## Build and identity
Reproducible dependencies and source/test lock hashes must be emitted. Build wheel and source tarball or ZIP; verify source file completeness, artifact manifest integrity, fresh-install CLI smoke and actual supported mixed evidence processing, then compare hash of unmodified original evidence before/after. Stage output in new per-run directory, not an old results append. Both successful report and incomplete report include verified status and source inventory; the latter cannot be passed off as success.

## Required evidence to return
Exact final code ZIP SHA-256, file manifest with hashes; `coverage_first.json` plus full report including all first-party roots, 100% executable statement coverage, measured reviewed branch coverage, explicit no-mock scan result; ordinary unit/integration/end-to-end/fuzz/mutation/Lean-domain/fault/security evidence per 21-discipline applicability; clean Linux wheel install and replay; benchmark with elapsed time, peak RSS, workload size and machine description; labeled real-format analyst confusion matrix when data is supplied. Record all failures, skips and environment limitations, not a single unsupported percentage.

## Release gates and reserved authority
Pre-Codex archive verification confirms **handoff structural integrity**, not working code. Codex return must be independently inspected and re-executed from exact final bytes with code-execution authorization; separate Auditor evaluates negative behaviors and semantic assumptions. Do not call the product production-ready before high-assurance evidence, client-labeled evaluation, actual benchmark, security/no-network checks and human owner approval. Human approval remains NOT_GRANTED at this checkpoint.

## Rollback and compatibility
Never overwrite original evidence; protect existing audit-results directories from silent append/reuse. Failed run preserves error and partial-status evidence; code package rollback reverts binary/rule config versions together and records original version and source hash. Schema changes require explicit version increment and regression of consuming report tools.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
