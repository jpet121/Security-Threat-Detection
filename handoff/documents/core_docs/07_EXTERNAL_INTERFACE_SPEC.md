# 07 — External interface (local CLI only)

## CLI and examples
Recommended v1 entry: `python -m security_log_auditor --input ./incident-evidence --rules ./rules/default.toml --output ./audit-results` with repeatable `--input` and optional `--from`, `--to` ISO timestamp filters and explicit `--timezone` for formats lacking an offset. The compiled XML contains a *non-normative* `auditor.py --rules rules.yaml` illustration (P067); preserve the source intent of selecting rules/inputs/window/output without pretending YAML was mandated. Document the final command and add `--help` smoke test. A single command from an unfamiliar supported bundle must work locally.

## File/config interface
`rules/default.toml`: local, versioned documented readable config; per rule ID/name, applicable source format/field, predicate/regex, enabled, severity; independent adjustable group thresholds/window and per-operation resource bounds. `tomllib` reads; supply a pin for third-party `regex` timeout with local wheel/venv setup. No auto-fetch during an audit. Missing flags, unsupported format, wrong timezone, invalid regex or malformed TOML produce actionable diagnostics *before* consuming evidence where possible.

## Return status design
Suggested exit integers (not XML-prescribed): `0` fully complete, `2` complete with nonfatal interpretation warnings, `3` incomplete/failed due unreadable/corrupt/interrupted evidence, `64` input/config usage failure. This is a design decision and must be clearly documented in program `--help` and manifest. No warning class may camouflage an incomplete selected source. Partial result paths must have distinct name/state and be presented prominently. `stdout/stderr` progress must never print raw token, huge log line or unsafe terminal sequence; emit periodic aggregate counters only.

## No external API
No network, agent, cloud log upload, live vulnerability scan, database server or automatic blocking. File access runs under operator OS permissions; no privilege escalation or credentials built into tool. The generated report is an offline investigation aid. Support Python 3.12+ Linux, documented locale/timezone, explicit dependency install and unsupported log-layout diagnostics.

## Compatibility and resources
Boundary tests: missing input, unreadable directory, duplicate names, zero-byte file, gzip corruption, oversized event, malformed percent encoding, timezone absence, custom rule disabled, repeated runs and concurrent same-output invocations. No silent field loss. Use versioned schemas to preserve machine-readable downstream consumers.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
