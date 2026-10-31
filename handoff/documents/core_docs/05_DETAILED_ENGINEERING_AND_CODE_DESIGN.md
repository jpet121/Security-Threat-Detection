# 05 — Detailed Python engineering design

## Proposed source tree and first-party coverage roots
```
src/security_log_auditor/(__init__,__main__,cli,model,config,inputs,stream,parsing,timestamps,
  auth,normalization,rules,injection,findings,redaction,clusters,timeline,reports,manifest,runner).py
rules/default.toml
benchmarks/measure.py; tests/test_*.py; docs/; pyproject.toml
```
The actual source roots must be discovered and explicitly declared to `codex/tools/coverage_gate.py`; cover **all first-party executable application modules and CLI entry points** and separately report executable benchmark/tools modules if shipped. No hidden exclusions, package-name-only tricks, or measurement scope narrowed to files reached by tests. No universal 100% branch threshold: measure branch and review uncovered edges. Relevant source paths proposed; Codex may add modules only after updating source-scope inventory and coverage.

## Types and interfaces
`EvidenceFile(path, selection_index, raw_sha256|None, read_status, format|unknown, error_code|None)`. `ParsedEvent(source_id, line_start, line_end, raw_timestamp|None, instant|None, timestamp_confidence, format_id, fields, raw_bytes_ref)`. `Rule(id, version, applicable_formats, field_selectors, pattern, enabled, priority, description, limits)`. `RuleHit(event_id, rule_id, config_sha256, class, reason, excerpt_redacted)`. `RunManifest(start,end,source_inventory,parser_counts,unique_finding_count,rule_match_count, status, outputs)`. Data classes should be immutable / validated across boundaries; keep raw secrets out of repr/logging.

## Critical algorithms
1. Validate local rules, configured format selectors, output path, regex syntax and safe timeouts before source reads. 2. Enumerate selected sources deterministically (stable relative path + selection ordinal), refusing unrequested escape via symlink. 3. Stream raw physical bytes with fixed-size read and SHA-256; gzip decode incrementally with limits; detect malformed/truncated archive after final CRC. 4. Record physical line boundaries even when a multiline console message groups lines; preserve file/line and original raw timestamp. 5. Apply format-specific field-aware auth conditions and injection predicate with bounded normalization; capture *all* matched rules. 6. Spill event tuples to local staging DB for time sorting/window queries; no unconstrained in-memory list. 7. Generate redacted outputs, exact counts and manifest; prove input bytes not mutated by before/after SHA checks.

## Seams and deliberately simple tests
Real `LocalEvidenceReader` and concrete `BytesEvidenceReader`; `SystemClock` and fixed concrete clock; `FilesystemWriter` and concrete constrained writer; `TimedRegexMatcher` and a concrete deterministic matcher used only to test error propagation, never to substitute for real regex integration. These are explicit constructor/function parameters, not mock frameworks or monkeypatches. Each production path has normal, error and boundary assertions. Test exact included behavior instead of testing only code import or CLI `--help`.

## Threat/performance controls
Specify size ceilings in versioned config: per-line/event, decoded field, percent-decode depth, compressed-file expansion count, temp disk and regex match seconds. A nonconforming input must be represented in evidence accounting; never silently truncate then present a misleading definitive negative. Source hash is over original compressed bytes for gzip; decompressed logical contents are parsed but are not the physical evidence SHA. Stable sorting key: known UTC instant then source selection/line, with unknown-time events separated; replay is deterministic. Do not execute any logged shell fragment or string interpolate into a shell invocation.

## Error contracts
Invalid config is an early fatal validation. Permission failure/corrupt gzip yields incomplete status, source inventory entry, and no misleading complete marker. Parser rejection yields counted unclassified source record. A timed out regex yields explicit manual review and resource warning. Output failure prevents finalized status; use a stage directory with retained, conspicuously partial evidence if safe. Interrupted run returns non-success. Exit integers are documented proposed CLI details, not compelled by source.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
