# 04 — Technical architecture | offline, source-preserving

## Architecture diagram (data and control)
```
CLI/config validation -> immutable selected-source inventory -> bounded physical file stream/hash
                     -> format-specific parsers -> timestamp/provenance record
                     -> auth classifier + contextual injection matcher
                     -> bounded disk-backed aggregator/timeline
                     -> redacted staged JSONL / report / manifest
                     -> finalize only with truthful completion status
```
The core depends on typed source/event/rule abstractions; the CLI and adapters depend on core, not vice versa. The same engine parses SSH/syslog, Nginx/Apache common/combined and configured console boundaries; unsupported layouts are accounted for, not guessed.

## Architectural decisions
A1: Explicit local reader abstraction `FileSource` and `FileStream` offers read-only file access, reproducible checksum evidence and real integration seams. A2: Stateless parser registry and classifiers permit independent source-derived oracles (SSH failure vs HTTP 401). A3: Read-only TOML configuration (`tomllib`) plus a pinned `regex` matching dependency with operation timeout, bounded input and normalization; Python stdlib `re` has no built-in operation timeout, so `re` alone is insufficient for arbitrary untrusted rule predicates. A4: SQLite local temporary keyed records/window spill avoids all-input RAM retention; no production DB or network needed. A5: All reports written to dedicated staged output and finalized atomically with manifest; any interruption creates partial/incomplete artifacts. A6: Store original source byte hashes and offsets; never rewrite originals, never include raw secret values in public exports.

## Alternatives rejected
Regex-only line grep loses format semantics, multiplies false positives and misses original event boundaries. Bulk loading into pandas is not memory bounded. A service/web dashboard violates first-release local scope and adds an attack surface. Content-only dedup loses separate evidence provenance. Relying exclusively on `re` plus a wall clock without per-match interruption is unsafe under hostile rules. Use controlled dependency pinning and an offline install procedure, not runtime downloads.

## Contract interfaces
`inputs.enumerate`, `stream.iter_bounded`, `parsing.parse_records`, `auth.classify`, `injection.inspect`, `clusters.consume`, `reports.stage/finalize` all accept explicit typed dependencies: abstract local clock, source enumeration, pattern matcher and output sink. Tests inject concrete in-memory streams/clocks/failing sinks via constructors; `unittest.mock`, `patch`, `MagicMock`, pytest monkeypatch and analogous runtime monkeypatching are prohibited. All first-party `.py` modules in `src/security_log_auditor` including `__main__.py` and CLI included in line coverage.

## Trust boundaries and failure propagation
External evidence/rules are hostile; source metadata is verified before/after read; decompression expansion has bounded resource policy; normalized inspection text never replaces original. A matcher timeout does not turn input into a confirmed negative—record a review-needed condition. Writer failure or unreadable source propagates into incomplete/failed status and prevents normal finalization. Operators may choose time and rule files but cannot authorize code execution via log text. Standalone CLI artifacts remain fully local.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
