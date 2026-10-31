# Feasibility / proportionality — BUILD, HIGH ASSURANCE

## Alternatives and decision
**BUILD (small offline CLI), HIGH-ASSURANCE methods** are warranted. Ordinary grep or SIEM query can provide rough search but fails the combined project needs for configurable contextual predicates, original line provenance, unreadable-source accounting, reproducible physical hashes, portable offline processing and transparent redacted machine+human report output. Full streaming-SIEM/server deployment increases security surface and is explicitly unnecessary in first release (P071).

## Feasibility evidence and dependencies
Python >=3.12 streaming raw/gzip sources, TOML parsing and SQLite temp staging are available for a small codebase. The hostile custom regex requirement warrants a vetted `regex` timeout-enabled dependency and explicit offline wheel provisioning; the caller's local audit requires no network. Exact memory limits, elapsed-time targets and detection accuracy goals are not in the XML; implement configurable controls and measure on representative corpus, do not fabricate SLAs. Source format variants, sanitization and analyst-labeled data require future evaluation and can be deferred until final acceptance without blocking safe preparation (P072–P086).

## Cost/risk and reduction
Complexity: mixed parser grammars, missing timestamps, multiline records, encoded payload interpretation and redaction. Reduce risk by pure classifier seams, frozen positive/benign neighbors and bounded matched fields; avoid live services, cloud dependence and auto-response. A versioned local rule schema and on-disk temporary aggregation keep cost proportionate. A failed coverage gate, unchanged hash validation or audited meaning requires repair, not a reduced threshold.

## Kill / reconsider criteria
Stop production release if output can modify source evidence, skip unreadable inputs yet signal completeness, execute log content, expose secrets, or hang on hostile regex. Reconsider parser support if no real-format client corpus validates source semantics. Owner approval is reserved; current state is pre-Codex design review only.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
