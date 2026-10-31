# 09 — Security, reliability, privacy, safety and performance

## Explicit trust and adversary model
Evidence content (including filename, URI, user-agent, console prefix, percent escapes, gzip payload and timestamps) and user rule patterns are untrusted. An attacker may try regex catastrophic backtracking, compression bombs, memory/disk exhaustion, Unicode decode failures, terminal/HTML/CSV injection, misleading timestamp prefixes, forged log events and leaked credentials. Source file contents are evidence, not commands or authority to change security boundaries. Output readers are analysts and tooling; they must receive escaped/redacted fields only (P045–P062).

## Defensive controls and failure semantics
- Perform safe path selection and read-only original evidence operations; distinguish physical gzip checksum from decoded records. Verify source before/after as feasible, flag mid-read mutation.
- Validate patterns and rule IDs before processing, use bounded field and percent-decoding depth and `regex` per-operation timeouts. Regex timeouts are practical controls, not claims of universal computational safety. On timeouts classify review-needed and keep incomplete detection accounting; ensure attack string never executes.
- Redact credentials, tokens, cookies and secret-bearing headers in every JSONL/CSV/Markdown/stderr/progress path; preserve hashed source provenance. Escape terminal control and spreadsheet formula prefixes; avoid HTML report unless robust encoding is verified. Restrict output permissions and avoid evidence-relative output writes.
- For interrupt, corrupt gzip, inaccessible file, disk full or hash inconsistency, leave explicit partial staging, non-success status, inventory/error record and no complete manifest. No process may silently append previous investigation results.
- Do not call external telemetry, rule updates or network services while auditing. Do not perform active scanning or IP blocking. Do not claim shared IP or temporal proximity proves same actor.

## Memory/performance plan
Iterate physical file chunks and logical event bounds, stream gzip, use disk-backed bounded event windows and emit streaming reports. Make uncompressed byte/event limits and temp-disk guardrails adjustable. A busy-event-weekend comparable corpus and 10x scaled data are required benchmarks on described host with wall-clock and peak RSS. Absolute performance/RAM targets were not stated by the contract; produce measurements and human capacity review rather than fake pass numbers.

## Security verification
Attack-oriented tests: high-entropy secrets in request query; ANSI escapes; CRLF; xlsx formula-like cells; malicious filenames; nested URL encoding; massive HTTP field; backtracking rule; gzip truncation/bomb; directory symlink escape; source mutation, output directory collision, offline execution with denied socket connectivity. Verify reports contain redacted field markers rather than raw tokens; ensure no shell/process APIs are invoked on evidence content. Independent examiner repeats exact released artifacts.

## Source-method references (not application authority)
OWASP Logging Cheat Sheet `https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html` advises protection of secrets and log-injection safety. Python `re` docs `https://docs.python.org/3.12/library/re.html` document regex syntax but no per-call timeout. Third-party `regex` project `https://pypi.org/project/regex/` documents `timeout` support. These references support design rationale, not new customer functional requirements.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
