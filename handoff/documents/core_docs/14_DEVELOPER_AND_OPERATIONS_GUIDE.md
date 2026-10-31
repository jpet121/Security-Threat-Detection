# 14 — Developer and analyst operations guide (implementation target)

## Quick start after Codex completion
Create Python 3.12+ venv, install verified local wheel and offline dependency wheels, check version and help. Put incident evidence in a read-only local folder. Copy supplied `rules/default.toml` and version it for an investigation. Invoke `python -m security_log_auditor --input ./incident-evidence --rules ./rules/default.toml --output ./audit-results`, optionally provide time filter and explicit timezone where source clocks lack offsets. Never change original evidence. The command is a **specified future CLI**, not an executable presently delivered with this handoff.

## Reading outputs
Open `manifest.json` first: check completion versus warnings/incomplete, all selected file dispositions, physical SHA-256 and total processed/unclassified. Review `findings.jsonl` by source path and bounded line range and match rules. Use `summary.md` for clusters and timeline but independently verify any suspected injection or related-login claim. A generic 401, lone punctuation, undated source or common origin is not proof of attack. Raw tokens and passwords must not appear in ordinary exported records.

## Troubleshooting and safe behavior
Missing files/permission -> source inventory contains unreadable entry, no full success; obtain authorized filesystem access and rerun in new directory. Corrupt gzip -> report partial, do not guess missing records. Invalid rules -> fail before scan; inspect rule ID/pattern/field version. Regex timeout/oversized line -> explicit review-needed and rule/record counters; tighten safe bounds or ask rule author, not silent bypass. Missing timezone -> raw time retained without trusted ordering; obtain source timezone evidence before asserting chronology. Interruption or disk full -> inspect stage/incomplete report, never resume by appending to a prior finalized run.

## Maintenance and extension
Add new console layout by versioned parser/rule adapter and separate known-good and negative fixtures; ensure complete source/line provenance. Add custom rule field selectors without modifying parsing core. Re-run meaningful `unittest`, entire first-party 100% line gate, branch review, relevant advanced suite and exact return recheck. Keep a precise list of unsupported log formats and evasion limits; perform independent analyst validation on real sanitized samples.

## Known limits
No application binary exists at pre-Codex phase. Reports, performance and real incident sensitivity have not been demonstrated. Source XML does not define numerical thresholds or service-level target. The final operator guide must replace these projected instructions with verified commands and real tested examples.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
