# 01 — Project charter and scope | Security Threat Detection — Security Log Regex Auditor

## Purpose and outcome
Build an offline, reproducible Linux investigator command-line tool that converts heterogeneous event-platform evidence to explainable failed-login and suspected-shell-injection **leads**, not verdicts of compromise. The motivating case concerns account lockouts and unusual HTTP requests on a high-traffic event weekend; the relationship remains unknown (P001–P004, P097–P098). A human analyst interprets findings and decides response.

## Users and operating model
Primary: incident-response analysts holding selected, authorized original evidence on a local investigation host. Inputs: one/multiple selected files or a directory of SSH/syslog, Apache/Nginx access, configurable console export, plain text and gzip. Process in bounded RAM; preserve original bytes and SHA-256. Outputs: per-run classified JSONL, redacted Markdown report (optional CSV), machine manifest and explicit incomplete/run states (P005–P013, P047–P064).

## Scope / exclusions
Include source-aware auth/injection rules, local rules with versions, configurable clustering thresholds, relevant original citations, timeline with unknown-clock notation, manual-review accounting, offline installation documentation, synthetic tests and performance benchmarks (P014–P094). Do not block IPs, notify live services, deploy agents, scan networks, execute logged commands, claim exploitation, or establish incident closure. No mandatory dashboard, alerting system, persistent server DB or network access in v1 (P031, P046, P060–P061, P071, P095–P096).

## Hard constraints and critical failures
An unreadable selected file, corrupt stream or interrupted run cannot be represented as a complete audit. A generic HTTP 401 does not establish login failure. A lone metacharacter does not establish shell injection. Missing or offsetless timestamps cannot be manufactured. Secrets must not appear in ordinary reports. Evidence remains unchanged. Every record, including unclassified material, must be accounted for (P011–P016, P026–P034, P057–P064).

## Decision authority and completion
Compiler XML is normative; implementation defaults such as TOML format, limits and exit-code numbers are explicitly design choices (DD-01–06). Changes that alter meaning require owner decision rather than silent scope expansion. Codex implementation completion requires real executable tests, complete 100% first-party line coverage and reviewed branch data, advanced assurance, labeled analyst data, busy-weekend benchmark and external independent verification. Pre-Codex ZIP approval **does not** grant final release. Product accepted only by authorized human after evaluated evidence (P072, P083–P094).

## Failure / stop conditions
Stop or hold if required source preservation fails, a selected source goes missing, a prior output is silently appended, unsafe regexes can cause unbounded processing, confidential information leaks, timestamp gaps produce false chronology, or normative requirements are weakened. Retain partial evidence with explicit failed/incomplete status. No invented service outage or breach assertion.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
