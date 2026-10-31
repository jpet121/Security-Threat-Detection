# 02 — Product requirements | mandatory source conservation

## Source requirements and identifiers
Each exact statement below is the compiled contract's native normative content. The Rxxx requirement and Axxx acceptance are recorded independently in the machine-readable `analysis/ENGINEERING_REVIEW.json`; source anchors are preserved there and in `source/REQUIREMENT_INDEX.json`. No product requirements were invented by the PEHAVOS engine.

| Source ID | Modality | Compiled behavior | Frozen oracle |
|---|---|---|---|
| P001 | REQUIRED | For an online ticketing/event-management platform with Linux servers and containers, build a forensic triage tool to turn diverse logs into reliable, reviewable leads about failed logins and suspected shell injection. | A001 |
| P002 | REQUIRED | Support reconstruction of what happened, when, targeted systems, and which actual log records warrant human investigation; do not assume two suspicious activities are related or an attack succeeded. | A002 |
| P003 | REQUIRED | Investigate SSH authentication, reverse-proxy HTTP access and application/container console log evidence with varying formats, timestamps, duplicate lines, truncated/malformed lines. | A003 |
| P004 | PROHIBITED | Do not declare a breach, successful exploitation or compromised system merely from suspicious strings. | A004 |
| P005 | REQUIRED | Accept one input export, multiple individually selected files, or a directory of incident evidence. | A005 |
| P006 | REQUIRED | Support common syslog-style Linux SSH/authentication records. | A006 |
| P007 | REQUIRED | Support Nginx and Apache HTTP access logs in documented supported layouts. | A007 |
| P008 | REQUIRED | Support application or container console exports, with configurable patterns for timestamps and event boundaries. | A008 |
| P009 | REQUIRED | Support plain-text logs and gzip-compressed exports where applicable. | A009 |
| P010 | REQUIRED | Process large collections from several dozen systems without loading all evidence into RAM at once. | A010 |
| P011 | REQUIRED | Explain read/unreadable files, recognized formats, and uninterpretable records. | A011 |
| P012 | REQUIRED | Support documented multiline messages and extra terminal prefixes without inventing missing data. | A012 |
| P013 | REQUIRED | Flag any unreliably parsed record as unclassified and account for it; never silently discard. | A013 |
| P014 | REQUIRED | Identify actual failed SSH logins and actual failed organizer-admin application sign-ins. | A014 |
| P015 | REQUIRED | Distinguish SSH Failed password, explicit application authentication failures and ordinary HTTP 401 responses; a 401 does not automatically establish failed authentication. | A015 |
| P016 | REQUIRED | Base failed-login classification on source format and surrounding fields. | A016 |
| P017 | REQUIRED | Extract source address, account identifier, target service, server and timestamp when present. | A017 |
| P018 | REQUIRED | Mark absent authentication field values as unavailable; never fabricate them. | A018 |
| P019 | REQUIRED | Highlight repeated authentication failures against the same account. | A019 |
| P020 | REQUIRED | Highlight many distinct targeted accounts from one origin (password spraying pattern). | A020 |
| P021 | REQUIRED | Highlight short-window failed-authentication bursts across servers. | A021 |
| P022 | REQUIRED | Make event-count and time-window thresholds configurable without source edits. | A022 |
| P023 | REQUIRED | Keep each individual event available as evidence alongside aggregated pattern summaries. | A023 |
| P024 | REQUIRED | Evaluate HTTP request parameters, headers and application-log fields for suspected hostile input. | A024 |
| P025 | REQUIRED | Use documented configurable regular expressions for suspicious shell command-execution syntax, metacharacter combinations, command substitution and relevant encoded forms. | A025 |
| P026 | REQUIRED | Require field context and the complete rule condition; a lone semicolon, dollar sign or other punctuation must not automatically become a security incident. | A026 |
| P027 | REQUIRED | Attach individually identifiable matching rules and explanations. | A027 |
| P028 | REQUIRED | For supported URL-encoded fields, analyze a carefully normalized copy along with the recorded original. | A028 |
| P029 | REQUIRED | Document bounded normalization; reject/handle ambiguous or excessively nested encoding safely and never overwrite original data. | A029 |
| P030 | REQUIRED | Unless independent execution evidence exists, label matches suspected injection attempts or indicators for review, not proof of execution. | A030 |
| P031 | PROHIBITED | Do not perform exploit testing or vulnerability scanning. | A031 |
| P032 | REQUIRED | For a selected incident window, show relevant events in chronological order and indicate each source. | A032 |
| P033 | REQUIRED | Handle UTC, local and missing-offset timestamps; document assumptions. | A033 |
| P034 | PROHIBITED | Do not manufacture precise times when offsets or usable timestamps are unavailable. | A034 |
| P035 | REQUIRED | Report source IPs with the most failed-login events. | A035 |
| P036 | REQUIRED | Report whether multiple organizer accounts were targeted from a single origin. | A036 |
| P037 | REQUIRED | Show endpoints receiving suspected shell-injection requests. | A037 |
| P038 | REQUIRED | Examine proximity of suspicious HTTP requests to repeated auth failures without claiming causality. | A038 |
| P039 | REQUIRED | Show systems and original source files behind relevant findings. | A039 |
| P040 | REQUIRED | Never equate IP overlap/time proximity with common attacker identity; explain grouping rule and evidence. | A040 |
| P041 | REQUIRED | Human-readable configuration for rule ID, description, applicable source types/fields, regex pattern, enabled status, and severity or review priority. | A041 |
| P042 | REQUIRED | Support tuning, enabling and disabling rules without editing core parsing code. | A042 |
| P043 | REQUIRED | Reject invalid rule configs with actionable explanations before auditing begins. | A043 |
| P044 | REQUIRED | Attribute each match to the exact rule version/configuration used in that run. | A044 |
| P045 | REQUIRED | Treat log text as hostile; use documented validation, input limits, timeouts or equivalent controls against catastrophic regex processing and resource exhaustion. | A045 |
| P046 | PROHIBITED | Never execute commands or other instructions present in input log content. | A046 |
| P047 | REQUIRED | Each finding refers to original source file, determinable line or bounded range, recorded timestamp, extracted fields, matching rule, rationale, and short excerpt. | A047 |
| P048 | REQUIRED | Include SHA-256 checksum for each audited evidence file. | A048 |
| P049 | REQUIRED | Output JSON Lines with every classified failed-login or suspected-injection finding, including provenance and rule information. | A049 |
| P050 | REQUIRED | Produce readable counts, leading sources, targeted accounts/endpoints, time distribution, notable clusters and records needing manual review. | A050 |
| P052 | REQUIRED | Machine-readable manifest records inputs, file hashes, rules configuration version, run start/end, records examined, parse failures, detection counts, tool version and final status. | A052 |
| P053 | REQUIRED | Clearly distinguish unique matched events from total individual rule matches where one event matches several rules. | A053 |
| P054 | REQUIRED | Include source lines/records that could not be classified in run statistics. | A054 |
| P055 | PROHIBITED | Do not silently append earlier incident findings into a new investigation. | A055 |
| P056 | REQUIRED | With same inputs and rule configuration, reproduce substantive findings apart from run-specific metadata. | A056 |
| P057 | PROHIBITED | Do not expose raw credentials, session tokens or other secrets in ordinary report files and console progress. | A057 |
| P058 | REQUIRED | Mask sensitive portions of excerpts while retaining enough detection context for an analyst. | A058 |
| P059 | PROHIBITED | Do not alter or rewrite original input evidence files. | A059 |
| P060 | PROHIBITED | Never upload logs or other incident evidence to external services during auditing. | A060 |
| P061 | PROHIBITED | Do not download new detection rules during an audit. | A061 |
| P062 | REQUIRED | Safely handle untrusted filenames, terminal escape sequences and recorded text in displays/exports. | A062 |
| P063 | REQUIRED | Unreadable files and lost or interrupted processing prevent an audit being reported as fully complete; flag incomplete audit conspicuously. | A063 |
| P064 | REQUIRED | Distinguish partial/interrupted output files from finalized results. | A064 |
| P065 | REQUIRED | Use Python 3.12 or later with a Linux-compatible CLI. | A065 |
| P066 | REQUIRED | Allow operators to choose input, output, rule configuration and optional time window. | A066 |
| P068 | REQUIRED | Provide periodic high-level progress, not an output of every analyzed event. | A068 |
| P069 | REQUIRED | Meaningfully distinguish completed, completed-with-warnings, failed CLI exit codes. | A069 |
| P070 | REQUIRED | Provide clear handling instructions/diagnostics for missing files, permissions, bad rules, corrupt archives and interruptions. | A070 |
| P072 | REQUIRED | Before acceptance, incorporate client-provided sanitized real-format samples and an analyst-annotated investigation set; future evidence is not a precompile blocker. | A072 |
| P073 | REQUIRED | Provide benign and malicious synthetic log examples for tests without requiring customer data. | A073 |
| P074 | REQUIRED | Automated acceptance coverage: Positive failed logons, successful logins and unrelated auth errors. | A074 |
| P075 | REQUIRED | Automated acceptance coverage: Repeated-account attacks and multi-account password spray. | A075 |
| P076 | REQUIRED | Automated acceptance coverage: Suspicious shell strings and harmless punctuation. | A076 |
| P077 | REQUIRED | Automated acceptance coverage: URL encoding, malformed escape sequences and evasion variants. | A077 |
| P078 | REQUIRED | Automated acceptance coverage: Broken/missing timestamps, encodings, multiline console lines, truncated and corrupt gzip logs. | A078 |
| P079 | REQUIRED | Automated acceptance coverage: Invalid/costly regex rules and long attacker-controlled fields. | A079 |
| P080 | REQUIRED | Automated acceptance coverage: Overlapping duplicate exports, ordering across files and unmatched events. | A080 |
| P081 | REQUIRED | Automated acceptance coverage: Permission failures, interruptions, deterministic reruns and preserved source hashes. | A081 |
| P082 | REQUIRED | Automated acceptance coverage: Report redaction, line/range traceability and reproducible rule explanations. | A082 |
| P083 | REQUIRED | Measure false positives and missed cases against labeled test data; report detection performance. | A083 |
| P084 | REQUIRED | Disclose what rules cannot detect; never claim comprehensive detection of every injection attempt. | A084 |
| P085 | REQUIRED | Benchmark bundle comparable to a busy event weekend on standard investigation host, capturing elapsed processing time and peak resident memory. | A085 |
| P086 | REQUIRED | Demonstrate continued operation as log volume grows without merely running out of memory on oversized files. | A086 |
| P087 | REQUIRED | Provide functioning application, source, CLI entry, default/editable regex rules, synthetic logs, automated tests, sample reports, benchmark results, install/operation/troubleshooting docs. | A087 |
| P088 | REQUIRED | Document supported formats, patterns, known limitations, incomplete-result behavior and occasions requiring manual investigation. | A088 |
| P089 | REQUIRED | Acceptance workflow: analyst processes an unfamiliar supported incident bundle via one documented command to obtain reproducible investigation package. | A089 |
| P090 | REQUIRED | Detect labeled failed logins and suspicious injection indicators with disclosed limitations and false positives available for review. | A090 |
| P091 | REQUIRED | Minimize irrelevant alerts with source-aware detection, expose remaining false positives. | A091 |
| P092 | REQUIRED | Finding references/checksums verify every source finding. | A092 |
| P093 | REQUIRED | Patterns and chronological evidence must be defensible. | A093 |
| P094 | REQUIRED | Large audits stay bounded-memory, disclose unreadable material rather than omitting. | A094 |
| P095 | PROHIBITED | Do not characterize unverified indicators as proved compromise. | A095 |

## User workflows / priority
1. Select evidence and local versioned rule file. 2. Validate configuration and safe output path before reading. 3. Stream source bytes and log parsers; keep hashes and line provenance. 4. Apply source-aware auth and context-aware injection tests without executing input. 5. Aggregate temporal leads with explicit windows. 6. Emit classified redacted JSONL, readable Markdown/CSV and manifest. 7. Mark incomplete/warnings without false success. 8. Have an analyst inspect the leads.

## Nonfunctional and risk requirements
Bounded-memory handling is a design hard gate, as are local-only operation, source immutability, source/rule provenance, incomplete semantics and deterministic substantive reruns. Timing/throughput and precision/recall targets are **not numeric** in the source: benchmark and measure against representative labeled/large data, disclose observations and limitations; do not silently invent SLAs. No blocked human decisions in the compiled UserDecisions section.

## Verification and acceptance
A complete source-to-case mapping covers all 92 required/prohibited clauses. Thirty-six frozen scenario families include expected class boundaries and negative neighbors in `tests/FROZEN_SCENARIOS.json`, and future CLI-level tests under `tests/`. The 15+7 ABVOS records and 21-discipline assurance register are preparatory, not executed application evidence. Human approval is reserved.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
