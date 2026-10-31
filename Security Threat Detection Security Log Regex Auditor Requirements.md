# Client Request: Security Log Regex Auditor

**Client:** Online Ticketing and Event-Management Platform  
**Project Type:** Security Incident Investigation and Log Forensics  
**Priority:** High — Unexplained Account Lockouts and Suspicious Web Requests

## The Situation We Need to Fix

We operate an online ticketing platform used by event organizers to manage venues, ticket sales, and customer accounts. Our public websites, administrative portal, and supporting services run across several Linux servers and containerized applications.

During a recent high-traffic event weekend, our support team received complaints that several organizer accounts were being locked after repeated unsuccessful sign-in attempts. Around the same time, one of our engineers noticed unusual requests against a public troubleshooting endpoint. Some request parameters contained characters and command-like fragments that do not belong in normal customer traffic.

We do not yet know whether the two activities are related or whether any attack succeeded. The incident-response team needs to establish what happened, when it happened, which systems were targeted, and which log entries justify further investigation.

The evidence is scattered across SSH authentication logs, reverse-proxy access logs, and application console exports. Some are plain files; others are printouts collected from containers and server terminals. They have different timestamp conventions, inconsistent layouts, repeated messages, and occasional truncated or malformed lines. Our security analyst currently searches each export by hand and then copies selected entries into a spreadsheet. This is slow, inconsistent, and difficult to defend when management asks how we know we did not miss something important.

We need a **Security Log Regex Auditor**: a Python tool that can examine substantial server-log exports, identify **failed-login activity** and **possible shell-command injection attempts**, and produce a reliable, reviewable evidence package. We need a tool that helps analysts make decisions, not a tool that declares a breach simply because a suspicious string appeared in a log.

## What We Want the Application to Do

### 1. Accept the Evidence Our Engineers Actually Collect

Our engineers should be able to point the auditor at a single export, several selected files, or a folder containing an incident's evidence. The initial release must support:

- Linux SSH/authentication logs using common syslog-style messages.
- Nginx and Apache HTTP access logs in documented, supported layouts.
- Application or container console exports, using a configurable pattern to locate timestamps and event boundaries.
- Plain-text files and, where applicable, gzip-compressed log exports.

We routinely consolidate logs from several dozen systems for an investigation, so the auditor must work through large collections without needing to open all the evidence in memory at once. The tool should explain which files it could read, which formats it recognized, and which records it could not interpret.

Some messages span multiple lines, and some console printouts include extra terminal prefixes. We expect the auditor to recognize supported variations without guessing at missing information. If a record cannot be parsed reliably, it should be flagged as unclassified rather than silently discarded.

### 2. Find Actual Failed-Authentication Events

We need to detect failed SSH logins as well as failed sign-in attempts against our organizer administration portal. These sources express failure differently; a `Failed password` message, an explicit application authentication failure, and an ordinary HTTP `401` response are not automatically equivalent.

Detection rules should use the source format and surrounding fields to decide whether an event can genuinely be classified as a failed login. The application must extract the source address, account identifier, target service, server, and timestamp when those details exist. It must mark absent information as unavailable rather than fill it in.

Investigators also need a concise view of patterns: repeated failures against one account, many account names tried from the same origin, and bursts across different servers in a short interval. We should be able to adjust the event-count and time-window thresholds without editing application code. The underlying individual events must remain accessible; a summary alone is not sufficient evidence.

### 3. Recognize Suspected Shell-Injection Attempts

The second major concern is hostile input submitted through HTTP request parameters, headers, or application log fields. The auditor should use documented, configurable regular-expression rules to find suspicious command-execution syntax and related indicators, including common shell metacharacter combinations, command-substitution patterns, and relevant encoded forms.

A legitimate customer may search for technical text that contains symbols also used by a shell. We do not want every semicolon or dollar sign reported as a security incident. Detection must consider the field in which a pattern appears and the complete rule condition, not just a single character. Rules must be individually identifiable and explain why they matched.

Where a supported log format contains URL-encoded values, the application should be able to inspect a carefully normalized copy as well as the recorded original. Normalization must be documented, limited, and protected against ambiguous or excessively nested encoding. It must never overwrite or alter the original evidence.

**A suspicious request is not proof that a command executed.** The report must label these findings as suspected injection attempts or indicators requiring review unless there is independent evidence of execution. The application is an evidence triage tool, not an exploit tester or vulnerability scanner.

### 4. Give Analysts a Useful Investigation Timeline

For a selected incident window, the auditor should arrange relevant events chronologically and show where they came from. Our systems may log in UTC, local time, or with no explicit offset. The application must document its timestamp assumptions and avoid manufacturing a precise time when one is unavailable.

We want investigators to be able to answer questions such as:

- Which IP addresses produced the largest concentration of failed logins?
- Were several organizer accounts targeted from the same address?
- Which endpoints received requests flagged as possible command injection?
- Did suspicious web requests occur near repeated authentication failures?
- Which systems and source files contain the original evidence?

Proximity in time or a matching IP address may support investigation, but it must not be presented as proof that two events share the same attacker. Related-event grouping should show the rule and evidence used to establish the relationship.

### 5. Make Regex Rules Maintainable and Safe

Our security team changes detection logic as new cases appear. We need a human-readable rule configuration defining a rule ID, description, applicable log sources or fields, pattern, enabled status, and severity or review priority.

An analyst should be able to enable, disable, or tune a rule without modifying core parsing code. Invalid rules must be rejected with a useful explanation before an audit begins. Each reported match must identify the rule version or configuration used in that run.

Log content is untrusted. A maliciously constructed input must not cause the regex engine to hang indefinitely, consume unbounded resources, or execute anything contained in the log. Please document how pattern validation, input limits, timeouts or equivalent safeguards, and safe handling of suspect text are enforced. The tool must **never execute a command found in a log**.

### 6. Preserve Evidence and Produce Reviewable Results

Each finding must lead us back to the original record. At minimum, capture the source file, line number or bounded line range where determinable, recorded timestamp, extracted fields, matching rule, explanation, and a short evidence excerpt. File-level SHA-256 checksums should be included so we can establish which evidence files were audited.

We want three deliverables from each completed audit:

1. **Findings file:** Machine-readable JSON Lines containing every classified failed-login or suspected-injection finding, with provenance and rule information.
2. **Analyst report:** A readable summary, preferably CSV plus a concise Markdown or HTML report, showing event counts, leading sources, targeted accounts or endpoints, time distribution, noteworthy clusters, and records needing manual review.
3. **Run manifest:** A machine-readable record of the input files, file hashes, configuration version, start and end times, records examined, parse failures, detection counts, tool version, and final run status.

We need counts to be explainable. One log event might match several rules, so the report must clearly distinguish unique matched events from the total number of rule matches. If a source line could not be classified, that fact must appear in the run statistics.

The auditor must not quietly append findings from an old investigation into a new one. A rerun using the same inputs and rule configuration should generate the same substantive findings, aside from run-specific metadata.

### 7. Protect Customer Information and Investigation Integrity

Access logs can contain session tokens, email addresses, cookies, and other private information. Normal reports and console progress messages should not expose raw credentials or secrets. If a snippet contains sensitive values, the report must mask them while keeping enough context to explain the detection. The untouched evidence must remain in the original input file; the auditor should not rewrite source files.

Our incident evidence must stay inside our environment. We do not authorize sending logs to an external service or downloading new detection rules during an audit. The application should treat file names, terminal escape sequences, and recorded text as untrusted data when displaying or exporting them.

A report that omits an unreadable file or loses part of a processing run is not acceptable as a complete investigation. Incomplete audits must be identified conspicuously, and any partial files must be distinguishable from finalized results.

### 8. Be Straightforward for Our Operations Team

We want a command-line application for Python 3.12 or later that can be operated on our Linux investigation hosts. A typical invocation might look like:

```bash
python auditor.py --input ./incident-evidence --rules ./rules.yaml --from 2026-10-17T00:00:00Z --to 2026-10-19T23:59:59Z --output ./audit-results
```

An operator should be able to select input, output, an optional time window, and a rule configuration. The tool should provide periodic progress messages without printing every analyzed log entry. It needs meaningful exit codes for completed, completed-with-warnings, and failed runs, and clear instructions for handling missing files, permission errors, bad rules, corrupted archives, or interrupted processing.

We do not require a dashboard, a database server, an alerting service, or automated blocking of suspicious IP addresses in the first release. The immediate purpose is repeatable **offline investigation** of collected evidence.

### 9. Show Us That the Findings Are Reliable

Before acceptance, we will provide a sanitized sample of the actual log formats, plus an annotated investigation set in which our analysts have identified representative events. The test package should also include synthetic benign and hostile examples so no customer data is required for automated testing.

We expect demonstrated testing of:

- Confirmed failed-logon messages, successful logins, and unrelated authentication errors.
- Repeated attempts against one account and password-spraying patterns against many accounts.
- Suspicious shell-like request input and harmless requests containing similar punctuation.
- URL-encoded input, malformed escapes, and attempts to evade simple pattern matching.
- Broken or missing timestamps, unexpected encodings, multiline console output, truncated files, and corrupted compressed files.
- Invalid or potentially expensive regex configurations and unusually long attacker-controlled fields.
- Duplicate events from overlapping log exports, cross-file ordering, and unmatched events.
- Permission failures, interrupted audits, reruns, and preservation of source-file hashes.
- Report redaction, line-level traceability, and consistent rule-to-finding explanations.

We need a measurement of detection performance against a labeled dataset, including false positives and missed cases. The development team should disclose what its detection rules do **not** cover rather than claim the tool can identify every injection attempt.

We also expect a benchmark against an investigation bundle comparable to a busy event weekend, recording processing time and peak memory usage on our standard investigation machine. It must remain operable as the amount of log material increases, rather than failing merely because files are too large to load into memory.

## What We Expect to Receive

The final handoff should contain a functioning Python application; its source code; a command-line entry point; default and editable regex-rule definitions; representative synthetic test logs; automated tests; example reports; benchmark measurements; and installation, operating, and troubleshooting documentation.

The documentation should clearly distinguish supported log formats, supported detection patterns, known limitations, incomplete-result behavior, and circumstances that require manual investigation.

## How We Will Decide It Is Successful

We will consider the project successful when an analyst can take an unfamiliar incident evidence bundle from our supported systems, run a single documented command, and receive a reproducible investigation package that:

- Reliably identifies the failed logins and suspected shell-injection indicators present in our labeled acceptance data.
- Reduces irrelevant alerts through source-aware rules and exposes remaining false positives for review.
- Provides enough original-file references and checksums to verify every reported finding.
- Shows meaningful authentication patterns and a defensible time-ordered view of suspicious activity.
- Completes large investigations without running out of memory or silently omitting unreadable material.
- Never treats an unverified indicator as proof that a system was compromised.

**We are not asking the application to stop an attack or declare the incident closed. We need it to turn confusing server printouts into accurate, traceable leads that our security analysts can investigate and explain.**
