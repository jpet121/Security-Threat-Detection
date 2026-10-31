# Security Threat Detection
### Security Log Regex Auditor

**AI-Assisted Python Engineering & High-Assurance Software Verification**

> **What it does:** Examines Linux authentication records, web-server access logs, and application console output to identify failed logins and **suspected** shell-injection attempts. It produces traceable findings, groups potentially related events, and keeps uncertain records available for manual review.

**Why I built it:** To demonstrate requirements-driven security tooling, human-directed AI-assisted Python development, defensive parsing, evidence preservation, independent defect discovery, and measurable verification. The goal was to build an investigation aid whose output can be inspected—not a scanner that claims it has proven a breach.

**Under the hood:** Python 3.12+ · regex-based detection · Linux/WSL2 CLI · SSH/syslog, Nginx/Apache, and supported console layouts · TOML detection rules · gzip input · SHA-256 evidence provenance · Hypothesis · coverage.py · fault injection · independent regression tests

**Verification status:** **Development candidate v0.1.1 passed its documented automated technical checks:** 55/55 tests on Python 3.12.14, 100% measured first-party line and branch coverage, and the two original independent defect regressions. Customer-scale detection accuracy, representative dense-event performance, and human production approval remain **open**.

**Names and compatibility:** **Security Threat Detection** is the portfolio-facing title; **Security Log Regex Auditor** is the technical project name. The application package remains `security-log-auditor`; source modules, CLI names, original contract, frozen tests and release archive filenames were not renamed for presentation.

[See an example](#security-threat-detection-in-action) · [Understand the design](#how-it-works) · [Review the testing](#how-the-engineering-was-verified) · [Try it](#try-it-yourself-ubuntu-or-wsl2) · [See limitations](#limitations-and-release-status)

## At a glance

| Question | Answer |
| --- | --- |
| **What did I build?** | An offline command-line log auditor that classifies failed authentication and suspected command-injection indicators, with explainable rules and evidence citations. |
| **What problem does it solve?** | During an investigation, analysts may need to examine log exports from several systems and distinguish meaningful leads from ordinary errors or harmless punctuation. |
| **What skills does it demonstrate?** | Secure parsing, regex rule design, configurable detection, structured outputs, provenance, defensive I/O, test design, fault injection, and evidence-based software assurance. |
| **Can I inspect or run it?** | Yes. The source, synthetic samples, unit/property tests, CLI instructions, and archived v0.1.1 release are included. |
| **Is this an AI threat-detection model?** | No. It is deterministic, rule-based Python software developed using a human-directed AI-assisted engineering workflow. No ML classifier, LLM, or autonomous security agent is claimed. |

## The problem

The starting point was a **online ticketing and event-management incident**, not an actual customer engagement. After a high-traffic event, the operations team discovered repeated account lockouts and suspicious command-like HTTP requests. The immediate need was an offline tool that could analyze mixed SSH, proxy, and application logs while retaining source references and avoiding unsupported claims about attacker identity or successful exploitation.

The [client requirements](Security Threat Detection Security Log Regex Auditor Requirements.md) describe that scenario. The [original compiled contract](source/contract.xml) is retained as the authoritative software requirements baseline.

## Security Threat Detection in action

The bundled `examples/logs/` directory contains SSH, HTTP, and application console records. Here is how the auditor treats representative conditions:

| Log situation | Interpretation | Result |
| --- | --- | --- |
| `sshd` records an explicit failed password authentication | Auth failure, with recorded account/source fields | **Failed-login finding** |
| A web request contains encoded shell-command substitution | Suspicious request syntax, not proof it executed | **Suspected-injection finding** |
| A web server returns HTTP `401` without an explicit authentication-failure event | Response code alone is insufficient | **Not automatically a failed login** |
| Documentation contains command syntax without the configured request-field context | Legitimate text can resemble an attack string | **No automatic injection finding** |
| A malformed record has ambiguous quoting | The parser must not invent missing meaning | **Manual-review accounting** |

A provided [analyst report](examples/sample-report/summary.md) shows how findings and grouped candidates are presented. The 12-record hand-labeled sample produced 8 true positives and 4 true negatives in its authored test, with no errors **on that corpus**.

## How it works

```text
Local log files or directories (plain text / gzip)
                    |
                    v
          Bounded evidence reader
                    |
                    v
   SSH / HTTP / console format parsing
                    |
            +-------+--------+
            |                |
     Parsed record       Uncertain record
            |                |
            v                v
  Context-aware regex     Manual-review
  and authentication      accounting
  classification
            |
            v
 Explainable rule hits + source/line/hash citations
            |
            v
     Time-window correlation candidates
            |
            v
 Findings JSONL + clusters JSONL + summary + manifest
            |
            v
      Safe completed/partial publication
```

The tool supports configurable, versioned rules, bounded URL-decoding, explicit uncertainty, secret masking in ordinary report excerpts, and source SHA-256 checksums. It does not execute commands found in logs, perform vulnerability scans, or upload evidence to an external service during an audit.

The incident correlation output describes potentially related observations, **not proven attacker identity or causation**. Unknown timestamps are not fabricated or silently forced into precise time windows.

Technical details: [operations](docs/OPERATIONS.md) · [rules](docs/RULES.md) · [original defect remediation](docs/REMEDIATION.md).

## Why I built it this way

My focus was to demonstrate more than generating Python code: starting with a written problem, transforming it into explicit requirements, directing AI-assisted implementation, requiring an independent review, addressing reproduced defects, and collecting test evidence on an exact Python runtime.

**My role:** Define the project and its acceptance boundaries, direct the AI-assisted engineering workflow, request independent adversarial verification, authorize defect remediation, execute the additional Ubuntu replay, and retain human authority over release decisions. AI tools contributed to implementation and verification artifacts.

## How the engineering was verified

The original independent review identified two defects in **v0.1.0**, and the **v0.1.1** candidate addressed them. The separate exact-runtime replay ran on Ubuntu with Python **3.12.14**. The returned logs and source hashes were then reviewed for consistency.

| Verification | Tested scope | Recorded result |
| --- | --- | --- |
| **Complete automated test suite** | Core behavior, frozen acceptance tests, property tests, remediation, synthetic corpus | **55/55 passed** |
| **Line coverage** | Eight first-party Python modules, 599 executable statements | **100%** measured |
| **Branch coverage** | First-party code in the recorded coverage run | **100%** measured; review-only rather than a universal certification gate |
| **Hypothesis** | Encoded requests, punctuation negatives, redaction, normalization, escaped-field round trips | Six property-based tests within the 55-test run |
| **Original independent regression tests** | Escaped console field; failed output publication | **2/2 passed** unchanged |
| **Artifact preservation** | Original XML and frozen test baseline | Exact hashes verified |
| **Packaged installation** | Wheel installation and isolated CLI smoke tests | Passed in recorded evidence |
| **Mutation checks** | Three deliberately altered behaviors | All three selected mutations detected in developer evidence; not a comprehensive mutation score |
| **Synthetic evaluation** | 12 labeled example records | 8 TP / 4 TN on authored examples only |

**What the evidence means:** The exact-runtime tests were executed on a user-controlled Ubuntu machine; the returned evidence ZIP was independently checked for structural integrity, matching SHA-256 entries, logged test outcomes and source consistency. The evidence reviewer did **not** rerun the entire suite on a separate environment. Full coverage measures code execution within a specified scope—not exhaustive correctness or security certification.

[Read the target-runtime independent evidence review](verification/PEHAVOS_0.1.1_TARGET_RUNTIME_EVIDENCE_REVIEW.md) · [See the target-runtime evidence archive](verification/PEHAVOS_011_TARGET_REPLAY_EVIDENCE.zip) · [Review original remediation](docs/REMEDIATION.md)

### Defects found and corrected

| Issue | What went wrong | What v0.1.1 changed |
| --- | --- | --- |
| **DEF-01 — quoted-field truncation** | A quoted console field with escaped characters could hide a suspicious command indicator from inspection. | Complete token parsing now retains the relevant inspection text; ambiguous records go to manual review. |
| **DEF-02 — incomplete output publication** | A simulated filesystem failure could leave a partially populated directory at a final-looking path. | Staging and an atomic Linux directory commit keep incomplete artifacts distinguishable from completed output. |

Both original independent reproducers were preserved and passed against the corrected candidate. The atomic publication strategy does **not** claim durability after sudden power loss.

## Measured performance and limits

Developer-recorded **synthetic** measurements on Linux across 40 hosts:

| Workload | Records | Elapsed time | Peak process RSS | Result |
| --- | ---: | ---: | ---: | --- |
| Mixed synthetic logs | 20,000 | 1.23 s | 18.0 MiB | Complete |
| Mixed synthetic logs | 200,000 | 12.54 s | 23.6 MiB | Complete |
| Dense same-instant auth failures | 400 | 0.18 s | 18.4 MiB | Complete |
| Dense same-instant auth failures | 1,600 | 1.14 s | 22.8 MiB | Complete |
| Dense same-instant auth failures | 6,400 | 13.58 s | 23.4 MiB | Complete |

Dense, overlapping correlation windows show substantially non-linear growth. A later independent environment also recorded approximately 28 seconds for 6,400 dense events. Large real incident collections require an explicitly agreed operating envelope and more acceptance testing.

Source data: [mixed benchmark](evidence/benchmark.json) · [dense benchmark](evidence/dense-benchmark.json).

## Try it yourself (Ubuntu or WSL2)

From the repository root (which contains `pyproject.toml` and `src/`) on a compatible Linux filesystem:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m security_log_auditor \
  --input examples/logs \
  --rules rules/default.toml \
  --output /tmp/security-audit-example
```

Use an **unused output directory outside the input tree**. See `docs/OPERATIONS.md` for supported layouts, timestamp options, filesystem requirements and exit-code interpretation. The tool uses Linux `renameat2(RENAME_NOREPLACE)` for safe final publication; not every filesystem or platform supports this operation. Package installation may require a matching `regex` wheel. Offline CPython 3.12 Linux x86-64 wheels are included in the release.

Inspect `findings.jsonl`, `clusters.jsonl`, `manual_review.jsonl`, `summary.md`, and `manifest.json` in the output directory. Findings signal **investigation leads** and do not prove a system was compromised.

For development tests, install `requirements-dev.txt`, run `python -m unittest discover -s tests -v`, then follow the supplied coverage gate in `handoff/codex/tools/coverage_gate.py`.

The original packaged distribution is retained at [Security-Threat-Detection-0.1.1.zip](releases/Security-Threat-Detection-0.1.1.zip); its contents and filename have not been changed.

## Requirements, evidence, and release status

| Resource | Purpose |
| --- | --- |
| [Client requirements](PROJECT_REQUIREMENTS.md) | Standalone simulated incident scenario and client acceptance needs. |
| [Compiled application contract](source/contract.xml) | Authoritative requirements baseline. |
| [Current technical validation](docs/VALIDATION.md) | Implemented verification, limits, and remaining customer acceptance. |
| [Original independent defects and corrections](docs/REMEDIATION.md) | DEF-01 and DEF-02 original failure and fix history. |
| [Target-runtime evidence review](verification/PEHAVOS_0.1.1_TARGET_RUNTIME_EVIDENCE_REVIEW.md) | Integrity checks and gate dispositions. |
| [Full logged replay archive](verification/PEHAVOS_011_TARGET_REPLAY_EVIDENCE.zip) | 55-test logs, coverage results, dependencies, and unchanged regressions. |
| [Release archive](releases/Security-Threat-Detection-0.1.1.zip) | Original developer-distributed v0.1.1 artifact. |

### Limitations and release status

- The business scenario and example logs are **synthetic**. No customer data or independently analyst-labeled incident corpus was evaluated.
- Accuracy on a 12-record authored test is **not** a real-world detection precision/recall claim; unknown threats and evasions can be missed.
- The tool is designed for offline **triage**, not active exploit testing, definitive compromise identification, or attacker attribution.
- Dense event correlation has a documented performance scaling risk; representative customer throughput and memory targets have not been accepted.
- Some text layouts, timestamps, secret formats, and filesystem behaviors remain deliberately unsupported or conservatively handled.
- Technical automated verification has passed within the stated scope; **customer acceptance, production authorization, and third-party security certification have not been granted**.

---

**Focus:** Defensible security software engineering, evidence preservation, testable requirements, explicit uncertainty, independent verification, and accountable human decisions when AI helps build the software.
