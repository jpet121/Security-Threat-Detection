# 0.1.1 remediation of the independent 0.1.0 verification

The original review is preserved unchanged in `verification/independent-0.1.0/`. The original uploaded 0.1.0 ZIP remains unchanged. Version 0.1.1 is a new development candidate; the supplied review's NOT APPROVED judgment is not superseded by a claim of independent re-certification.

## DEF-01: quoted console field truncation

Reproduced the original failure with the unchanged independent reproducer (`evidence/remediation/baseline-regressions.log`). Replaced partial regex extraction with complete token parsing. In quoted values, escaped quote/backslash pairs are decoded into an inspection copy while source bytes, SHA-256 and line citations remain unchanged. Ambiguous quoting, unsupported escapes, duplicate keys and unexplained text following fields reject the whole record into unclassified/manual-review accounting. Empty fields, logger labels, benign documentation strings and supported multiline continuation boundaries have explicit regression tests. A generated quoted-field round-trip property verifies valid supported escape sequences.

The exact reported `note=\"safe\";cat /etc/passwd` field is now retained in full and produces a command-chain suspected-injection finding. The unchanged independent R01 regression passes.

## DEF-02: publication failure under a final-looking directory

Reproduced the original failure with a deterministic second-move fault. All individual artifact moves now occur inside a sibling `.partial-*.publication` directory. The final path appears through one Linux `renameat2(RENAME_NOREPLACE)` directory commit only after every file has moved. Existing files, directories (including empty ones), and symlinks cannot be replaced. Unsupported atomic rename capability or filesystem operations fail incomplete rather than degrading to unsafe publication.

First, middle and last move failures, simulated disk-full, interruption, failed commit, concurrent destination creation, pre-existing destinations and staging-cleanup failures have regression tests. Moved artifacts remain under a partial name; the incomplete root manifest records both `partial_output` and `publication_partial`. If the atomic commit succeeded, failure to remove leftover staging does not invalidate the completed bundle. Atomic visibility does not establish persistence across power loss; there is no fsync durability guarantee.

The unchanged independent R02 regression passes. The supplied reproducer's mover seam is preserved and still exercises actual per-file filesystem operations.

## Additional review decisions

- Genuine SSH public-key failures are included, consistent with the broader authentication-failure requirement. A separate configurable/versioned `ssh.failed-publickey` rule joins the password rule; successful public-key records do not match. Both extract the same provenance/account/address fields. Optional `[preauth]` suffixes are supported. Other method/message/fingerprint layouts remain explicitly outside these default signatures.
- Raw HTTP request-target fragments (`#...`) are anomalous for this access-log layout and now require manual review, instead of silently discarding the fragment. Encoded `%23` input remains eligible for bounded inspection.
- Dense correlation was measured at 400, 1,600 and 6,400 same-instant authentication events across 40 sources. See `evidence/dense-benchmark.json`. Per-anchor SQL window aggregation has potentially quadratic work for dense collections. The benchmark exposes that risk; it is not a customer capacity pass. Use smaller incident windows/collection partitions and capacity review for large dense collections. No customer busy-weekend dataset was supplied.

## Validation and delivery

- `evidence/coverage_first.json`: full 55-test suite under the supplied coverage gate; six actual Hypothesis tests included. Full application scope, no exclusions; line and branch coverage both 100% at the recorded run.
- `evidence/remediation/independent-regressions.log`: the original independent two-test reproducer rerun without edits.
- `evidence/remediation/runtime.json`: unprivileged Linux execution, Python 3.12.14, regex 2026.4.4, Hypothesis and coverage tool versions.
- `evidence/wheel-smoke.json`: clean offline installation and isolated wheel CLI checks, including the escaped-field and raw-fragment regressions.
- `evidence/remediation/` and `IMPLEMENTATION_RECEIPT.json`: current validation evidence and file hashes. Original contract, frozen tests/scenarios, handoff and supplied verification source hashes are preserved.

The GitHub delivery branch contains source, README, this remediation record and `releases/Security-Threat-Detection-0.1.1.zip` with its SHA-256 checksum. Existing `main` and the previous `downloads` branch are not changed. Customer samples, independent analyst labels, unfamiliar-bundle acceptance, representative customer load and human production approval remain outstanding.
