# Validation and acceptance limits

The executable application is implemented and locally validated. This is a development candidate, not human production approval or a claim that every handoff assurance activity has been completed.

## Recorded evidence

- `evidence/coverage_first.json` and `coverage_gate.log`: actual unittest execution under the supplied unmodified coverage gate, all eight application Python modules including the CLI/module entrypoint. No coverage exclusions or mock frameworks. Final line/branch values and test count are recorded in the JSON. Coverage demonstrates execution, not correctness or an independent security review.
- Supplied application oracle tests and fixture-integrity test are unchanged. Added tests cover grouping, physical gzip hashes, corrupt deflate/truncation, limits, nonregular files, symlinks, source mutation, Unicode, unknown/DST times, time filters, disk faults, interrupts and publication collisions. Handwritten failing adapters exercise explicit constructor/function seams; real files, gzip and regex engines are also tested.
- Six Hypothesis tests exercise encoded injection, punctuation negatives, safe display, secret redaction, bounded normalization and escaped-field round trips. Deterministic generation makes failures reproducible. The generators and their invariants are in `tests/test_properties.py` and `tests/test_remediation.py`; no theorem-proving or comprehensive fuzzing claim is made.
- `evidence/mutation.json`: three hand-selected semantic mutations were killed by the tests: disabling matching, disabling credential masking and fabricating missing times. This is a limited negative control, not exhaustive mutation coverage.
- `tests/test_sample_bundle.py` checks 12 hand-labeled synthetic records: 8 true positives, 4 true negatives, 0 false positives, 0 false negatives. Synthetic precision/recall are both 1.0 on this tiny authored set only; this is not a field-accuracy estimate. Other frozen/negative/property cases provide additional checks without a single combined confusion matrix.
- `evidence/benchmark.json`: 40 synthetic hosts at 20,000 and 200,000 records, elapsed/user/system time and per-process peak RSS. Both runs verify processed and finding counts. Dataset generation and measurement are reproducible with `bash tools/benchmark.sh`. This is a scaling demonstration, not a validated busy-weekend workload or capacity certification.
- `evidence/schema-validation.json`: JSON Schema Draft 2020-12 validation of the generated sample manifest and findings. `evidence/build.log` records wheel/sdist creation; `wheel-install.log` records a clean offline wheel install. The wheel's bundled defaults are exercised without relying on the editable source installation.

- `verification/independent-0.1.0/` preserves the supplied review and reproducer unchanged. `evidence/remediation/` records the original failures and the repaired reproducer results. See `docs/REMEDIATION.md`.
- `evidence/dense-benchmark.json` measures 400/1,600/6,400 same-instant authentication failures across 40 sources. This specifically probes dense overlapping windows; quadratic grouping time remains a capacity risk for larger high-density collections. Reproduce with `AUDITOR_BENCH_DENSE=1 bash tools/benchmark.sh`.

## Still outstanding

Customer sanitized real-format samples, an independently analyst-labeled investigation corpus, analyst processing of an unfamiliar bundle, and the actual busy-weekend dataset/standard investigation host are not available. They remain required for full customer acceptance (particularly P072, P083, P085, P089 and P090). No detection performance beyond the disclosed synthetic corpus is inferred.

The supplied independent review of 0.1.0 found DEF-01/02; both regressions are rerun unchanged against 0.1.1. No independent re-certification of the repaired build, third-party assessment, formal Lean proof, exhaustive mutation campaign, power-loss durability proof or production human approval has been performed. The handoff's broad method register is a prospective plan, not a list of completed checks; only the activities above have evidence. Those remaining reviews are not replaced by high coverage. The implementation is intentionally conservative about unknown times, unsupported layouts and partial processing.

## Replay

Install `requirements-dev.txt`, then run the documented unittest and coverage commands from the repository root. Use a new output directory for each audit. Frozen tests compare actual CLI artifacts and source hashes; generated sample paths and run timestamps vary. Final returned archive verification uses the same application source/test bytes. See `IMPLEMENTATION_RECEIPT.json` for artifact hashes and exact limitations.
