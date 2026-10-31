# Security Threat Detection

An offline Linux CLI that turns SSH, reverse-proxy access, and application console logs into reviewable authentication-failure and suspected shell-injection leads. Python 3.12+; no service, network connection, or database server is used during an audit.

## Install and run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m security_log_auditor --input examples/logs --rules rules/default.toml --output /tmp/security-audit-example
```

Choose a **new output directory outside the input tree** on every invocation. Repeat `--input` for multiple files or select a directory recursively. Plain text and gzip are supported. A packaged default rule file is used when `--rules` is omitted.

For an incident window:

```bash
security-log-auditor --input /path/to/local-evidence --output /path/to/new-results \
  --rules rules/default.toml --from 2026-10-17T00:00:00Z --to 2026-10-19T23:59:59Z
```

For yearless syslog, supply both `--syslog-year 2026` and `--timezone America/Chicago` only when justified by the collection. Missing offsets/years remain unknown otherwise. Ambiguous or nonexistent local DST times remain unknown. Unknown times are retained last, and excluded from precise window grouping; time filters retain unknown-time findings for separate review.

## Results

- `findings.jsonl`: one finding per selected source record, all matching classes in `classifications`, all individually versioned rule hits, original file SHA-256 and line range. `classification` is the first alphabetically sorted class for compatibility; consumers must use `classifications` for dual-class records.
- `clusters.jsonl`: repeated-account, distinct-account spray, cross-server burst and temporal-proximity candidates. Windows overlap and do not count independent incidents. The anchor, window and membership predicate identify members in findings.
- `manual_review.jsonl`: source/line citations and reasons for malformed, unsupported or bounded-out records.
- `summary.md`: readable counts, sources, targeted accounts/endpoints and time distribution.
- `manifest.json`: all selected sources, physical hashes (compressed bytes for gzip), parser counts, exact rule hash, settings, artifact hashes and completion state.

Exit codes: **0** complete, **2** completed with interpretation warnings, **3** incomplete, **64** invalid input/configuration. Argparse usage errors such as missing required flags return **2** and print usage without creating results. A finding itself does not change the exit code. Incomplete results remain in a conspicuous sibling `*.partial-*` directory, never the requested final directory. Inspect errors and rerun into a new directory; no resume/append operation is implemented.

See [supported formats and operation](docs/OPERATIONS.md), [rule configuration](docs/RULES.md), [validation and remaining acceptance work](docs/VALIDATION.md), and the [sample report](examples/sample-report/summary.md).

## Development

```bash
. .venv/bin/activate
python -m pip install coverage hypothesis build setuptools wheel
python -m unittest discover -s tests -v
python handoff/codex/tools/coverage_gate.py --root . --source src/security_log_auditor --tests tests --json-out evidence/coverage_first.json
python -m build --no-isolation
bash tools/benchmark.sh
```

The original uploaded handoff is preserved under `handoff/`; the source XML and frozen test copies are unchanged. Historical preparation reports inside that directory describe the uploaded package, not current implementation results. Current evidence lives in `evidence/`. This implementation is an investigation aid; customer-data acceptance and human production approval remain outstanding.

For the included CPython 3.12 Linux x86-64 runtime wheel cache, an offline install is also possible after building or extracting the supplied application wheel:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --find-links vendor/wheels dist/security_log_auditor-0.1.0-py3-none-any.whl
```

Other Python/platform combinations need their matching `regex` wheel obtained during a trusted connected installation. Nothing is fetched during auditing.
