# Security log triage

Run state: **complete**

Records examined: 12; unique matched events: 8; rule matches: 8; manual review: 0.

Findings are investigation leads. Suspected injection does not establish execution. Shared addresses or temporal proximity do not establish identity or causality.

Unknown times appear last in findings.jsonl and are excluded from precise windows. Duplicate records retain separate file/line identities. clusters.jsonl records rolling windows anchored on each timed authentication event; overlapping windows are not independent incidents.

## Leading failed-login source addresses

- 198&#46;51&#46;100&#46;7: 6

## Targeted accounts

- organizer: 5
- manager42: 1

## Suspected injection endpoints

- &#47;diagnostics: 2

## Accounts per origin

- 198&#46;51&#46;100&#46;7: 2

## Time distribution (UTC hour; null = undated)

- 2026&#45;10&#45;17T02: 8

## Source systems

- unavailable: 2
- edge&#45;a: 2
- edge&#45;b: 2
- app&#45;a: 1
- edge&#45;c: 1

## Limitations

Only documented source layouts and configured signatures are recognized. Unclassified/manual-review records require inspection at their original citations. Unknown timestamps are not invented. No comprehensive injection detection or attribution is claimed. Key-aware redaction cannot identify arbitrary unlabeled secrets; treat all reports as confidential. Source inventory and diagnostics are in manifest.json.
