"""Disk-backed evidence ordering, counts and window membership."""
from datetime import datetime, timedelta
import json
import html
from pathlib import Path
import sqlite3
from hashlib import sha256
from .safety import safe, fingerprint


class Store:
    def __init__(self, path, disk_bytes):
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA temp_store=FILE')
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.execute(f'PRAGMA max_page_count={max(1, disk_bytes // 4096)}')
        self.db.execute('CREATE TABLE events (id TEXT, instant TEXT, source TEXT, line INTEGER, class TEXT, ip TEXT, account TEXT, server TEXT, endpoint TEXT, payload TEXT)')
        self.db.execute('CREATE INDEX timeline ON events(class,instant,source,line)')
        self.db.execute('CREATE INDEX by_account ON events(class,account,instant)')
        self.db.execute('CREATE INDEX by_ip ON events(class,ip,instant)')

    def add(self, event):
        f = event['fields_redacted']
        for classification in event['classifications']:
            self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)',
                            (event['finding_id'], event['utc_instant'], event['source_id'], event['line_start'],
                             classification, f.get('ip'), f.get('account'), f.get('server'), f.get('endpoint'),
                             json.dumps(event, ensure_ascii=True)))

    def groups(self, config):
        window = config.groups['window_seconds']
        # Rolling anchor windows, disk queries return bounded scalar aggregates.
        for ident, instant, ip, account in self.db.execute("SELECT id,instant,ip,account FROM events WHERE class='failed_authentication' AND instant IS NOT NULL ORDER BY instant,source,line"):
            dt = datetime.fromisoformat(instant.replace('Z', '+00:00'))
            end = (dt + timedelta(seconds=window)).isoformat(timespec='microseconds').replace('+00:00', 'Z')
            begin = (dt - timedelta(seconds=window)).isoformat(timespec='microseconds').replace('+00:00', 'Z')
            condition = "class='failed_authentication' AND instant>=? AND instant<=?"
            params = (instant, end)
            for kind, extra, extra_params, threshold, count_expr in [
                ('repeated_account', ' AND account=?', (account,), config.groups['repeat_count'], 'COUNT(*)'),
                ('password_spray', ' AND ip=?', (ip,), config.groups['spray_accounts'], 'COUNT(DISTINCT account)'),
                ('cross_server_burst', '', (), config.groups['burst_count'], 'COUNT(*)')]:
                count, servers = self.db.execute(f'SELECT {count_expr},COUNT(DISTINCT server) FROM events WHERE {condition}{extra}', params + extra_params).fetchone()
                valid = (kind != 'repeated_account' or account is not None) and (kind != 'password_spray' or ip is not None)
                if valid and count >= threshold and (kind != 'cross_server_burst' or servers > 1):
                    yield {'kind': kind, 'anchor_finding': ident, 'start': instant, 'window_seconds': window,
                           'count': count, 'count_semantics': 'distinct_accounts' if kind == 'password_spray' else 'events',
                           'membership': {'account': account} if kind == 'repeated_account' else {'ip': ip} if kind == 'password_spray' else {},
                           'interpretation': 'candidate grouping only; no shared identity or causality established'}
            near = self.db.execute("SELECT COUNT(*) FROM events WHERE class='suspected_injection' AND instant>=? AND instant<=?", (begin, end)).fetchone()[0]
            if near:
                yield {'kind': 'temporal_proximity', 'anchor_finding': ident, 'window_seconds': window,
                       'nearby_injection_events': near, 'interpretation': 'proximity only; no causality established'}

    def write(self, output, manifest, config):
        def emit(name, values):
            with (output / name).open('x', encoding='utf-8') as stream:
                for value in values:
                    stream.write(json.dumps(safe(value), ensure_ascii=True, sort_keys=True) + '\n')
                    if stream.tell() > config.limits['disk_bytes']:
                        raise OSError('report disk limit exceeded')
        emit('findings.jsonl', (json.loads(row[0]) for row in self.db.execute('SELECT payload FROM events GROUP BY id ORDER BY instant IS NULL,instant,source,line')))
        emit('clusters.jsonl', self.groups(config))
        with (output / 'summary.md').open('x', encoding='utf-8') as report:
            report.write('# Security log triage\n\n')
            report.write(f"Run state: **{manifest['run_state']}**\n\nRecords examined: {manifest['records_examined']}; unique matched events: {manifest['unique_matched_events']}; rule matches: {manifest['total_rule_matches']}; manual review: {manifest['manual_review_records']}.\n\n")
            report.write('Findings are investigation leads. Suspected injection does not establish execution. Shared addresses or temporal proximity do not establish identity or causality.\n\n')
            report.write('Unknown times appear last in findings.jsonl and are excluded from precise windows. Duplicate records retain separate file/line identities. clusters.jsonl records rolling windows anchored on each timed authentication event; overlapping windows are not independent incidents.\n\n')
            for label, query in [
                ('Leading failed-login source addresses', "SELECT ip,COUNT(*) FROM events WHERE class='failed_authentication' GROUP BY ip ORDER BY COUNT(*) DESC,ip LIMIT 20"),
                ('Targeted accounts', "SELECT account,COUNT(*) FROM events WHERE class='failed_authentication' GROUP BY account ORDER BY COUNT(*) DESC,account LIMIT 20"),
                ('Suspected injection endpoints', "SELECT endpoint,COUNT(*) FROM events WHERE class='suspected_injection' GROUP BY endpoint ORDER BY COUNT(*) DESC,endpoint LIMIT 20"),
                ('Accounts per origin', "SELECT ip,COUNT(DISTINCT account) FROM events WHERE class='failed_authentication' GROUP BY ip ORDER BY COUNT(DISTINCT account) DESC,ip LIMIT 20"),
                ('Time distribution (UTC hour; null = undated)', 'SELECT substr(instant,1,13),COUNT(DISTINCT id) FROM events GROUP BY substr(instant,1,13) ORDER BY 1'),
                ('Source systems', 'SELECT server,COUNT(DISTINCT id) FROM events GROUP BY server ORDER BY 2 DESC,server LIMIT 20')]:
                report.write(f'## {label}\n\n')
                for key, count in self.db.execute(query):
                    key = ''.join(c if c.isalnum() or c.isspace() else f'&#{ord(c)};' for c in str(safe(key if key is not None else 'unavailable')))
                    report.write(f'- {key}: {count}\n')
                report.write('\n')
            report.write('## Limitations\n\nOnly documented source layouts and configured signatures are recognized. Unclassified/manual-review records require inspection at their original citations. Unknown timestamps are not invented. No comprehensive injection detection or attribution is claimed. Key-aware redaction cannot identify arbitrary unlabeled secrets; treat all reports as confidential. Source inventory and diagnostics are in manifest.json.\n')
        self.db.commit()
        hashes = {}
        for p in output.iterdir():
            if p.suffix in {'.jsonl', '.md'}:
                with p.open('rb') as stream:
                    hashes[p.name] = fingerprint(stream)
        return hashes

    def close(self):
        self.db.close()
