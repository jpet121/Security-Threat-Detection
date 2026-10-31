"""Documented format adapters. No generic whole-line attack grep."""
from dataclasses import dataclass
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import re
from urllib.parse import unquote, urlsplit

HTTP = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>[^" ]+) HTTP/[0-9.]+" (?P<status>\d{3}) (?:\d+|-)(?: "(?P<referer>[^"\r\n]*)" "(?P<agent>[^"\r\n]*)")?\s*$')
SSH = re.compile(r'^(?:(?P<time>[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) )?(?P<server>\S+) sshd\[\d+\]: (?P<message>[^\r\n]+)$')
AUTH = re.compile(r'^Failed (?:password|publickey) for (?:invalid user )?(?P<account>\S+) from (?P<ip>\S+) port \d+(?: ssh\d)?(?: \[preauth\])?$')
KEY = re.compile(r'([\w.]+)=')


def console_fields(text):
    """Parse complete key/value tokens; refuse ambiguous or lost field content.

    Double quotes and backslashes may be escaped inside quoted values. Other
    escapes, duplicate keys and non-field tails are unsupported, never ignored.
    Plain logger labels before fields and fieldless continuation lines are valid.
    """
    fields = {}
    for line in text.splitlines():
        position, seen_field = 0, False
        while position < len(line):
            if line[position].isspace():
                position += 1
                continue
            match = KEY.match(line, position)
            if not match:
                end = position
                while end < len(line) and not line[end].isspace():
                    end += 1
                if seen_field or any(c in line[position:end] for c in '=\\"'):
                    raise ValueError('unsupported console token')
                position = end
                continue
            key = match[1]
            if key in fields:
                raise ValueError('duplicate console field')
            seen_field = True
            position = match.end()
            value = []
            if position < len(line) and line[position] == '"':
                position += 1
                while position < len(line) and line[position] != '"':
                    char = line[position]
                    if char == '\\':
                        position += 1
                        if position == len(line) or line[position] not in '\\"':
                            raise ValueError('unsupported console escape')
                        char = line[position]
                    value.append(char)
                    position += 1
                if position == len(line):
                    raise ValueError('unterminated console quote')
                position += 1
                if position < len(line) and not line[position].isspace():
                    raise ValueError('unparsed content after quoted field')
            else:
                while position < len(line) and not line[position].isspace():
                    if line[position] in '\\"':
                        raise ValueError('unsupported unquoted escape or quote')
                    value.append(line[position])
                    position += 1
            fields[key] = ''.join(value)
    return fields


@dataclass(frozen=True)
class Event:
    format: str
    timestamp: str | None
    fields: dict


def parse(text, config):
    match = HTTP.fullmatch(text)
    if match:
        v = match.groupdict()
        if '#' in v['target']:
            return None
        try:
            target = urlsplit(v['target'])
        except ValueError:
            return None
        return Event('http', v['time'], {'ip': v['ip'], 'account': None, 'server': None,
                     'service': 'http', 'endpoint': target.path, 'request.path': target.path,
                     'request.query': target.query, 'request.user_agent': v['agent'],
                     'request.referer': v['referer'], 'status': v['status']})
    match = SSH.fullmatch(text)
    if match:
        v = match.groupdict()
        auth = AUTH.fullmatch(v['message'])
        return Event('ssh', v['time'], {'server': v['server'], 'service': 'ssh',
                    'ip': auth['ip'] if auth else None, 'account': auth['account'] if auth else None,
                    'auth_message': v['message']})
    match = config.console['timestamp'].search(text, timeout=config.limits['regex_seconds'])
    if match:
        try:
            fields = console_fields(text)
        except ValueError:
            return None
        return Event('console', match['timestamp'], {
            'ip': fields.get('ip'), 'account': fields.get('account'), 'server': fields.get('server'),
            'service': fields.get('service'), 'event': fields.get('event'),
            **{k: v for k, v in fields.items() if k.startswith('request.')},
            'endpoint': fields.get('endpoint')})
    return None


def timestamp(raw, tz=None, year=None):
    if not raw:
        return None, 'missing'
    try:
        if re.match(r'^\d{1,2}/[A-Z]', raw):
            dt = datetime.strptime(raw, '%d/%b/%Y:%H:%M:%S %z')
        elif re.match(r'^[A-Z][a-z]{2} ', raw):
            if year is None:
                return None, 'missing_year_and_offset'
            dt = datetime.strptime(f'{year} {raw}', '%Y %b %d %H:%M:%S')
        else:
            dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        state = 'recorded_offset'
        if dt.tzinfo is None:
            if tz is None:
                return None, 'missing_offset'
            zone = ZoneInfo(tz)
            first, second = dt.replace(tzinfo=zone, fold=0), dt.replace(tzinfo=zone, fold=1)
            if first.utcoffset() != second.utcoffset() or first.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) != dt:
                return None, 'ambiguous_or_nonexistent_local_time'
            dt, state = first, 'operator_timezone'
        return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'), state
    except ValueError:
        return None, 'invalid'


def normalize(value, limits):
    if len(value) > limits['field_chars']:
        return [value[:limits['field_chars']]], 'field_limit'
    copies = [value]
    for _ in range(limits['decode_depth']):
        if re.search(r'%(?![0-9a-fA-F]{2})', copies[-1]):
            return copies, 'malformed_percent'
        try:
            decoded = unquote(copies[-1], errors='strict')
        except UnicodeError:
            return copies, 'invalid_percent_utf8'
        if decoded == copies[-1]:
            return copies, None
        copies.append(decoded)
    if re.search(r'%[0-9a-fA-F]{2}', copies[-1]):
        return copies, 'decode_depth'
    return copies, None


def inspect(event, config):
    hits, reviews = [], set()
    cache = {}
    for rule in config.rules:
        if not rule.enabled or event.format not in rule.formats:
            continue
        matched = False
        for field in rule.fields:
            value = event.fields.get(field)
            if not isinstance(value, str):
                continue
            if field not in cache:
                cache[field] = normalize(value, config.limits) if field.startswith('request.') else ([value], None)
            variants, issue = cache[field]
            if issue:
                reviews.add(issue)
            for variant in variants:
                try:
                    matched |= bool(rule.pattern.search(variant, timeout=config.limits['regex_seconds']))
                except TimeoutError:
                    reviews.add('regex_timeout')
        if matched:
            hits.append({'rule_id': rule.id, 'rule_version': rule.version,
                         'config_sha256': config.digest, 'classification': rule.classification,
                         'reason': rule.description, 'priority': rule.priority})
    return hits, sorted(reviews)
