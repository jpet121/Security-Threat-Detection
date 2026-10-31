"""Strict, versioned local configuration; compile all patterns before input I/O."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import tomllib
import math
import regex


@dataclass(frozen=True)
class Rule:
    id: str
    version: str
    classification: str
    formats: tuple[str, ...]
    fields: tuple[str, ...]
    pattern: object
    description: str
    priority: str
    enabled: bool


@dataclass(frozen=True)
class Config:
    digest: str
    rules: tuple[Rule, ...]
    limits: dict
    groups: dict
    console: dict


LIMITS = {'line_bytes': 65536, 'event_bytes': 262144, 'field_chars': 32768,
          'decode_depth': 2, 'regex_seconds': 0.02, 'expanded_bytes': 1073741824,
          'disk_bytes': 1073741824}
GROUPS = {'window_seconds': 300, 'repeat_count': 5, 'spray_accounts': 5, 'burst_count': 5}
CONSOLE = {'boundary': r'^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d',
           'timestamp': r'^(?P<timestamp>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)',
           'prefix': r'^(?:[^ |]+\s+\|\s*)?'}
FIELDS = {'auth_message', 'event', 'request.query', 'request.path', 'request.body',
          'request.header', 'request.user_agent', 'request.referer'}


def load(path: Path) -> Config:
    if path.stat().st_size > 1048576:
        raise ValueError('rule configuration exceeds 1 MiB')
    raw = path.read_bytes()
    data = tomllib.loads(raw.decode('utf-8'))
    if data.get('schema_version') != 1 or set(data) - {'schema_version', 'limits', 'groups', 'console', 'rules'}:
        raise ValueError('expected schema_version = 1 and documented sections')
    sections = []
    for name, defaults in [('limits', LIMITS), ('groups', GROUPS)]:
        values = data.get(name, {})
        if not isinstance(values, dict) or set(values) - set(defaults):
            raise ValueError(f'unknown {name} option')
        merged = defaults | values
        for key, value in merged.items():
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError(f'{name}.{key} must be positive and finite')
            if key not in ('regex_seconds', 'window_seconds') and type(value) is not int:
                raise ValueError(f'{name}.{key} must be an integer')
        sections.append(merged)
    limits, groups = sections
    if not (limits['line_bytes'] <= limits['event_bytes'] <= 16777216 and
            limits['field_chars'] <= 1048576 and limits['decode_depth'] <= 5 and
            limits['regex_seconds'] <= 1):
        raise ValueError('unsafe limits: event <=16 MiB, field <=1 MiB, decode <=5, timeout <=1s')
    console = data.get('console', {})
    if not isinstance(console, dict) or set(console) - set(CONSOLE):
        raise ValueError('unknown console option')
    console = {k: regex.compile(v) for k, v in (CONSOLE | console).items()}
    if 'timestamp' not in console['timestamp'].groupindex:
        raise ValueError('console timestamp must define named timestamp group')
    rules = []
    ids = set()
    for item in data.get('rules', []):
        required = {'id', 'version', 'classification', 'formats', 'fields', 'pattern', 'description', 'priority', 'enabled'}
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError('each rule must contain exactly the documented rule fields')
        if not all(isinstance(item[k], str) and item[k] for k in required - {'formats', 'fields', 'enabled'}):
            raise ValueError('rule metadata must be nonempty strings')
        if not regex.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', item['id']) or item['id'] in ids:
            raise ValueError('rule IDs must be unique safe identifiers')
        if item['classification'] not in {'failed_authentication', 'suspected_injection'} or type(item['enabled']) is not bool:
            raise ValueError('invalid classification or enabled flag')
        for key, allowed in [('formats', {'ssh', 'http', 'console'}), ('fields', FIELDS)]:
            if not isinstance(item[key], list) or not item[key] or any(v not in allowed for v in item[key]):
                raise ValueError(f'invalid rule {key}')
        if item['classification'] == 'failed_authentication' and (set(item['fields']) - {'auth_message', 'event'} or 'http' in item['formats']):
            raise ValueError('authentication rules require explicit SSH/console auth fields')
        if item['classification'] == 'suspected_injection' and any(not f.startswith('request.') for f in item['fields']):
            raise ValueError('injection rules require request input fields')
        if len(item['pattern']) > 8192:
            raise ValueError('rule pattern exceeds 8192 characters')
        ids.add(item['id'])
        rules.append(Rule(item['id'], item['version'], item['classification'], tuple(item['formats']),
                          tuple(item['fields']), regex.compile(item['pattern']), item['description'], item['priority'], item['enabled']))
    if not rules:
        raise ValueError('at least one rule is required')
    return Config(sha256(raw).hexdigest(), tuple(rules), limits, groups, console)
