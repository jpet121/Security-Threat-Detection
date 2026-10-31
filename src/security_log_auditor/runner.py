"""Local orchestration: immutable sources, staged outputs, truthful failure state."""
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import gzip
import zlib
import json
import os
import sqlite3
import time
import uuid
import ctypes
import errno
from . import __version__
from .parsing import parse, timestamp, inspect
from .safety import enumerate_sources, open_source, fingerprint, records, safe
from .reports import Store


def now():
    return datetime.now(timezone.utc).isoformat()


def rename_noreplace(source, destination, library=None):
    """Linux atomic directory commit; never replace even an empty destination."""
    library = library if library is not None else ctypes.CDLL(None, use_errno=True)
    operation = getattr(library, 'renameat2', None)
    if operation is None:
        raise OSError(errno.ENOTSUP, 'atomic no-replace publication is unavailable')
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def publish_output(stage, output, mover=Path.rename, commit=rename_noreplace):
    # All per-file operations happen under a partial name. The only operation
    # targeting the final path is the atomic, exclusive directory commit.
    if output.exists() or output.is_symlink():
        raise FileExistsError(errno.EEXIST, 'output already exists')
    candidate = stage.with_name(stage.name + '.publication')
    candidate.mkdir(mode=0o700)
    for p in sorted(stage.iterdir(), key=lambda p: p.name == 'manifest.json'):
        mover(p, candidate / p.name)
    commit(candidate, output)
    # Commit already succeeded. A leftover empty staging directory must not
    # turn a valid finalized bundle into an incomplete audit.
    try:
        stage.rmdir()
    except OSError:
        pass


def run(inputs, output, config, *, tz=None, year=None, start=None, end=None,
        clock=now, progress=lambda text: None, opener=open_source, store_factory=Store, tick=time.monotonic,
        publisher=publish_output):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('output already exists; select a new output directory')
    output = output.resolve()
    sources = enumerate_sources(inputs, output)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = output.parent / (output.name + '.partial-' + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    manifest = {'schema_version': 1, 'tool_version': __version__, 'rules_config_sha256': config.digest,
                'started_at': clock(), 'run_state': 'incomplete', 'source_inventory': [],
                'records_examined': 0, 'parse_failures': 0, 'unclassified_records': 0,
                'filtered_records': 0, 'manual_review_records': 0, 'unknown_timestamp_records': 0,
                'unique_matched_events': 0, 'total_rule_matches': 0, 'classified_by_type': {},
                'errors': [], 'warnings': [], 'time_policy': {'timezone': tz, 'syslog_year': year,
                'from': start, 'to': end, 'unknown_times': 'retained separately; excluded from windows'},
                'limits': config.limits, 'group_thresholds': config.groups,
                'duplicate_policy': 'each selected physical source and record retained',
                'partial_output': str(stage)}
    store = None
    last_progress = tick()
    incomplete = False
    try:
        store = store_factory(stage / '.events.sqlite', config.limits['disk_bytes'])
        with (stage / 'manual_review.jsonl').open('x', encoding='utf-8') as review:
            for index, path in enumerate(sources):
                source = {'source_id': f's{index:06d}', 'path': safe(str(path)), 'raw_sha256': None,
                          'file_status': 'unreadable', 'records_examined': 0, 'parse_failures': 0,
                          'formats': {}, 'lines_examined': 0}
                manifest['source_inventory'].append(source)
                formats = Counter()
                try:
                    with opener(path) as raw:
                        before = os.fstat(raw.fileno())
                        source['raw_sha256'] = fingerprint(raw)
                        magic = raw.read(2); raw.seek(0)
                        zipped = magic == b'\x1f\x8b' or path.suffix == '.gz'
                        stream = gzip.GzipFile(fileobj=raw) if zipped else raw
                        try:
                            for text, first, last, issue in records(stream, config):
                                source['records_examined'] += 1
                                source['lines_examined'] = last
                                manifest['records_examined'] += 1
                                try:
                                    event = parse(text, config) if not issue else None
                                except TimeoutError:
                                    event, issue = None, 'parser_timeout'
                                hit, reasons = [], []
                                instant, state = None, 'missing'
                                if event:
                                    formats[event.format] += 1
                                    instant, state = timestamp(event.timestamp, tz, year)
                                    if instant is None:
                                        manifest['unknown_timestamp_records'] += 1
                                    if instant and ((start and instant < start) or (end and instant > end)):
                                        manifest['filtered_records'] += 1
                                        continue
                                    hit, reasons = inspect(event, config)
                                    if state in {'invalid', 'ambiguous_or_nonexistent_local_time'}:
                                        reasons.append('timestamp_' + state)
                                else:
                                    issue = issue or 'unsupported_or_malformed_record'
                                    source['parse_failures'] += 1
                                    manifest['parse_failures'] += 1
                                if issue:
                                    reasons.append(issue)
                                if reasons:
                                    manifest['manual_review_records'] += 1
                                    review.write(json.dumps(safe({'source_id': source['source_id'], 'line_start': first,
                                         'line_end': last, 'reasons': reasons}), sort_keys=True) + '\n')
                                if not hit:
                                    manifest['unclassified_records'] += 1
                                else:
                                    classes = sorted({h['classification'] for h in hit})
                                    finding = safe({'finding_id': f"{source['source_id']}:{first}-{last}",
                                        'classification': classes[0], 'classifications': classes,
                                        'source_id': source['source_id'], 'source_path_display_safe': str(path),
                                        'raw_file_sha256': source['raw_sha256'], 'line_start': first, 'line_end': last,
                                        'raw_timestamp': event.timestamp, 'utc_instant': instant,
                                        'timestamp_state': state, 'format_id': event.format,
                                        'fields_redacted': event.fields, 'rule_hits': hit,
                                        'safe_excerpt': text[:1024], 'review_reasons': reasons})
                                    store.add(finding)
                                    manifest['unique_matched_events'] += 1
                                    manifest['total_rule_matches'] += len(hit)
                                    for classification in classes:
                                        counts = manifest['classified_by_type']
                                        counts[classification] = counts.get(classification, 0) + 1
                                if tick() - last_progress >= 5:
                                    progress(f"Examined {manifest['records_examined']} records; {manifest['unique_matched_events']} matched events")
                                    last_progress = tick()
                                if sum(p.stat().st_size for p in stage.iterdir()) > config.limits['disk_bytes']:
                                    raise OSError('staging disk limit exceeded')
                        finally:
                            if zipped:
                                stream.close()
                        after = os.fstat(raw.fileno())
                        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino) or fingerprint(raw) != source['raw_sha256']:
                            raise OSError('source changed while auditing')
                        source['file_status'] = 'read'
                except (OSError, EOFError, TimeoutError, zlib.error) as exc:
                    incomplete = True
                    # Fixed codes only: exception text can contain hostile paths/data.
                    source['file_status'] = 'incomplete'
                    source['error_code'] = type(exc).__name__
                    manifest['errors'].append({'source_id': source['source_id'], 'code': type(exc).__name__,
                                               'action': 'check permissions, archive integrity, configured limits and source stability'})
                source['formats'] = dict(formats)
        if manifest['manual_review_records']:
            manifest['warnings'].append('Records require manual review; see manual_review.jsonl')
        manifest['run_state'] = 'incomplete' if incomplete else 'warnings' if manifest['warnings'] else 'complete'
        manifest['artifacts'] = store.write(stage, manifest, config)
        store.close(); store = None
        (stage / '.events.sqlite').unlink()
        manifest['ended_at'] = clock()
        if not incomplete:
            del manifest['partial_output']
        with (stage / 'manifest.json').open('x', encoding='utf-8') as f:
            json.dump(safe(manifest), f, indent=2, sort_keys=True)
        if not incomplete:
            # Final visibility is one atomic no-replace directory commit.
            publisher(stage, output)
        progress(f"Audit {manifest['run_state']}; results: {safe(str(stage if incomplete else output))}")
        return (3 if incomplete else 2 if manifest['warnings'] else 0), manifest
    except (KeyboardInterrupt, OSError, sqlite3.Error, TimeoutError) as exc:
        manifest['run_state'] = 'incomplete'
        manifest['partial_output'] = str(stage)
        candidate = stage.with_name(stage.name + '.publication')
        if candidate.exists():
            manifest['publication_partial'] = str(candidate)
        manifest['ended_at'] = clock()
        manifest['errors'].append({'code': type(exc).__name__, 'action': 'inspect partial output; rerun into a new directory'})
        try:
            (stage / 'manifest.json').write_text(json.dumps(safe(manifest), indent=2), encoding='utf-8')
        except OSError:
            pass
        progress(f'Audit incomplete; partial results: {safe(str(stage))}')
        return 3, manifest
    finally:
        if store is not None:
            store.close()
