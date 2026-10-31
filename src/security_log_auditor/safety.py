"""Safe displays and streaming evidence adapters; never execute evidence."""
from hashlib import sha256
from pathlib import Path
import os
import stat
import re
from urllib.parse import unquote

# Key-aware masking is deliberately conservative; arbitrary unlabeled secrets
# cannot be recognized. Reports must still be handled as confidential evidence.
SECRET = re.compile(r'''(?ix)(\b(?:password|passwd|pwd|token|session(?:id|_id)?|session_token|access_token|refresh_token|api[_-]?key|secret|cookie|authorization|set-cookie)\b\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s&;"'<>]+)''')
HEADER = re.compile(r'(?i)\b(authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+')


def safe(value):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if re.fullmatch(r'(?i)(password|passwd|pwd|token|session.*|.*token|api[_-]?key|secret|cookie|authorization)', str(k)) else safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [safe(v) for v in value]
    if not isinstance(value, str):
        return value
    for _ in range(5):
        decoded = unquote(value, errors='replace')
        if decoded == value:
            break
        value = decoded
    if re.search(r'%[0-9a-fA-F]{2}', value):
        return '[REDACTED: excessive encoding]'
    value = HEADER.sub(lambda m: m[1] + '=[REDACTED]', value)
    value = SECRET.sub(lambda m: m[1] + '[REDACTED]', value)
    return ''.join(c if c.isprintable() and c not in '\u2028\u2029' else f'\\u{ord(c):04x}' for c in value)


def enumerate_sources(inputs, output):
    sources = []
    for name in inputs:
        root = Path(name).absolute()
        if root.is_symlink() or not root.is_dir():
            sources.append(root)
            continue
        if output.is_relative_to(root.resolve()):
            raise ValueError('output must be outside every input directory')
        def failure(error):
            sources.append(Path(error.filename))
        for parent, dirs, files in os.walk(root, followlinks=False, onerror=failure):
            for d in sorted(dirs):
                if (Path(parent) / d).is_symlink():
                    sources.append(Path(parent) / d)
                    dirs.remove(d)
            sources.extend(Path(parent) / f for f in sorted(files))
    sources = sorted(sources, key=str)
    if not sources:
        raise ValueError('input selection contains no files')
    for source in sources:
        if source.resolve() == output or source.resolve().is_relative_to(output):
            raise ValueError('input/output paths overlap')
    return sources


def open_source(path):
    # Walk directory descriptors with O_NOFOLLOW to close ancestor-symlink races.
    path = Path(path).absolute()
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_dir = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_dir
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    stream = os.fdopen(fd, 'rb')
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        stream.close()
        raise OSError('only regular files are accepted')
    return stream


def fingerprint(stream):
    digest = sha256()
    stream.seek(0)
    while chunk := stream.read(1048576):
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()


def records(stream, config):
    """Bound physical lines and console continuations, retain every line range."""
    limit = config.limits['line_bytes']
    total, line, pending = 0, 0, None
    while block := stream.readline(limit + 1):
        line += 1
        start = line
        total += len(block)
        oversize = len(block) > limit
        while not block.endswith(b'\n') and len(block) > limit:
            block = stream.readline(limit + 1)
            total += len(block)
            if total > config.limits['expanded_bytes']:
                raise OSError('expanded byte limit exceeded')
        if total > config.limits['expanded_bytes']:
            raise OSError('expanded byte limit exceeded')
        issue = 'line_limit' if oversize else None
        try:
            text = block.decode('utf-8').rstrip('\r\n') if not oversize else ''
        except UnicodeError:
            text, issue = '', 'invalid_utf8'
        text = config.console['prefix'].sub('', text, count=1, timeout=config.limits['regex_seconds'])
        continuation = text[:1].isspace() and pending is not None and not issue
        boundary = config.console['boundary'].search(text, timeout=config.limits['regex_seconds'])
        if continuation and not boundary and pending[4] is None:
            old, first, _, size, _ = pending
            size += len(block)
            pending = (old + '\n' + text if size <= config.limits['event_bytes'] else '', first, line, size,
                       None if size <= config.limits['event_bytes'] else 'event_limit')
            continue
        if pending:
            yield pending[0], pending[1], pending[2], pending[4]
        pending = (text, start, line, len(block), issue)
    if pending:
        yield pending[0], pending[1], pending[2], pending[4]
