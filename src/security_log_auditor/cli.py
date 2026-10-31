"""Linux-compatible CLI; no network I/O or automatic rule updates."""
import argparse
from pathlib import Path
import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import regex
from . import __version__
from .config import load
from .parsing import timestamp
from .runner import run


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline SSH, HTTP and console forensic triage. Exit 0 complete, 2 warnings, 3 incomplete (partial directory), 64 invalid input/config.')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--input', action='append', required=True, help='local file or directory; repeat for several exports')
    parser.add_argument('--rules', type=Path, default=Path(__file__).with_name('default.toml'))
    parser.add_argument('--output', type=Path, required=True, help='new directory outside input trees')
    parser.add_argument('--from', dest='start', help='inclusive ISO datetime with explicit offset')
    parser.add_argument('--to', dest='end', help='inclusive ISO datetime with explicit offset')
    parser.add_argument('--timezone', help='explicit IANA timezone for missing offsets')
    parser.add_argument('--syslog-year', type=int, help='explicit year for yearless syslog records')
    args = parser.parse_args(argv)
    try:
        config = load(args.rules)
        if args.timezone:
            ZoneInfo(args.timezone)
        if args.syslog_year is not None and not 1 <= args.syslog_year <= 9999:
            raise ValueError('syslog year must be between 1 and 9999')
        bounds = []
        for raw in (args.start, args.end):
            instant, _ = timestamp(raw)
            if raw and instant is None:
                raise ValueError('time filters require valid ISO timestamps with offsets')
            bounds.append(instant)
        if all(bounds) and bounds[0] > bounds[1]:
            raise ValueError('--from must not exceed --to')
        code, _ = run(args.input, args.output, config, tz=args.timezone, year=args.syslog_year,
                      start=bounds[0], end=bounds[1], progress=lambda text: print(text, file=sys.stderr))
        return code
    except (ValueError, OSError, TypeError, KeyError, regex.error, ZoneInfoNotFoundError):
        print('Invalid input/config: check rule schema and regex syntax, paths, output collision, timezone and time bounds. No audit completed.', file=sys.stderr)
        return 64
