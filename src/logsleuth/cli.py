"""Command-line interface for LogSleuth."""

from __future__ import annotations

import argparse
import math
import os
import sys
from collections.abc import Sequence
from datetime import datetime

from . import __version__
from .analyzer import analyze, filter_entries
from .models import LEVELS, normalize_level
from .parser import ParseResult, parse_file, parse_lines
from .report import format_entry, render_json, render_text

EXIT_OK = 0
EXIT_INPUT_ERROR = 1
EXIT_USAGE_ERROR = 2

_EPILOG = """\
Log format (one record per header line):
  YYYY-MM-DD HH:MM:SS[,mmm] LEVEL source: message
Lines that do not start a new record (for example stack traces) are attached
to the previous record. Use "-" as FILE to read from standard input.

Exit codes: 0 success, 1 the input could not be read, 2 invalid usage.
"""


# --------------------------------------------------------------------------- #
# Argument converters
# --------------------------------------------------------------------------- #
def _level(text: str) -> str:
    try:
        return normalize_level(text)
    except ValueError:
        message = f"unknown level {text!r} (choose from {', '.join(LEVELS)})"
        raise argparse.ArgumentTypeError(message) from None


def _timestamp(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid date/time {text!r} (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)"
        ) from None
    if value.tzinfo is not None:
        raise argparse.ArgumentTypeError("time zones are not supported; omit the offset")
    return value


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {text!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be a positive, finite number")
    return value


# --------------------------------------------------------------------------- #
# Parser construction
# --------------------------------------------------------------------------- #
def _add_input_and_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file", metavar="FILE", help='log file to read, or "-" for stdin')
    group = parser.add_argument_group("filters")
    group.add_argument("--min-level", type=_level, metavar="LEVEL", help="minimum severity")
    group.add_argument("--source", help="only entries from this source (case-insensitive)")
    group.add_argument("--contains", help="only messages containing this text (case-insensitive)")
    group.add_argument(
        "--since",
        type=_timestamp,
        metavar="TIME",
        help="only entries at or after TIME (date-only values mean midnight)",
    )
    group.add_argument(
        "--until",
        type=_timestamp,
        metavar="TIME",
        help="only entries at or before TIME (date-only values mean midnight)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser (exposed for testing)."""
    parser = argparse.ArgumentParser(
        prog="logsleuth",
        description="Parse application logs and surface error patterns.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    report = commands.add_parser(
        "report",
        help="summarise a log: levels, sources, top errors, bursts and activity",
        description="Summarise a log file.",
    )
    _add_input_and_filters(report)
    report.add_argument("--format", choices=("text", "json"), default="text")
    report.add_argument(
        "--top", type=_positive_int, default=5, metavar="N", help="recurring errors to show"
    )
    report.add_argument(
        "--burst-window",
        type=_positive_float,
        default=60.0,
        metavar="SECONDS",
        help="time window used to detect error bursts (default: 60)",
    )
    report.add_argument(
        "--burst-threshold",
        type=_positive_int,
        default=5,
        metavar="N",
        help="errors within the window needed to count as a burst (default: 5)",
    )

    grep = commands.add_parser(
        "grep",
        help="print the entries that match the filters",
        description="Print log entries that match all of the given filters.",
    )
    _add_input_and_filters(grep)
    grep.add_argument("--count", action="store_true", help="print only the number of matches")

    return parser


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #
def _load(path: str) -> ParseResult:
    if path == "-":
        return parse_lines(sys.stdin)
    return parse_file(path)


def _make_streams_tolerant() -> None:
    """Replace undecodable/unencodable characters instead of crashing."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def _silence_stdout() -> None:
    """Avoid a second error at exit after the reader closed the pipe."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _run(args: argparse.Namespace) -> int:
    try:
        result = _load(args.file)
    except OSError as exc:
        reason = exc.strerror or str(exc)
        print(f"logsleuth: error: cannot read {args.file!r}: {reason}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    try:
        entries = filter_entries(
            result.entries,
            min_level=args.min_level,
            source=args.source,
            contains=args.contains,
            since=args.since,
            until=args.until,
        )
    except ValueError as exc:
        print(f"logsleuth: error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if args.command == "report":
        report = analyze(
            entries,
            malformed=result.malformed,
            top=args.top,
            burst_window=args.burst_window,
            burst_threshold=args.burst_threshold,
        )
        print(render_json(report) if args.format == "json" else render_text(report))
    elif args.count:
        print(len(entries))
    else:
        for entry in entries:
            print(format_entry(entry))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    _make_streams_tolerant()
    try:
        return _run(args)
    except BrokenPipeError:
        # Happens with e.g. `logsleuth grep app.log | head -n 1`.
        _silence_stdout()
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
