"""Parse plain-text application logs into :class:`~logsleuth.models.LogEntry` objects.

Each record starts with a header line in this format::

    YYYY-MM-DD HH:MM:SS[,mmm] LEVEL source: message

* The date and time may be separated by a space or a ``T``.
* Fractional seconds (1-6 digits) may follow a comma or a dot.
* ``LEVEL`` is case-insensitive; ``WARN`` and ``FATAL`` are accepted aliases.
* ``source`` is a short name such as ``db`` or ``auth.http`` followed by a colon.

Any line that is not a header is treated as a continuation of the previous
record (for example a stack trace). Lines that cannot be attached to a record,
and headers with an impossible timestamp, are counted as malformed and skipped.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime

from .models import LogEntry, normalize_level

_HEADER_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"
    r"\s+(?P<level>(?i:debug|info|warning|warn|error|critical|fatal))"
    r"\s+(?P<source>[\w.\-]+):"
    r"(?:\s+(?P<message>.*))?$"
)


@dataclass(frozen=True)
class ParseResult:
    """Entries parsed from a log plus the number of lines that were skipped."""

    entries: list[LogEntry]
    malformed: int


def _parse_timestamp(text: str) -> datetime:
    """Convert a header timestamp to a naive :class:`datetime`.

    Raises :class:`ValueError` for impossible values such as month 13.
    """
    date_part, time_part = re.split(r"[ T]", text.replace(",", "."), maxsplit=1)
    whole, dot, fraction = time_part.partition(".")
    if dot:
        # Pad so that ".5" means half a second and ".123" means 123 ms.
        whole = f"{whole}.{fraction.ljust(6, '0')}"
    return datetime.fromisoformat(f"{date_part} {whole}")


def _entry_from_match(match: re.Match[str], line_number: int) -> LogEntry:
    return LogEntry(
        timestamp=_parse_timestamp(match["ts"]),
        level=normalize_level(match["level"]),
        source=match["source"],
        message=match["message"] or "",
        line_number=line_number,
    )


def parse_line(line: str, line_number: int = 0) -> LogEntry | None:
    """Parse one header line, returning ``None`` if it is not a valid header."""
    match = _HEADER_RE.match(line.rstrip())
    if match is None:
        return None
    try:
        return _entry_from_match(match, line_number)
    except ValueError:
        return None


def parse_lines(lines: Iterable[str]) -> ParseResult:
    """Parse an iterable of lines (a file object, a list of strings, ...)."""
    entries: list[LogEntry] = []
    malformed = 0
    current: LogEntry | None = None
    extra: list[str] = []

    def flush() -> None:
        nonlocal current, extra
        if current is not None:
            if extra:
                current = replace(current, message="\n".join([current.message, *extra]))
            entries.append(current)
        current = None
        extra = []

    for number, line in enumerate(lines, start=1):
        raw = line.rstrip()
        if not raw:
            continue
        match = _HEADER_RE.match(raw)
        if match is not None:
            flush()
            try:
                current = _entry_from_match(match, number)
            except ValueError:
                malformed += 1
        elif current is not None:
            extra.append(raw)
        else:
            malformed += 1
    flush()
    return ParseResult(entries=entries, malformed=malformed)


def parse_file(path: str | os.PathLike[str]) -> ParseResult:
    """Parse the log file at ``path``.

    The file is read as UTF-8 (a leading byte-order mark is ignored) and
    undecodable bytes are replaced instead of raising an error.
    """
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        return parse_lines(handle)
