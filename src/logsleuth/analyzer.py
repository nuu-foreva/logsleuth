"""Analysis helpers: filtering, summarising and spotting error patterns."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import LEVELS, LogEntry, level_rank, normalize_level

ERROR_RANK = LEVELS.index("ERROR")
HOURS_IN_DAY = 24


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #
def filter_entries(
    entries: Iterable[LogEntry],
    *,
    min_level: str | None = None,
    source: str | None = None,
    contains: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[LogEntry]:
    """Return the entries that satisfy every given criterion.

    * ``min_level``: keep entries at this severity or higher.
    * ``source``: keep entries from this source (case-insensitive, exact).
    * ``contains``: keep entries whose message contains this text (case-insensitive).
    * ``since`` / ``until``: keep entries within the range, both ends inclusive.

    Raises :class:`ValueError` for an unknown level or when ``since`` is later
    than ``until``.
    """
    if since is not None and until is not None and since > until:
        raise ValueError("'since' must not be later than 'until'")
    minimum = level_rank(min_level) if min_level is not None else 0
    wanted_source = source.lower() if source is not None else None
    needle = contains.lower() if contains else None

    selected: list[LogEntry] = []
    for entry in entries:
        if entry.rank < minimum:
            continue
        if wanted_source is not None and entry.source.lower() != wanted_source:
            continue
        if needle is not None and needle not in entry.message.lower():
            continue
        if since is not None and entry.timestamp < since:
            continue
        if until is not None and entry.timestamp > until:
            continue
        selected.append(entry)
    return selected


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Summary:
    """High-level statistics about a set of entries."""

    total: int
    by_level: dict[str, int]
    by_source: dict[str, int]
    first_timestamp: datetime | None
    last_timestamp: datetime | None
    error_count: int

    @property
    def error_rate(self) -> float:
        """Fraction of entries that are ERROR or CRITICAL (0.0 when empty)."""
        return self.error_count / self.total if self.total else 0.0

    @property
    def span(self) -> timedelta | None:
        """Time between the first and last entry, or ``None`` when empty."""
        if self.first_timestamp is None or self.last_timestamp is None:
            return None
        return self.last_timestamp - self.first_timestamp


def summarize(entries: Iterable[LogEntry]) -> Summary:
    """Count entries by level and source and find the covered time range."""
    level_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    first: datetime | None = None
    last: datetime | None = None
    total = 0

    for entry in entries:
        total += 1
        level_counts[normalize_level(entry.level)] += 1
        source_counts[entry.source] += 1
        if first is None or entry.timestamp < first:
            first = entry.timestamp
        if last is None or entry.timestamp > last:
            last = entry.timestamp

    by_level = {name: level_counts.get(name, 0) for name in LEVELS}
    by_source = dict(sorted(source_counts.items(), key=lambda item: (-item[1], item[0])))
    return Summary(
        total=total,
        by_level=by_level,
        by_source=by_source,
        first_timestamp=first,
        last_timestamp=last,
        error_count=by_level["ERROR"] + by_level["CRITICAL"],
    )


# --------------------------------------------------------------------------- #
# Recurring errors
# --------------------------------------------------------------------------- #
_SIGNATURE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    # Numbers, including ones glued to a unit ("5000ms"), but not digits that are
    # part of a word such as "user42".
    (re.compile(r"(?<![A-Za-z_\d])\d+"), "<n>"),
)


def error_signature(message: str) -> str:
    """Reduce a message to a signature so similar errors group together.

    Only the first non-empty line is used (so stack traces do not split
    groups) and UUIDs, IP addresses, hex values and numbers are replaced with
    placeholders: ``"Timeout after 5000ms"`` becomes ``"Timeout after <n>ms"``.
    """
    first_line = next((line.strip() for line in message.splitlines() if line.strip()), "")
    for pattern, placeholder in _SIGNATURE_PATTERNS:
        first_line = pattern.sub(placeholder, first_line)
    return first_line


@dataclass(frozen=True)
class ErrorGroup:
    """A family of similar ERROR/CRITICAL entries from one source."""

    source: str
    signature: str
    count: int
    first_seen: datetime
    last_seen: datetime


def top_errors(entries: Iterable[LogEntry], limit: int = 5) -> list[ErrorGroup]:
    """Return the most frequent error groups, most common first.

    Ties are broken by earliest first occurrence, then by source and signature,
    so the result is deterministic. Raises :class:`ValueError` if ``limit`` < 1.
    """
    if limit < 1:
        raise ValueError("limit must be at least 1")

    groups: dict[tuple[str, str], list] = {}
    for entry in entries:
        if entry.rank < ERROR_RANK:
            continue
        key = (entry.source, error_signature(entry.message))
        stats = groups.get(key)
        if stats is None:
            groups[key] = [1, entry.timestamp, entry.timestamp]
        else:
            stats[0] += 1
            stats[1] = min(stats[1], entry.timestamp)
            stats[2] = max(stats[2], entry.timestamp)

    ordered = sorted(
        (
            ErrorGroup(source, signature, count, first, last)
            for (source, signature), (count, first, last) in groups.items()
        ),
        key=lambda g: (-g.count, g.first_seen, g.source, g.signature),
    )
    return ordered[:limit]


# --------------------------------------------------------------------------- #
# Error bursts
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Burst:
    """A tight cluster of ERROR/CRITICAL entries."""

    start: datetime
    end: datetime
    count: int


def find_error_bursts(
    entries: Iterable[LogEntry],
    window_seconds: float = 60.0,
    threshold: int = 5,
) -> list[Burst]:
    """Find clusters of at least ``threshold`` errors within ``window_seconds``.

    The scan is greedy and left to right: a burst starts at the first error not
    yet claimed and extends over every error that follows within the window, so
    bursts never overlap. Raises :class:`ValueError` for invalid arguments.
    """
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a positive, finite number")
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    try:
        window = timedelta(seconds=window_seconds)
    except OverflowError:
        raise ValueError("window_seconds is too large") from None

    times = sorted(entry.timestamp for entry in entries if entry.rank >= ERROR_RANK)
    bursts: list[Burst] = []
    count = len(times)
    i = 0
    j = 0
    while i < count:
        j = max(j, i)
        while j + 1 < count and times[j + 1] - times[i] <= window:
            j += 1
        size = j - i + 1
        if size >= threshold:
            bursts.append(Burst(start=times[i], end=times[j], count=size))
            i = j + 1
        else:
            i += 1
    return bursts


# --------------------------------------------------------------------------- #
# Activity and the combined report
# --------------------------------------------------------------------------- #
def hourly_counts(entries: Iterable[LogEntry]) -> list[int]:
    """Return 24 counts: how many entries fall in each hour of the day."""
    counts = [0] * HOURS_IN_DAY
    for entry in entries:
        counts[entry.timestamp.hour] += 1
    return counts


@dataclass(frozen=True)
class Report:
    """Everything the ``report`` command shows."""

    summary: Summary
    top_errors: list[ErrorGroup]
    bursts: list[Burst]
    hourly: list[int]
    malformed: int
    burst_window: float
    burst_threshold: int


def analyze(
    entries: Iterable[LogEntry],
    *,
    malformed: int = 0,
    top: int = 5,
    burst_window: float = 60.0,
    burst_threshold: int = 5,
) -> Report:
    """Run every analysis over ``entries`` and bundle the results."""
    items = list(entries)
    return Report(
        summary=summarize(items),
        top_errors=top_errors(items, top),
        bursts=find_error_bursts(items, burst_window, burst_threshold),
        hourly=hourly_counts(items),
        malformed=malformed,
        burst_window=burst_window,
        burst_threshold=burst_threshold,
    )
