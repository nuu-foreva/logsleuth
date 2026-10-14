"""Render analysis results as plain text or JSON.

Text output is pure ASCII so it displays correctly in any terminal.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from .analyzer import Report
from .models import LogEntry

_BAR_WIDTH = 30
_MAX_SOURCES_SHOWN = 10
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def format_entry(entry: LogEntry) -> str:
    """Format an entry on one logical line (continuation lines follow it)."""
    stamp = entry.timestamp.isoformat(sep=" ", timespec="milliseconds")
    return f"{stamp} {entry.level:<8} {entry.source}: {entry.message}".rstrip()


def _bar(count: int, maximum: int) -> str:
    if count <= 0 or maximum <= 0:
        return ""
    return "#" * max(1, round(count / maximum * _BAR_WIDTH))


def _fmt(moment: datetime) -> str:
    return moment.strftime(_TIME_FORMAT)


def render_text(report: Report) -> str:
    """Return a human-readable report."""
    summary = report.summary
    lines = ["LogSleuth report", "================"]
    lines.append(f"Entries analysed : {summary.total}")
    if report.malformed:
        lines.append(f"Malformed lines  : {report.malformed} (skipped)")

    if summary.total == 0:
        lines.extend(["", "No log entries matched."])
        return "\n".join(lines)

    span = timedelta(seconds=int(summary.span.total_seconds()))  # drop fractional seconds
    lines.append(
        f"Period           : {_fmt(summary.first_timestamp)} -> {_fmt(summary.last_timestamp)}"
        f" ({span})"
    )
    lines.append(
        f"Error rate       : {summary.error_rate:.1%} "
        f"({summary.error_count} of {summary.total} are ERROR or CRITICAL)"
    )

    lines.extend(["", "Levels"])
    level_max = max(summary.by_level.values())
    for name, count in summary.by_level.items():
        lines.append(f"  {name:<9}{count:>6}  {_bar(count, level_max)}".rstrip())

    lines.extend(["", "Sources"])
    sources = list(summary.by_source.items())
    source_max = sources[0][1]
    width = max(len(name) for name, _ in sources[:_MAX_SOURCES_SHOWN])
    for name, count in sources[:_MAX_SOURCES_SHOWN]:
        lines.append(f"  {name:<{width}}{count:>6}  {_bar(count, source_max)}")
    hidden = len(sources) - _MAX_SOURCES_SHOWN
    if hidden > 0:
        lines.append(f"  ... and {hidden} more")

    lines.extend(["", "Top errors"])
    if report.top_errors:
        for rank, group in enumerate(report.top_errors, start=1):
            lines.append(f"  {rank}. {group.count}x [{group.source}] {group.signature}")
            lines.append(
                f"     first seen {_fmt(group.first_seen)}, last seen {_fmt(group.last_seen)}"
            )
    else:
        lines.append("  none")

    lines.extend(
        [
            "",
            f"Error bursts (>= {report.burst_threshold} errors within {report.burst_window:g}s)",
        ]
    )
    if report.bursts:
        for burst in report.bursts:
            lines.append(f"  {_fmt(burst.start)} -> {_fmt(burst.end)}  {burst.count} errors")
    else:
        lines.append("  none detected")

    lines.extend(["", "Activity by hour"])
    hour_max = max(report.hourly)
    for hour, count in enumerate(report.hourly):
        if count:
            lines.append(f"  {hour:02d}:00{count:>6}  {_bar(count, hour_max)}")

    return "\n".join(lines)


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


def report_to_dict(report: Report) -> dict[str, Any]:
    """Convert a report to plain data that can be serialised as JSON."""
    summary = report.summary
    return {
        "total_entries": summary.total,
        "malformed_lines": report.malformed,
        "first_timestamp": _iso(summary.first_timestamp),
        "last_timestamp": _iso(summary.last_timestamp),
        "span_seconds": summary.span.total_seconds() if summary.span is not None else None,
        "error_count": summary.error_count,
        "error_rate": round(summary.error_rate, 4),
        "by_level": dict(summary.by_level),
        "by_source": dict(summary.by_source),
        "top_errors": [
            {
                "source": group.source,
                "signature": group.signature,
                "count": group.count,
                "first_seen": group.first_seen.isoformat(),
                "last_seen": group.last_seen.isoformat(),
            }
            for group in report.top_errors
        ],
        "error_bursts": {
            "window_seconds": report.burst_window,
            "threshold": report.burst_threshold,
            "bursts": [
                {
                    "start": burst.start.isoformat(),
                    "end": burst.end.isoformat(),
                    "count": burst.count,
                }
                for burst in report.bursts
            ],
        },
        "hourly_counts": list(report.hourly),
    }


def render_json(report: Report) -> str:
    """Return the report as indented JSON."""
    return json.dumps(report_to_dict(report), indent=2)
