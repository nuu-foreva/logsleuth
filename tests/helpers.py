"""Shared helpers for the test-suite."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from logsleuth.models import LogEntry

SAMPLE_LOG = Path(__file__).resolve().parents[1] / "sample_logs" / "app.log"
SRC_DIR = Path(__file__).resolve().parents[1] / "src"

BASE_TIME = datetime(2026, 10, 13, 10, 0, 0)


def make_entry(
    timestamp: str | datetime = BASE_TIME,
    level: str = "INFO",
    source: str = "app",
    message: str = "hello",
    line_number: int = 1,
) -> LogEntry:
    """Build a LogEntry with sensible defaults."""
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)
    return LogEntry(
        timestamp=timestamp,
        level=level,
        source=source,
        message=message,
        line_number=line_number,
    )


def error_at(seconds: float, level: str = "ERROR", **kwargs) -> LogEntry:
    """Build an error entry ``seconds`` after BASE_TIME."""
    return make_entry(BASE_TIME + timedelta(seconds=seconds), level=level, **kwargs)
