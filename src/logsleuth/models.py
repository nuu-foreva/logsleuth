"""Core data types shared across LogSleuth modules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: Canonical log levels, ordered from least to most severe.
LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_ALIASES = {"WARN": "WARNING", "FATAL": "CRITICAL"}


def normalize_level(level: str) -> str:
    """Return the canonical upper-case name for ``level``.

    ``WARN`` becomes ``WARNING`` and ``FATAL`` becomes ``CRITICAL``.
    Raises :class:`ValueError` if the level is not recognised.
    """
    name = level.strip().upper()
    name = _ALIASES.get(name, name)
    if name not in LEVELS:
        raise ValueError(f"unknown log level: {level!r}")
    return name


def level_rank(level: str) -> int:
    """Return the severity rank of ``level`` (0 = DEBUG ... 4 = CRITICAL)."""
    return LEVELS.index(normalize_level(level))


@dataclass(frozen=True)
class LogEntry:
    """A single parsed log record.

    ``message`` may span several lines when the record was followed by
    continuation lines such as a stack trace.
    """

    timestamp: datetime
    level: str
    source: str
    message: str
    line_number: int

    @property
    def rank(self) -> int:
        """Severity rank of this entry (see :func:`level_rank`)."""
        return level_rank(self.level)
