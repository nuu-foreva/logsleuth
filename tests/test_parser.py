import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from logsleuth.parser import parse_file, parse_line, parse_lines


class ParseLineTests(unittest.TestCase):
    def test_extracts_all_fields(self):
        entry = parse_line("2026-10-13 08:00:01,120 INFO app: Service starting", line_number=7)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.timestamp, datetime(2026, 10, 13, 8, 0, 1, 120000))
        self.assertEqual(entry.level, "INFO")
        self.assertEqual(entry.source, "app")
        self.assertEqual(entry.message, "Service starting")
        self.assertEqual(entry.line_number, 7)

    def test_fractional_seconds_formats(self):
        cases = {
            "2026-10-13 08:00:01": 0,
            "2026-10-13 08:00:01,5": 500000,
            "2026-10-13 08:00:01.123": 123000,
            "2026-10-13T08:00:01.123456": 123456,
        }
        for text, microsecond in cases.items():
            with self.subTest(text=text):
                entry = parse_line(f"{text} INFO app: x")
                self.assertIsNotNone(entry)
                self.assertEqual(entry.timestamp.microsecond, microsecond)
                self.assertEqual(entry.timestamp.second, 1)

    def test_level_aliases_and_case(self):
        cases = {
            "WARN": "WARNING",
            "warning": "WARNING",
            "Fatal": "CRITICAL",
            "error": "ERROR",
            "DEBUG": "DEBUG",
            "critical": "CRITICAL",
        }
        for written, expected in cases.items():
            with self.subTest(level=written):
                entry = parse_line(f"2026-10-13 08:00:01 {written} app: x")
                self.assertIsNotNone(entry)
                self.assertEqual(entry.level, expected)

    def test_source_with_dots_and_dashes(self):
        entry = parse_line("2026-10-13 08:00:01 INFO auth.http-v2: ok")
        self.assertEqual(entry.source, "auth.http-v2")

    def test_message_may_contain_colons(self):
        entry = parse_line("2026-10-13 08:00:01 INFO app: key: value: more")
        self.assertEqual(entry.message, "key: value: more")

    def test_empty_message_is_allowed(self):
        for line in ("2026-10-13 08:00:01 INFO app:", "2026-10-13 08:00:01 INFO app: "):
            with self.subTest(line=line):
                entry = parse_line(line)
                self.assertIsNotNone(entry)
                self.assertEqual(entry.message, "")

    def test_trailing_newlines_are_ignored(self):
        entry = parse_line("2026-10-13 08:00:01 INFO app: ok\r\n")
        self.assertEqual(entry.message, "ok")

    def test_returns_none_for_non_headers(self):
        bad_lines = [
            "",
            "just some text",
            "2026-10-13 08:00:01 INFO no source here",
            "2026-10-13 08:00:01 LOUD app: unknown level",
            "10/13/2026 08:00:01 INFO app: wrong date format",
        ]
        for line in bad_lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))

    def test_returns_none_for_impossible_timestamp(self):
        self.assertIsNone(parse_line("2026-13-45 99:00:00 ERROR app: nope"))
        self.assertIsNone(parse_line("2026-02-30 10:00:00 ERROR app: no such day"))
        self.assertIsNone(parse_line("2026-10-13 24:00:00 ERROR app: no hour 24"))


class ParseLinesTests(unittest.TestCase):
    def test_continuation_lines_are_attached(self):
        result = parse_lines(
            [
                "2026-10-13 09:00:00 ERROR api: Unhandled exception",
                "Traceback (most recent call last):",
                '  File "x.py", line 1, in <module>',
                "ValueError: boom",
                "2026-10-13 09:00:05 INFO api: next",
            ]
        )
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.malformed, 0)
        self.assertEqual(
            result.entries[0].message,
            "Unhandled exception\n"
            "Traceback (most recent call last):\n"
            '  File "x.py", line 1, in <module>\n'
            "ValueError: boom",
        )
        self.assertEqual(result.entries[0].line_number, 1)
        self.assertEqual(result.entries[1].line_number, 5)
        self.assertEqual(result.entries[1].message, "next")

    def test_blank_lines_are_ignored_and_leading_junk_is_malformed(self):
        result = parse_lines(
            [
                "garbage before any record",
                "",
                "   ",
                "2026-10-13 09:00:00 INFO a: ok",
                "",
                "trailing detail",
            ]
        )
        self.assertEqual(result.malformed, 1)
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.entries[0].message, "ok\ntrailing detail")

    def test_header_with_bad_timestamp_is_malformed_and_detaches_following_lines(self):
        result = parse_lines(
            [
                "2026-10-13 09:00:00 INFO a: ok",
                "2026-13-45 99:00:00 ERROR a: bad",
                "  stray continuation",
                "2026-10-13 09:00:01 INFO a: fine",
            ]
        )
        self.assertEqual(result.malformed, 2)
        self.assertEqual([e.message for e in result.entries], ["ok", "fine"])

    def test_empty_input(self):
        result = parse_lines([])
        self.assertEqual(result.entries, [])
        self.assertEqual(result.malformed, 0)

    def test_accepts_any_iterable(self):
        lines = (f"2026-10-13 09:00:0{i} INFO a: m{i}" for i in range(3))
        result = parse_lines(lines)
        self.assertEqual([e.message for e in result.entries], ["m0", "m1", "m2"])


class ParseFileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_reads_a_file(self):
        path = self.dir / "a.log"
        path.write_text("2026-10-13 09:00:00 INFO a: ok\n", encoding="utf-8")
        result = parse_file(path)
        self.assertEqual(len(result.entries), 1)

    def test_handles_crlf_line_endings(self):
        path = self.dir / "crlf.log"
        path.write_bytes(b"2026-10-13 09:00:00 INFO a: one\r\n2026-10-13 09:00:01 INFO a: two\r\n")
        result = parse_file(path)
        self.assertEqual([e.message for e in result.entries], ["one", "two"])

    def test_ignores_utf8_byte_order_mark(self):
        path = self.dir / "bom.log"
        path.write_bytes(b"\xef\xbb\xbf2026-10-13 09:00:00 INFO a: ok\n")
        result = parse_file(path)
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.malformed, 0)

    def test_replaces_undecodable_bytes(self):
        path = self.dir / "latin1.log"
        path.write_bytes(b"2026-10-13 09:00:00 INFO a: caf\xe9\n")
        result = parse_file(path)
        self.assertEqual(result.entries[0].message, "caf�")

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_file(self.dir / "missing.log")


if __name__ == "__main__":
    unittest.main()
