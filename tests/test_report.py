import json
import unittest

from helpers import SAMPLE_LOG, make_entry

from logsleuth.analyzer import analyze
from logsleuth.parser import parse_file, parse_line
from logsleuth.report import format_entry, render_json, render_text


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parsed = parse_file(SAMPLE_LOG)
        cls.entries = parsed.entries
        cls.report = analyze(parsed.entries, malformed=parsed.malformed)

    def test_text_has_every_section(self):
        text = render_text(self.report)
        for heading in ("Levels", "Sources", "Top errors", "Error bursts", "Activity by hour"):
            self.assertIn(heading, text)

    def test_text_is_ascii_and_has_no_trailing_spaces(self):
        text = render_text(self.report)
        self.assertTrue(text.isascii())
        for line in text.splitlines():
            self.assertEqual(line, line.rstrip(), msg=repr(line))

    def test_text_for_empty_report(self):
        text = render_text(analyze([], malformed=3))
        self.assertIn("No log entries matched.", text)
        self.assertIn("Malformed lines  : 3", text)

    def test_text_omits_malformed_line_when_zero(self):
        text = render_text(analyze([make_entry()]))
        self.assertNotIn("Malformed", text)

    def test_text_lists_only_ten_sources(self):
        entries = [make_entry(source=f"src{i:02d}") for i in range(12)]
        text = render_text(analyze(entries))
        self.assertIn("... and 2 more", text)

    def test_json_is_valid_and_consistent(self):
        data = json.loads(render_json(self.report))
        self.assertEqual(data["total_entries"], len(self.entries))
        self.assertEqual(sum(data["by_level"].values()), data["total_entries"])
        self.assertEqual(sum(data["by_source"].values()), data["total_entries"])
        self.assertEqual(sum(data["hourly_counts"]), data["total_entries"])
        self.assertEqual(len(data["hourly_counts"]), 24)
        self.assertEqual(data["error_bursts"]["bursts"][0]["count"], 7)

    def test_json_for_empty_report(self):
        data = json.loads(render_json(analyze([])))
        self.assertEqual(data["total_entries"], 0)
        self.assertIsNone(data["first_timestamp"])
        self.assertIsNone(data["span_seconds"])
        self.assertEqual(data["error_rate"], 0.0)


class FormatEntryTests(unittest.TestCase):
    def test_single_line(self):
        entry = make_entry("2026-10-13 14:42:01.123456", "ERROR", "db", "Connection lost")
        expected = "2026-10-13 14:42:01.123 ERROR    db: Connection lost"
        self.assertEqual(format_entry(entry), expected)

    def test_multi_line_message_keeps_continuation_lines(self):
        entry = make_entry(message="Boom\n  at x.py:1")
        self.assertTrue(format_entry(entry).endswith("Boom\n  at x.py:1"))

    def test_empty_message_has_no_trailing_space(self):
        self.assertTrue(format_entry(make_entry(message="")).endswith("app:"))

    def test_output_can_be_parsed_back(self):
        originals = [
            make_entry("2026-10-13 14:42:01.123000", "ERROR", "auth.http-v2", "key: value"),
            make_entry("2026-01-01 00:00:00", "DEBUG", "db_1", ""),
            make_entry("2026-12-31 23:59:59.999000", "CRITICAL", "x", "café ✓"),
        ]
        for original in originals:
            with self.subTest(original=original):
                parsed = parse_line(format_entry(original))
                self.assertIsNotNone(parsed)
                self.assertEqual(
                    (parsed.timestamp, parsed.level, parsed.source, parsed.message),
                    (original.timestamp, original.level, original.source, original.message),
                )


if __name__ == "__main__":
    unittest.main()
