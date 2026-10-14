import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import SAMPLE_LOG, SRC_DIR

from logsleuth import __version__
from logsleuth.cli import main


def run(*argv):
    """Run main() and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


def run_expecting_exit(*argv):
    """Run main() where argparse is expected to call sys.exit()."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            main([str(a) for a in argv])
        except SystemExit as exc:
            return exc.code, out.getvalue(), err.getvalue()
    raise AssertionError("main() did not exit")


class ReportCommandTests(unittest.TestCase):
    def test_text_report(self):
        code, out, err = run("report", SAMPLE_LOG)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("Entries analysed : 29", out)
        self.assertIn("Malformed lines  : 2 (skipped)", out)
        self.assertIn("4x [db] Connection timed out after <n>ms (host=<ip>)", out)
        self.assertIn("09:14:05 -> 2026-10-13 09:14:44  7 errors", out)

    def test_json_report(self):
        code, out, _ = run("report", SAMPLE_LOG, "--format", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["total_entries"], 29)
        self.assertEqual(data["malformed_lines"], 2)
        self.assertEqual(data["error_count"], 12)

    def test_top_option(self):
        _, out, _ = run("report", SAMPLE_LOG, "--format", "json", "--top", "1")
        self.assertEqual(len(json.loads(out)["top_errors"]), 1)

    def test_burst_options(self):
        options = ["--format", "json", "--burst-window", "5", "--burst-threshold", "2"]
        _, out, _ = run("report", SAMPLE_LOG, *options)
        data = json.loads(out)["error_bursts"]
        self.assertEqual(data["window_seconds"], 5.0)
        self.assertEqual(data["threshold"], 2)
        self.assertGreaterEqual(len(data["bursts"]), 1)

    def test_filters_apply_to_report(self):
        _, out, _ = run("report", SAMPLE_LOG, "--format", "json", "--source", "payments")
        data = json.loads(out)
        self.assertEqual(data["total_entries"], 2)
        self.assertEqual(data["malformed_lines"], 2)

    def test_report_with_no_matches(self):
        code, out, _ = run("report", SAMPLE_LOG, "--contains", "no such text")
        self.assertEqual(code, 0)
        self.assertIn("No log entries matched.", out)


class GrepCommandTests(unittest.TestCase):
    def count(self, *filters):
        code, out, _ = run("grep", SAMPLE_LOG, *filters, "--count")
        self.assertEqual(code, 0)
        return int(out)

    def test_counts(self):
        self.assertEqual(self.count(), 29)
        self.assertEqual(self.count("--min-level", "ERROR"), 12)
        self.assertEqual(self.count("--min-level", "warn"), 15)
        self.assertEqual(self.count("--source", "payments"), 2)
        self.assertEqual(self.count("--contains", "TIMED OUT"), 4)
        self.assertEqual(self.count("--since", "2026-10-13T10:00:00"), 6)
        self.assertEqual(self.count("--until", "2026-10-13T08:00:02"), 2)
        self.assertEqual(self.count("--since", "2026-10-14"), 0)

    def test_prints_entries(self):
        code, out, _ = run("grep", SAMPLE_LOG, "--min-level", "CRITICAL")
        self.assertEqual(code, 0)
        self.assertEqual(
            out,
            "2026-10-13 09:14:44.873 CRITICAL db: Primary database unreachable, failing over\n",
        )

    def test_multi_line_entries_are_printed_whole(self):
        _, out, _ = run("grep", SAMPLE_LOG, "--source", "api", "--contains", "unhandled")
        self.assertEqual(out.count("Traceback (most recent call last):"), 2)
        self.assertIn("TimeoutError: database unavailable", out)


class InputHandlingTests(unittest.TestCase):
    def test_reads_stdin(self):
        data = "2026-10-13 09:00:00 ERROR a: boom\n2026-10-13 09:00:01 INFO a: fine\n"
        with mock.patch.object(sys, "stdin", io.StringIO(data)):
            code, out, _ = run("grep", "-", "--min-level", "ERROR")
        self.assertEqual(code, 0)
        self.assertEqual(out, "2026-10-13 09:00:00.000 ERROR    a: boom\n")

    def test_missing_file(self):
        code, out, err = run("report", "definitely-missing.log")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("cannot read 'definitely-missing.log'", err)

    def test_directory_instead_of_file(self):
        with tempfile.TemporaryDirectory() as folder:
            code, _, err = run("report", folder)
        self.assertEqual(code, 1)
        self.assertIn("cannot read", err)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "empty.log"
            path.write_text("")
            code, out, _ = run("report", path)
        self.assertEqual(code, 0)
        self.assertIn("No log entries matched.", out)


class UsageErrorTests(unittest.TestCase):
    def test_since_after_until(self):
        code, _, err = run("grep", SAMPLE_LOG, "--since", "2026-10-14", "--until", "2026-10-13")
        self.assertEqual(code, 2)
        self.assertIn("'since' must not be later than 'until'", err)

    def test_invalid_arguments_exit_with_2(self):
        bad_invocations = [
            ("report", SAMPLE_LOG, "--min-level", "LOUD"),
            ("report", SAMPLE_LOG, "--since", "yesterday"),
            ("report", SAMPLE_LOG, "--since", "2026-10-13T10:00:00+01:00"),
            ("report", SAMPLE_LOG, "--top", "0"),
            ("report", SAMPLE_LOG, "--top", "abc"),
            ("report", SAMPLE_LOG, "--burst-window", "nan"),
            ("report", SAMPLE_LOG, "--burst-window", "-5"),
            ("report", SAMPLE_LOG, "--burst-threshold", "0"),
            ("report", SAMPLE_LOG, "--format", "xml"),
            ("report",),
            (),
        ]
        for argv in bad_invocations:
            with self.subTest(argv=argv):
                code, _, err = run_expecting_exit(*argv)
                self.assertEqual(code, 2)
                self.assertIn("usage:", err)

    def test_version(self):
        code, out, _ = run_expecting_exit("--version")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), f"logsleuth {__version__}")

    def test_help_mentions_log_format(self):
        code, out, _ = run_expecting_exit("--help")
        self.assertEqual(code, 0)
        self.assertIn("YYYY-MM-DD HH:MM:SS", out)


class ModuleEntryPointTests(unittest.TestCase):
    def test_python_dash_m(self):
        env = dict(os.environ, PYTHONPATH=str(SRC_DIR))
        completed = subprocess.run(
            [sys.executable, "-m", "logsleuth", "grep", str(SAMPLE_LOG), "--count"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        self.assertEqual(completed.stdout.strip(), "29")


if __name__ == "__main__":
    unittest.main()
