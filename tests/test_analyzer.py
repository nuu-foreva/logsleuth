import random
import unittest
from datetime import datetime, timedelta

from helpers import BASE_TIME, error_at, make_entry

from logsleuth.analyzer import (
    analyze,
    error_signature,
    filter_entries,
    find_error_bursts,
    hourly_counts,
    summarize,
    top_errors,
)


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.entries = [
            make_entry("2026-10-13 08:00:00", "DEBUG", "cache", "warm"),
            make_entry("2026-10-13 09:00:00", "INFO", "api", "GET /orders"),
            make_entry("2026-10-13 10:00:00", "WARNING", "api", "Slow request"),
            make_entry("2026-10-13 11:00:00", "ERROR", "db", "Connection LOST"),
            make_entry("2026-10-13 12:00:00", "CRITICAL", "db", "Failover"),
        ]

    def messages(self, **criteria):
        return [e.message for e in filter_entries(self.entries, **criteria)]

    def test_no_criteria_keeps_everything(self):
        self.assertEqual(len(filter_entries(self.entries)), 5)

    def test_min_level(self):
        self.assertEqual(self.messages(min_level="ERROR"), ["Connection LOST", "Failover"])
        self.assertEqual(len(filter_entries(self.entries, min_level="debug")), 5)

    def test_min_level_accepts_aliases(self):
        self.assertEqual(self.messages(min_level="WARN")[0], "Slow request")

    def test_unknown_level_raises(self):
        with self.assertRaises(ValueError):
            filter_entries(self.entries, min_level="LOUD")

    def test_source_is_case_insensitive_and_exact(self):
        self.assertEqual(self.messages(source="API"), ["GET /orders", "Slow request"])
        self.assertEqual(self.messages(source="ap"), [])

    def test_contains_is_case_insensitive(self):
        self.assertEqual(self.messages(contains="connection lost"), ["Connection LOST"])

    def test_since_and_until_are_inclusive(self):
        since = datetime(2026, 10, 13, 9, 0, 0)
        until = datetime(2026, 10, 13, 11, 0, 0)
        self.assertEqual(
            self.messages(since=since, until=until),
            ["GET /orders", "Slow request", "Connection LOST"],
        )

    def test_since_after_until_raises(self):
        with self.assertRaises(ValueError):
            filter_entries(
                self.entries,
                since=datetime(2026, 10, 14),
                until=datetime(2026, 10, 13),
            )

    def test_criteria_combine_with_and(self):
        self.assertEqual(self.messages(source="db", min_level="CRITICAL"), ["Failover"])

    def test_works_on_generators(self):
        self.assertEqual(len(filter_entries(iter(self.entries), min_level="ERROR")), 2)


class SummaryTests(unittest.TestCase):
    def test_empty(self):
        summary = summarize([])
        self.assertEqual(summary.total, 0)
        self.assertEqual(summary.error_rate, 0.0)
        self.assertIsNone(summary.first_timestamp)
        self.assertIsNone(summary.span)
        self.assertEqual(list(summary.by_level), ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.assertTrue(all(count == 0 for count in summary.by_level.values()))

    def test_counts_and_range(self):
        entries = [
            make_entry("2026-10-13 12:00:00", "ERROR", "db"),
            make_entry("2026-10-13 08:00:00", "INFO", "api"),
            make_entry("2026-10-13 09:00:00", "INFO", "api"),
            make_entry("2026-10-13 10:00:00", "CRITICAL", "auth"),
        ]
        summary = summarize(entries)
        self.assertEqual(summary.total, 4)
        self.assertEqual(summary.by_level["INFO"], 2)
        self.assertEqual(summary.by_level["WARNING"], 0)
        self.assertEqual(summary.error_count, 2)
        self.assertAlmostEqual(summary.error_rate, 0.5)
        self.assertEqual(summary.first_timestamp, datetime(2026, 10, 13, 8))
        self.assertEqual(summary.last_timestamp, datetime(2026, 10, 13, 12))
        self.assertEqual(summary.span, timedelta(hours=4))

    def test_sources_sorted_by_count_then_name(self):
        entries = [
            make_entry(source="b"),
            make_entry(source="a"),
            make_entry(source="c"),
            make_entry(source="c"),
        ]
        self.assertEqual(list(summarize(entries).by_source.items()), [("c", 2), ("a", 1), ("b", 1)])

    def test_non_canonical_level_is_normalised(self):
        summary = summarize([make_entry(level="WARN")])
        self.assertEqual(summary.by_level["WARNING"], 1)


class SignatureTests(unittest.TestCase):
    def test_numbers_ips_hex_and_uuids_are_masked(self):
        self.assertEqual(
            error_signature("Timeout after 5000ms (host=10.0.0.12)"),
            "Timeout after <n>ms (host=<ip>)",
        )
        self.assertEqual(error_signature("Bad pointer 0xDEADBEEF"), "Bad pointer <hex>")
        self.assertEqual(
            error_signature("Order 123e4567-e89b-12d3-a456-426614174000 failed"),
            "Order <uuid> failed",
        )
        self.assertEqual(error_signature("retry 3 of 5"), "retry <n> of <n>")

    def test_ip_with_port(self):
        self.assertEqual(error_signature("connect 10.0.0.1:5432"), "connect <ip>:<n>")

    def test_words_containing_digits_are_kept(self):
        self.assertEqual(error_signature("user42 failed"), "user42 failed")

    def test_only_first_non_empty_line_is_used(self):
        self.assertEqual(error_signature("\n  Boom 7\nTraceback ..."), "Boom <n>")

    def test_empty_message(self):
        self.assertEqual(error_signature(""), "")


class TopErrorsTests(unittest.TestCase):
    def test_groups_similar_errors_and_orders_by_count(self):
        entries = [
            error_at(0, source="db", message="Timeout after 100ms"),
            error_at(10, source="db", message="Timeout after 250ms"),
            error_at(20, source="api", message="Boom"),
            error_at(30, source="db", message="Timeout after 300ms"),
            make_entry(level="INFO", source="db", message="Timeout after 1ms"),
        ]
        groups = top_errors(entries)
        self.assertEqual([(g.source, g.signature, g.count) for g in groups],
                         [("db", "Timeout after <n>ms", 3), ("api", "Boom", 1)])
        self.assertEqual(groups[0].first_seen, BASE_TIME)
        self.assertEqual(groups[0].last_seen, BASE_TIME + timedelta(seconds=30))

    def test_same_message_from_different_sources_is_separate(self):
        entries = [error_at(0, source="a", message="x"), error_at(1, source="b", message="x")]
        self.assertEqual(len(top_errors(entries)), 2)

    def test_ties_are_broken_by_first_seen(self):
        entries = [error_at(5, message="later"), error_at(1, message="earlier")]
        self.assertEqual([g.signature for g in top_errors(entries)], ["earlier", "later"])

    def test_limit(self):
        entries = [error_at(i, message=f"m{'x' * i}") for i in range(4)]
        self.assertEqual(len(top_errors(entries, limit=2)), 2)

    def test_invalid_limit(self):
        with self.assertRaises(ValueError):
            top_errors([], limit=0)

    def test_no_errors(self):
        self.assertEqual(top_errors([make_entry()]), [])


class BurstTests(unittest.TestCase):
    def test_detects_a_burst(self):
        entries = [error_at(s) for s in (0, 1, 2, 3, 4)]
        bursts = find_error_bursts(entries, window_seconds=10, threshold=5)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0].count, 5)
        self.assertEqual(bursts[0].start, BASE_TIME)
        self.assertEqual(bursts[0].end, BASE_TIME + timedelta(seconds=4))

    def test_below_threshold_is_not_a_burst(self):
        entries = [error_at(s) for s in (0, 1, 2, 3)]
        self.assertEqual(find_error_bursts(entries, window_seconds=10, threshold=5), [])

    def test_errors_spread_beyond_the_window_are_not_a_burst(self):
        entries = [error_at(s) for s in (0, 20, 40, 60, 80)]
        self.assertEqual(find_error_bursts(entries, window_seconds=10, threshold=2), [])

    def test_two_separate_bursts(self):
        entries = [error_at(s) for s in (0, 1, 2, 500, 501, 502)]
        bursts = find_error_bursts(entries, window_seconds=10, threshold=3)
        self.assertEqual([b.count for b in bursts], [3, 3])

    def test_unsorted_input(self):
        entries = [error_at(s) for s in (4, 0, 3, 1, 2)]
        bursts = find_error_bursts(entries, window_seconds=10, threshold=5)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0].start, BASE_TIME)

    def test_only_errors_and_critical_count(self):
        entries = [error_at(0, level="WARNING"), error_at(1, level="INFO")]
        entries += [error_at(2), error_at(3, level="CRITICAL")]
        self.assertEqual(find_error_bursts(entries, window_seconds=10, threshold=3), [])
        self.assertEqual(len(find_error_bursts(entries, window_seconds=10, threshold=2)), 1)

    def test_bursts_do_not_overlap(self):
        entries = [error_at(s) for s in range(10)]
        bursts = find_error_bursts(entries, window_seconds=4, threshold=3)
        self.assertEqual([b.count for b in bursts], [5, 5])
        self.assertLess(bursts[0].end, bursts[1].start)

    def test_window_boundary_is_inclusive(self):
        entries = [error_at(0), error_at(10)]
        self.assertEqual(len(find_error_bursts(entries, window_seconds=10, threshold=2)), 1)
        self.assertEqual(len(find_error_bursts(entries, window_seconds=9.99, threshold=2)), 0)

    def test_threshold_of_one_reports_isolated_errors(self):
        entries = [error_at(0), error_at(100)]
        self.assertEqual(len(find_error_bursts(entries, window_seconds=10, threshold=1)), 2)

    def test_invalid_arguments(self):
        for window in (0, -1, float("nan"), float("inf"), 1e30):
            with self.subTest(window=window), self.assertRaises(ValueError):
                find_error_bursts([], window_seconds=window)
        with self.assertRaises(ValueError):
            find_error_bursts([], threshold=0)

    def test_empty_input(self):
        self.assertEqual(find_error_bursts([]), [])

    def test_matches_a_brute_force_reference_on_random_data(self):
        def reference(times, window, threshold):
            times = sorted(times)
            found, i = [], 0
            while i < len(times):
                group = [t for t in times[i:] if t - times[i] <= window]
                if len(group) >= threshold:
                    found.append((group[0], group[-1], len(group)))
                    i += len(group)
                else:
                    i += 1
            return found

        rng = random.Random(7)
        levels = ["INFO", "WARNING", "ERROR", "CRITICAL"]
        for _ in range(300):
            entries = [
                error_at(rng.randint(0, 120) / 2, level=rng.choice(levels))
                for _ in range(rng.randint(0, 40))
            ]
            window = rng.choice([1, 5, 10, 60])
            threshold = rng.randint(1, 6)
            expected = reference(
                [e.timestamp for e in entries if e.rank >= 3],
                timedelta(seconds=window),
                threshold,
            )
            actual = [
                (b.start, b.end, b.count) for b in find_error_bursts(entries, window, threshold)
            ]
            self.assertEqual(actual, expected)


class HourlyTests(unittest.TestCase):
    def test_counts_per_hour(self):
        entries = [
            make_entry("2026-10-13 08:10:00"),
            make_entry("2026-10-13 08:59:59"),
            make_entry("2026-10-14 13:00:00"),
        ]
        counts = hourly_counts(entries)
        self.assertEqual(len(counts), 24)
        self.assertEqual(counts[8], 2)
        self.assertEqual(counts[13], 1)
        self.assertEqual(sum(counts), 3)


class AnalyzeTests(unittest.TestCase):
    def test_bundles_every_analysis(self):
        entries = [error_at(s, message="Boom") for s in range(5)] + [make_entry()]
        report = analyze(entries, malformed=2, top=3, burst_window=30, burst_threshold=4)
        self.assertEqual(report.summary.total, 6)
        self.assertEqual(report.malformed, 2)
        self.assertEqual(report.top_errors[0].count, 5)
        self.assertEqual(report.bursts[0].count, 5)
        self.assertEqual(sum(report.hourly), 6)
        self.assertEqual((report.burst_window, report.burst_threshold), (30, 4))

    def test_empty(self):
        report = analyze([])
        self.assertEqual(report.summary.total, 0)
        self.assertEqual(report.top_errors, [])
        self.assertEqual(report.bursts, [])


if __name__ == "__main__":
    unittest.main()
