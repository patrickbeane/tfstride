from __future__ import annotations

import unittest

from tfstride.providers.network_ranges import consume_intervals


class NetworkIntervalTests(unittest.TestCase):
    def test_subtraction_conserves_coverage_and_never_duplicates_points(self):
        intervals = [(start, end) for start in range(6) for end in range(start, 6)]
        for start, end in intervals:
            for cut_start, cut_end in intervals:
                with self.subTest(interval=(start, end), cut=(cut_start, cut_end)):
                    matched, remaining = consume_intervals([(start, end)], cut_start, cut_end)
                    selected = {port for lower, upper in matched for port in range(lower, upper + 1)}
                    rest = {port for lower, upper in remaining for port in range(lower, upper + 1)}
                    original = set(range(start, end + 1))
                    self.assertEqual(selected, original & set(range(cut_start, cut_end + 1)))
                    self.assertFalse(selected & rest)
                    self.assertEqual(selected | rest, original)

    def test_boundary_subtraction_does_not_create_out_of_range_intervals(self):
        self.assertEqual(consume_intervals([(0, 65535)], 0, 0), ([(0, 0)], [(1, 65535)]))
        self.assertEqual(consume_intervals([(0, 65535)], 65535, 65535), ([(65535, 65535)], [(0, 65534)]))
        self.assertEqual(consume_intervals([(0, 65535)], 0, 65535), ([(0, 65535)], []))
