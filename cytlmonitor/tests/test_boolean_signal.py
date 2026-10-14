"""Unit tests for cytlmonitor.boolean_signal.BooleanSignal."""

import unittest

from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.interval import Interval


class TestConstruction(unittest.TestCase):

    def test_empty_signal(self):
        sig = BooleanSignal()
        self.assertEqual(sig.length(), 0)

    def test_horizon_defaults_to_zero(self):
        self.assertEqual(BooleanSignal().horizon, 0.0)

    def test_construct_sets_horizon_to_last_end(self):
        sig = BooleanSignal([Interval(0, 5), Interval(7, 10)])
        self.assertEqual(sig.horizon, 10.0)

    def test_construct_from_valid_iterable(self):
        intervals = [
            Interval(0, 5, right_open=True),
            Interval(7, 10, right_open=True),
        ]
        sig = BooleanSignal(intervals)
        self.assertEqual(sig.length(), 2)
        self.assertEqual(sig[0], intervals[0])
        self.assertEqual(sig[1], intervals[1])

    def test_construct_merges_adjacent_intervals(self):
        sig = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(5, 10, right_open=True),
        ])
        self.assertEqual(sig.length(), 1)
        self.assertEqual(sig[0], Interval(0, 10, right_open=True))

    def test_construct_from_invalid_iterable_raises(self):
        intervals = [
            Interval(5, 10, right_open=True),
            Interval(0, 5, right_open=True),
        ]
        with self.assertRaises(ValueError):
            BooleanSignal(intervals)


class TestAdd(unittest.TestCase):

    def test_add_first_interval(self):
        sig = BooleanSignal()
        i = Interval(0, 5, right_open=True)
        sig.add(i)
        self.assertEqual(sig.length(), 1)
        self.assertEqual(sig[0], i)

    def test_add_non_interval_raises_type_error(self):
        sig = BooleanSignal()
        with self.assertRaises(TypeError):
            sig.add((0, 5))

    def test_add_just_before_interval_merges_into_last(self):
        # last is right-open at 5, next is left-closed at 5: they abut, so
        # they are merged into a single interval instead of appended.
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        sig.add(Interval(5, 10, right_open=True))
        self.assertEqual(sig.length(), 1)
        self.assertEqual(sig[0], Interval(0, 10, right_open=True))

    def test_add_just_before_interval_next_left_open_merges_into_last(self):
        # last is right-closed at 5, next is left-open at 5: they abut, so
        # they are merged into a single interval instead of appended.
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=False))
        sig.add(Interval(5, 10, left_open=True, right_open=True))
        self.assertEqual(sig.length(), 1)
        self.assertEqual(sig[0], Interval(0, 10, right_open=True))

    def test_add_merges_repeatedly_across_several_just_before_intervals(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        sig.add(Interval(5, 10, right_open=True))
        sig.add(Interval(10, 15, right_open=True))
        self.assertEqual(sig.length(), 1)
        self.assertEqual(sig[0], Interval(0, 15, right_open=True))

    def test_add_merge_then_gap_keeps_them_as_separate_intervals(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        sig.add(Interval(5, 10, right_open=True))
        sig.add(Interval(12, 20, right_open=True))
        self.assertEqual(sig.length(), 2)
        self.assertEqual(sig[0], Interval(0, 10, right_open=True))
        self.assertEqual(sig[1], Interval(12, 20, right_open=True))

    def test_add_touching_intervals_both_closed_raises(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=False))
        with self.assertRaises(ValueError):
            sig.add(Interval(5, 10, left_open=False, right_open=True))

    def test_add_gap_between_intervals_succeeds(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        sig.add(Interval(7, 10, right_open=True))
        self.assertEqual(sig.length(), 2)

    def test_add_overlapping_interval_raises(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        with self.assertRaises(ValueError):
            sig.add(Interval(3, 10, right_open=True))

    def test_add_after_right_unbounded_interval_raises(self):
        sig = BooleanSignal()
        sig.add(Interval(0))  # right unbounded
        with self.assertRaises(ValueError):
            sig.add(Interval(10, right_open=True))

    def test_right_unbounded_interval_can_be_last(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        sig.add(Interval(7))  # gap between 5 and 7: no merge
        self.assertEqual(sig.length(), 2)
        self.assertTrue(sig[1].is_right_unbounded)

    def test_right_unbounded_interval_just_before_merges_into_last(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        sig.add(Interval(5))  # abuts the last interval: gets merged
        self.assertEqual(sig.length(), 1)
        self.assertTrue(sig[0].is_right_unbounded)
        self.assertEqual(sig[0], Interval(0))

    def test_failed_add_does_not_modify_sequence(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5, right_open=True))
        with self.assertRaises(ValueError):
            sig.add(Interval(3, 10, right_open=True))
        self.assertEqual(sig.length(), 1)


class TestHorizon(unittest.TestCase):

    def test_add_moves_horizon_to_interval_end(self):
        sig = BooleanSignal()
        sig.add(Interval(0, 5))
        self.assertEqual(sig.horizon, 5.0)
        sig.add(Interval(7, 10, right_open=False))
        self.assertEqual(sig.horizon, 10.0)

    def test_add_merging_into_last_moves_horizon(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.add(Interval(5, 8))
        self.assertEqual(sig.length(), 1)
        self.assertEqual(sig.horizon, 8.0)

    def test_add_does_not_move_horizon_back(self):
        sig = BooleanSignal()
        sig.set_horizon(20)
        sig.add(Interval(0, 5))
        self.assertEqual(sig.horizon, 20.0)

    def test_add_right_unbounded_interval_makes_horizon_none(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.add(Interval(7))
        self.assertIsNone(sig.horizon)

    def test_failed_add_does_not_modify_horizon(self):
        sig = BooleanSignal([Interval(0, 5)])
        with self.assertRaises(ValueError):
            sig.add(Interval(3, 10))
        self.assertEqual(sig.horizon, 5.0)

    def test_set_horizon(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.set_horizon(12)
        self.assertEqual(sig.horizon, 12.0)
        self.assertIsInstance(sig.horizon, float)

    def test_set_horizon_can_move_it_back_down_to_last_end(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.set_horizon(12)
        sig.set_horizon(5)
        self.assertEqual(sig.horizon, 5.0)

    def test_set_horizon_to_none(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.set_horizon(None)
        self.assertIsNone(sig.horizon)

    def test_set_horizon_zero_on_empty_signal(self):
        sig = BooleanSignal()
        sig.set_horizon(0)
        self.assertEqual(sig.horizon, 0.0)

    def test_set_horizon_negative_raises_value_error(self):
        sig = BooleanSignal()
        with self.assertRaises(ValueError):
            sig.set_horizon(-1)
        self.assertEqual(sig.horizon, 0.0)

    def test_set_horizon_before_last_end_raises_value_error(self):
        sig = BooleanSignal([Interval(0, 5)])
        with self.assertRaises(ValueError):
            sig.set_horizon(4)
        self.assertEqual(sig.horizon, 5.0)

    def test_set_finite_horizon_after_unbounded_interval_raises_value_error(self):
        sig = BooleanSignal([Interval(0)])
        with self.assertRaises(ValueError):
            sig.set_horizon(100)
        self.assertIsNone(sig.horizon)

    def test_horizon_has_no_setter(self):
        sig = BooleanSignal()
        with self.assertRaises(AttributeError):
            sig.horizon = 5.0


class TestIndexingAndLength(unittest.TestCase):

    def setUp(self):
        self.intervals = [
            Interval(0, 5, right_open=True),
            Interval(7, 10, right_open=True),
            Interval(12, 20, right_open=True),
        ]
        self.sig = BooleanSignal(self.intervals)

    def test_length(self):
        self.assertEqual(self.sig.length(), 3)

    def test_len_matches_length(self):
        self.assertEqual(len(self.sig), self.sig.length())

    def test_getitem_returns_correct_interval(self):
        for i in range(self.sig.length()):
            self.assertEqual(self.sig[i], self.intervals[i])

    def test_getitem_out_of_range_raises_index_error(self):
        with self.assertRaises(IndexError):
            self.sig[self.sig.length()]

    def test_iteration_yields_intervals_in_order(self):
        self.assertEqual(list(self.sig), self.intervals)


class TestComplement(unittest.TestCase):

    def test_single_interval_not_starting_at_zero(self):
        sig = BooleanSignal([Interval(5, 10)])
        self.assertEqual(list(sig.complement()), [Interval(0, 5)])

    def test_trailing_gap_up_to_horizon_is_right_open(self):
        sig = BooleanSignal([Interval(5, 10)])
        sig.set_horizon(15)
        self.assertEqual(list(sig.complement()), [Interval(0, 5), Interval(10, 15)])

    def test_first_interval_starts_at_zero_omits_leading_gap(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.set_horizon(8)
        self.assertEqual(list(sig.complement()), [Interval(5, 8)])

    def test_gap_between_two_intervals_and_trailing_gap(self):
        sig = BooleanSignal([Interval(0, 5), Interval(7, 10)])
        sig.set_horizon(12)
        self.assertEqual(list(sig.complement()), [Interval(5, 7), Interval(10, 12)])

    def test_trailing_gap_is_left_open_after_right_closed_interval(self):
        sig = BooleanSignal([Interval(0, 5, right_open=False)])
        sig.set_horizon(8)
        self.assertEqual(list(sig.complement()), [Interval(5, 8, left_open=True)])

    def test_adjacent_open_intervals_produce_point_gaps(self):
        # (0,5) and (5,10): 5 is excluded from both, and 0 is excluded from
        # the first, so {0} and {5} are isolated "false" instants.
        sig = BooleanSignal([
            Interval(0, 5, left_open=True, right_open=True),
            Interval(5, 10, left_open=True, right_open=True),
        ])
        sig.set_horizon(12)
        self.assertEqual(
            list(sig.complement()),
            [Interval.point(0), Interval.point(5), Interval(10, 12)],
        )

    def test_right_unbounded_interval_has_no_trailing_gap(self):
        sig = BooleanSignal([Interval(5)])
        self.assertEqual(list(sig.complement()), [Interval(0, 5)])

    def test_last_interval_ending_at_horizon_has_no_trailing_gap(self):
        for last in (Interval(0, 5), Interval(0, 5, right_open=False)):
            with self.subTest(last=last):
                self.assertEqual(BooleanSignal([last]).complement().length(), 0)

    def test_unbounded_horizon_gives_unbounded_trailing_gap(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.set_horizon(None)
        self.assertEqual(list(sig.complement()), [Interval(5)])

    def test_empty_signal_with_zero_horizon(self):
        self.assertEqual(BooleanSignal().complement().length(), 0)

    def test_empty_signal_with_horizon(self):
        sig = BooleanSignal()
        sig.set_horizon(5)
        self.assertEqual(list(sig.complement()), [Interval(0, 5)])

    def test_empty_signal_with_unbounded_horizon(self):
        sig = BooleanSignal()
        sig.set_horizon(None)
        self.assertEqual(list(sig.complement()), [Interval(0)])

    def test_complement_keeps_the_horizon(self):
        for horizon in (10, 20, None):
            with self.subTest(horizon=horizon):
                sig = BooleanSignal([Interval(5, 10)])
                sig.set_horizon(horizon)
                self.assertEqual(sig.complement().horizon, horizon)

    def test_double_complement_is_identity(self):
        sig = BooleanSignal([Interval(0, 2, right_open=False), Interval(5, 10)])
        sig.set_horizon(15)
        twice = sig.complement().complement()
        self.assertEqual(list(twice), list(sig))
        self.assertEqual(twice.horizon, sig.horizon)

    def test_double_complement_loses_closed_end_at_horizon(self):
        # The trailing gap is right-open, so a last interval closed exactly
        # at the horizon loses its end point.
        sig = BooleanSignal([Interval(0, 5, right_open=False)])
        self.assertEqual(list(sig.complement().complement()), [Interval(0, 5)])

    def test_complement_does_not_mutate_original_signal(self):
        sig = BooleanSignal([Interval(5, 10)])
        sig.set_horizon(20)
        original = list(sig)
        sig.complement()
        self.assertEqual(list(sig), original)
        self.assertEqual(sig.horizon, 20.0)


class TestUnion(unittest.TestCase):

    def test_union_with_empty_signal(self):
        sig = BooleanSignal()
        other = BooleanSignal([Interval(0, 5, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0, 5, right_open=True)])

    def test_union_of_two_empty_signals(self):
        result = BooleanSignal().union(BooleanSignal())
        self.assertEqual(result.length(), 0)

    def test_union_with_gap_before_all_intervals(self):
        sig = BooleanSignal([Interval(5, 10, right_open=True)])
        other = BooleanSignal([Interval(0, 2, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [
            Interval(0, 2, right_open=True),
            Interval(5, 10, right_open=True),
        ])

    def test_union_with_gap_after_all_intervals(self):
        sig = BooleanSignal([Interval(0, 2, right_open=True)])
        other = BooleanSignal([Interval(5, 10, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [
            Interval(0, 2, right_open=True),
            Interval(5, 10, right_open=True),
        ])

    def test_union_fitting_in_a_gap_stays_separate(self):
        sig = BooleanSignal([
            Interval(0, 2, right_open=True),
            Interval(10, 15, right_open=True),
        ])
        other = BooleanSignal([Interval(5, 7, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [
            Interval(0, 2, right_open=True),
            Interval(5, 7, right_open=True),
            Interval(10, 15, right_open=True),
        ])

    def test_union_overlapping_single_interval_merges(self):
        sig = BooleanSignal([Interval(0, 5, right_open=True)])
        other = BooleanSignal([Interval(3, 10, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0, 10, right_open=True)])

    def test_union_contained_within_existing_interval_is_unchanged(self):
        sig = BooleanSignal([Interval(0, 10, right_open=True)])
        other = BooleanSignal([Interval(3, 5, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0, 10, right_open=True)])

    def test_union_identical_to_existing_interval_is_idempotent(self):
        sig = BooleanSignal([Interval(0, 5, right_open=True)])
        other = BooleanSignal([Interval(0, 5, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0, 5, right_open=True)])

    def test_union_just_before_existing_interval_merges(self):
        sig = BooleanSignal([Interval(5, 10, right_open=True)])
        other = BooleanSignal([Interval(0, 5, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0, 10, right_open=True)])

    def test_union_bridges_two_intervals_across_a_gap(self):
        sig = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(7, 10, right_open=True),
        ])
        other = BooleanSignal([Interval(4, 8, right_open=True)])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0, 10, right_open=True)])

    def test_union_with_right_unbounded_interval_swallows_everything_after(self):
        sig = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(7, 10, right_open=True),
        ])
        other = BooleanSignal([Interval(3)])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0)])
        self.assertTrue(result[0].is_right_unbounded)

    def test_union_of_two_multi_interval_signals_interleaved(self):
        sig = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(10, 15, right_open=True),
        ])
        other = BooleanSignal([
            Interval(6, 8, right_open=True),
            Interval(20, 25, right_open=True),
        ])
        result = sig.union(other)
        self.assertEqual(list(result), [
            Interval(0, 5, right_open=True),
            Interval(6, 8, right_open=True),
            Interval(10, 15, right_open=True),
            Interval(20, 25, right_open=True),
        ])

    def test_union_of_two_multi_interval_signals_overlapping(self):
        sig = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(10, 15, right_open=True),
        ])
        other = BooleanSignal([
            Interval(3, 12, right_open=True),
        ])
        result = sig.union(other)
        self.assertEqual(list(result), [Interval(0, 15, right_open=True)])

    def test_union_horizon_is_max_of_both(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.set_horizon(30)
        other = BooleanSignal([Interval(7, 10)])
        other.set_horizon(20)
        self.assertEqual(sig.union(other).horizon, 30.0)
        self.assertEqual(other.union(sig).horizon, 30.0)

    def test_union_horizon_defaults_to_last_end(self):
        sig = BooleanSignal([Interval(0, 5)])
        other = BooleanSignal([Interval(7, 10)])
        self.assertEqual(sig.union(other).horizon, 10.0)

    def test_union_with_unbounded_horizon(self):
        sig = BooleanSignal([Interval(0, 5)])
        sig.set_horizon(None)
        other = BooleanSignal([Interval(7, 10)])
        self.assertIsNone(sig.union(other).horizon)

    def test_union_of_empty_signals_keeps_max_horizon(self):
        sig = BooleanSignal()
        sig.set_horizon(4)
        self.assertEqual(sig.union(BooleanSignal()).horizon, 4.0)

    def test_union_with_non_boolean_signal_raises_type_error(self):
        sig = BooleanSignal([Interval(0, 5, right_open=True)])
        with self.assertRaises(TypeError):
            sig.union(Interval(0, 5))

    def test_union_does_not_mutate_either_original_signal(self):
        sig = BooleanSignal([Interval(0, 5, right_open=True)])
        other = BooleanSignal([Interval(3, 10, right_open=True)])
        sig_before, other_before = list(sig), list(other)
        sig.union(other)
        self.assertEqual(list(sig), sig_before)
        self.assertEqual(list(other), other_before)


class TestIntersection(unittest.TestCase):

    def test_overlapping_intervals(self):
        a = BooleanSignal([Interval(0, 10, right_open=True)])
        b = BooleanSignal([Interval(5, 15, right_open=True)])
        self.assertEqual(list(a.intersection(b)), [Interval(5, 10, right_open=True)])

    def test_disjoint_intervals_give_empty_result(self):
        a = BooleanSignal([Interval(0, 5, right_open=True)])
        b = BooleanSignal([Interval(10, 15, right_open=True)])
        self.assertEqual(a.intersection(b).length(), 0)

    def test_identical_intervals(self):
        a = BooleanSignal([Interval(0, 5, right_open=True)])
        b = BooleanSignal([Interval(0, 5, right_open=True)])
        self.assertEqual(list(a.intersection(b)), [Interval(0, 5, right_open=True)])

    def test_one_signal_empty_gives_empty_result(self):
        a = BooleanSignal()
        b = BooleanSignal([Interval(0, 5, right_open=True)])
        self.assertEqual(a.intersection(b).length(), 0)

    def test_both_signals_empty_gives_empty_result(self):
        self.assertEqual(BooleanSignal().intersection(BooleanSignal()).length(), 0)

    def test_multi_interval_signal_against_a_spanning_interval(self):
        a = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(10, 15, right_open=True),
        ])
        b = BooleanSignal([Interval(3, 12, right_open=True)])
        self.assertEqual(list(a.intersection(b)), [
            Interval(3, 5, right_open=True),
            Interval(10, 12, right_open=True),
        ])

    def test_intersection_is_symmetric(self):
        a = BooleanSignal([Interval(0, 10, right_open=True)])
        b = BooleanSignal([Interval(5, 15, right_open=True)])
        self.assertEqual(list(a.intersection(b)), list(b.intersection(a)))

    def test_intersection_with_non_boolean_signal_raises_type_error(self):
        a = BooleanSignal([Interval(0, 5, right_open=True)])
        with self.assertRaises(TypeError):
            a.intersection(Interval(0, 5))

    def test_intersection_does_not_mutate_either_original_signal(self):
        a = BooleanSignal([Interval(0, 10, right_open=True)])
        b = BooleanSignal([Interval(5, 15, right_open=True)])
        a_before, b_before = list(a), list(b)
        a.intersection(b)
        self.assertEqual(list(a), a_before)
        self.assertEqual(list(b), b_before)

    def test_intersection_keeps_the_open_and_closed_ends(self):
        a = BooleanSignal([Interval(0, 5, right_open=False)])
        b = BooleanSignal([Interval(5, 10)])
        self.assertEqual(list(a.intersection(b)), [Interval.point(5)])
        c = BooleanSignal([Interval(5, 10, left_open=True)])
        self.assertEqual(a.intersection(c).length(), 0)

    def test_intersection_with_right_unbounded_intervals(self):
        a = BooleanSignal([Interval(0, 2), Interval(4)])
        b = BooleanSignal([Interval(1, 5), Interval(8)])
        self.assertEqual(list(a.intersection(b)), [Interval(1, 2), Interval(4, 5), Interval(8)])

    def test_intersection_does_not_depend_on_the_horizons(self):
        # Beyond the smaller horizon the intervals are taken as they are.
        a = BooleanSignal([Interval(0, 10)])
        b = BooleanSignal([Interval(0, 2)])
        self.assertEqual(list(a.intersection(b)), [Interval(0, 2)])

    def test_intersection_horizon_is_max_of_both(self):
        a = BooleanSignal([Interval(0, 5)])
        a.set_horizon(10)
        b = BooleanSignal([Interval(3, 8)])
        b.set_horizon(20)
        result = a.intersection(b)
        self.assertEqual(list(result), [Interval(3, 5)])
        self.assertEqual(result.horizon, 20.0)
        self.assertEqual(b.intersection(a).horizon, 20.0)

    def test_intersection_with_unbounded_horizon(self):
        a = BooleanSignal([Interval(0, 5)])
        b = BooleanSignal([Interval(3)])
        self.assertIsNone(a.intersection(b).horizon)

    def test_intersection_of_empty_signals_keeps_max_horizon(self):
        a = BooleanSignal()
        a.set_horizon(7)
        self.assertEqual(a.intersection(BooleanSignal()).horizon, 7.0)

    def test_matches_definition_on_random_signals(self):
        import random
        rng = random.Random(0)

        def random_signal():
            sig, x = BooleanSignal(), 0.0
            for _ in range(rng.randint(0, 5)):
                start = x + rng.choice([0, 0.5, 1, 2])
                left_open = rng.random() < 0.5
                if rng.random() < 0.15:
                    try:
                        sig.add(Interval(start, None, left_open=left_open))
                    except ValueError:
                        pass
                    break
                end = start + rng.choice([0, 0.5, 1, 3])
                if end == start:
                    interval = Interval.point(start)
                else:
                    interval = Interval(start, end, left_open=left_open,
                                        right_open=rng.random() < 0.5)
                try:
                    sig.add(interval)
                except ValueError:
                    continue
                x = end
            return sig

        def holds(sig, t):
            return any(i.contains(t) for i in sig)

        for _ in range(500):
            a, b = random_signal(), random_signal()
            result = a.intersection(b)
            points = {0.0, 20.0}
            for i in list(a) + list(b):
                points.add(i.start)
                if i.end is not None:
                    points |= {i.end, (i.start + i.end) / 2}
            for t in points:
                self.assertEqual(holds(result, t), holds(a, t) and holds(b, t))


class TestShift(unittest.TestCase):

    def test_shift_all_intervals_stay_valid(self):
        sig = BooleanSignal([
            Interval(5, 10, right_open=True),
            Interval(20, 25, right_open=True),
        ])
        result = sig.shift(-3)
        self.assertEqual(list(result), [
            Interval(2, 7, right_open=True),
            Interval(17, 22, right_open=True),
        ])

    def test_shift_clips_interval_crossing_zero(self):
        sig = BooleanSignal([
            Interval(0, 10, right_open=True),
            Interval(20, 25, right_open=True),
        ])
        result = sig.shift(-5)
        self.assertEqual(list(result), [
            Interval(0, 5, right_open=True),
            Interval(15, 20, right_open=True),
        ])

    def test_shift_discards_intervals_that_vanish(self):
        sig = BooleanSignal([
            Interval(0, 3, right_open=True),
            Interval(10, 15, right_open=True),
        ])
        result = sig.shift(-10)
        self.assertEqual(list(result), [Interval(0, 5, right_open=True)])

    def test_shift_discards_all_intervals_but_shifts_horizon(self):
        sig = BooleanSignal([Interval(0, 3, right_open=True)])
        sig.set_horizon(50)
        result = sig.shift(-10)
        self.assertEqual(result.length(), 0)
        self.assertEqual(result.horizon, 40.0)

    def test_shift_right_unbounded_last_interval(self):
        sig = BooleanSignal([Interval(0, 5, right_open=True), Interval(10)])
        result = sig.shift(-3)
        self.assertEqual(list(result), [
            Interval(0, 2, right_open=True),
            Interval(7),
        ])
        self.assertTrue(result[-1].is_right_unbounded)

    def test_shift_by_zero_is_unchanged(self):
        sig = BooleanSignal([Interval(5, 10, right_open=True)])
        result = sig.shift(0)
        self.assertEqual(list(result), list(sig))

    def test_shift_empty_signal_shifts_horizon(self):
        sig = BooleanSignal()
        sig.set_horizon(20)
        result = sig.shift(-5)
        self.assertEqual(result.length(), 0)
        self.assertEqual(result.horizon, 15.0)

    def test_shift_forward_moves_horizon_forward(self):
        sig = BooleanSignal([Interval(5, 10)])
        sig.set_horizon(12)
        self.assertEqual(sig.shift(3).horizon, 15.0)

    def test_shift_back_beyond_zero_clips_horizon_at_zero(self):
        sig = BooleanSignal([Interval(5, 10)])
        result = sig.shift(-30)
        self.assertEqual(result.length(), 0)
        self.assertEqual(result.horizon, 0.0)

    def test_shift_preserves_unbounded_horizon(self):
        sig = BooleanSignal([Interval(5)])
        self.assertIsNone(sig.shift(-3).horizon)

    def test_shift_forward(self):
        sig = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(10),
        ])
        result = sig.shift(3)
        self.assertEqual(list(result), [
            Interval(3, 8, right_open=True),
            Interval(13),
        ])

    def test_shift_back_then_forward_is_identity_when_no_clipping(self):
        sig = BooleanSignal([
            Interval(5, 10, right_open=True),
            Interval(20, 25, right_open=True),
        ])
        self.assertEqual(list(sig.shift(-3).shift(3)), list(sig))

    def test_shift_does_not_mutate_original_signal(self):
        sig = BooleanSignal([Interval(5, 10, right_open=True)])
        sig.set_horizon(20)
        original = list(sig)
        sig.shift(-3)
        self.assertEqual(list(sig), original)
        self.assertEqual(sig.horizon, 20.0)


class TestBackward(unittest.TestCase):

    def test_backward_applied_to_each_interval(self):
        sig = BooleanSignal([
            Interval(5, 10, right_open=True),
            Interval(20, 25, right_open=True),
        ])
        result = sig.backward(Interval(1, 3, right_open=True))
        self.assertEqual(list(result), [
            Interval(2, 9, left_open=True, right_open=True),
            Interval(17, 24, left_open=True, right_open=True),
        ])

    def test_backward_joins_overlapping_results(self):
        # A wide i makes the backward() results of two originally separate,
        # non-overlapping intervals overlap each other.
        sig = BooleanSignal([
            Interval(0, 5, right_open=True),
            Interval(10, 15, right_open=True),
        ])
        result = sig.backward(Interval(0, 20, right_open=True))
        self.assertEqual(list(result), [Interval(0, 15, right_open=True)])

    def test_backward_discards_intervals_that_vanish(self):
        sig = BooleanSignal([
            Interval(0, 2, right_open=True),
            Interval(50, 60, right_open=True),
        ])
        result = sig.backward(Interval(30, 40, right_open=True))
        self.assertEqual(list(result), [Interval(10, 30, left_open=True, right_open=True)])

    def test_backward_discards_all_intervals_but_keeps_horizon(self):
        sig = BooleanSignal([Interval(0, 2, right_open=True)])
        sig.set_horizon(100)
        result = sig.backward(Interval(50, 60, right_open=True))
        self.assertEqual(result.length(), 0)
        self.assertEqual(result.horizon, 100.0)

    def test_backward_keeps_horizon(self):
        sig = BooleanSignal([Interval(5, 10, right_open=True)])
        result = sig.backward(Interval(1, 3, right_open=True))
        self.assertEqual(result.horizon, 10.0)

    def test_backward_preserves_unbounded_horizon(self):
        sig = BooleanSignal([Interval(5)])
        self.assertIsNone(sig.backward(Interval(1, 3)).horizon)

    def test_backward_with_non_interval_raises_type_error(self):
        sig = BooleanSignal([Interval(5, 10, right_open=True)])
        with self.assertRaises(TypeError):
            sig.backward((0, 5))

    def test_backward_does_not_mutate_original_signal(self):
        sig = BooleanSignal([Interval(5, 10, right_open=True)])
        sig.set_horizon(20)
        original = list(sig)
        sig.backward(Interval(1, 3, right_open=True))
        self.assertEqual(list(sig), original)
        self.assertEqual(sig.horizon, 20.0)


if __name__ == '__main__':
    unittest.main()
