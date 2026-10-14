"""Unit tests for cytlmonitor.interval.Interval."""

import unittest

import numpy as np

from cytlmonitor.interval import Interval


class TestIntervalConstruction(unittest.TestCase):

    def test_default_is_left_closed_right_open(self):
        i = Interval(1, 5)
        self.assertEqual(i.start, 1.0)
        self.assertEqual(i.end, 5.0)
        self.assertFalse(i.left_open)
        self.assertTrue(i.right_open)

    def test_values_are_stored_as_float(self):
        i = Interval(1, 5)
        self.assertIsInstance(i.start, float)
        self.assertIsInstance(i.end, float)

    def test_to_none_is_right_unbounded_and_right_open(self):
        i = Interval(2)
        self.assertIsNone(i.end)
        self.assertTrue(i.is_right_unbounded)
        self.assertTrue(i.right_open)

    def test_to_none_ignores_explicit_right_open_false(self):
        i = Interval(2, right_open=False)
        self.assertTrue(i.right_open)

    def test_left_open_and_right_open_flags_are_kept(self):
        i = Interval(1, 5, left_open=True, right_open=True)
        self.assertTrue(i.left_open)
        self.assertTrue(i.right_open)

    def test_to_smaller_than_from_raises(self):
        with self.assertRaises(ValueError):
            Interval(5, 1)

    def test_degenerate_open_interval_raises(self):
        with self.assertRaises(ValueError):
            Interval(5, 5, left_open=True, right_open=False)
        with self.assertRaises(ValueError):
            Interval(5, 5, left_open=False, right_open=True)

    def test_default_call_with_equal_bounds_raises(self):
        # right_open defaults to True, so from_ == to is degenerate unless
        # both sides are explicitly closed (see Interval.point).
        with self.assertRaises(ValueError):
            Interval(5, 5)

    def test_point_classmethod(self):
        i = Interval.point(3)
        self.assertEqual(i, Interval(3, 3, left_open=False, right_open=False))


class TestEndNoneImpliesRightOpen(unittest.TestCase):
    """Invariant: for every Interval, end is None implies right_open is True."""

    def test_default_construction(self):
        self.assertTrue(Interval(3).right_open)

    def test_construction_with_right_open_explicitly_false(self):
        # Even an explicit right_open=False is overridden when end is None.
        self.assertTrue(Interval(3, right_open=False).right_open)

    def test_construction_with_right_open_explicitly_true(self):
        self.assertTrue(Interval(3, right_open=True).right_open)

    def test_construction_battery_over_left_open_and_right_open(self):
        for start in (-5, 0, 3.5, 100):
            for left_open in (True, False):
                for right_open in (True, False):
                    i = Interval(start, None, left_open=left_open, right_open=right_open)
                    self.assertIsNone(i.end)
                    self.assertTrue(i.right_open)

    def test_join_producing_a_right_unbounded_interval(self):
        j = Interval(0, 5, right_open=True).join(Interval(3))
        self.assertIsNone(j.end)
        self.assertTrue(j.right_open)

    def test_join_of_two_right_unbounded_intervals(self):
        j = Interval(5).join(Interval(0, 10, right_open=True))
        self.assertIsNone(j.end)
        self.assertTrue(j.right_open)


class TestIsPoint(unittest.TestCase):

    def test_point_interval(self):
        self.assertTrue(Interval(4, 4, left_open=False, right_open=False).is_point)

    def test_not_a_point_when_bounds_differ(self):
        self.assertFalse(Interval(1, 5).is_point)

    def test_not_a_point_when_right_unbounded(self):
        self.assertFalse(Interval(4).is_point)

    def test_not_a_point_when_equal_but_not_closed(self):
        # left/right_open can't both hold with from_ == to (raises), so this
        # only exercises the property's own guard logic via equal bounds.
        self.assertTrue(Interval(4, 4, left_open=False, right_open=False).is_point)


class TestContains(unittest.TestCase):

    def test_closed_interval_includes_bounds(self):
        i = Interval(0, 10, right_open=False)
        self.assertIn(0, i)
        self.assertIn(10, i)
        self.assertIn(5, i)
        self.assertNotIn(-1, i)
        self.assertNotIn(11, i)

    def test_default_interval_excludes_to(self):
        i = Interval(0, 10)
        self.assertIn(0, i)
        self.assertIn(9.9999, i)
        self.assertNotIn(10, i)

    def test_left_open_excludes_from(self):
        i = Interval(0, 10, left_open=True, right_open=False)
        self.assertNotIn(0, i)
        self.assertIn(0.0001, i)
        self.assertIn(10, i)

    def test_right_open_excludes_to(self):
        i = Interval(0, 10, right_open=True)
        self.assertIn(0, i)
        self.assertIn(9.9999, i)
        self.assertNotIn(10, i)

    def test_open_on_both_sides(self):
        i = Interval(0, 10, left_open=True, right_open=True)
        self.assertNotIn(0, i)
        self.assertNotIn(10, i)
        self.assertIn(5, i)

    def test_right_unbounded_interval(self):
        i = Interval(3)
        self.assertNotIn(2.999, i)
        self.assertIn(3, i)
        self.assertIn(1_000_000, i)

    def test_right_unbounded_interval_left_open(self):
        i = Interval(3, left_open=True)
        self.assertNotIn(3, i)
        self.assertIn(3.001, i)

    def test_point_interval_contains_only_its_value(self):
        i = Interval.point(7)
        self.assertIn(7, i)
        self.assertNotIn(6.999, i)
        self.assertNotIn(7.001, i)

    def test_contains_method_matches_in_operator(self):
        i = Interval(0, 10)
        self.assertTrue(i.contains(5))
        self.assertFalse(i.contains(-5))


class TestComplement(unittest.TestCase):

    def test_none_when_t_is_contained_in_self(self):
        self.assertIsNone(Interval(5, 10).complement(7))
        self.assertIsNone(Interval(5, 10).complement(5))  # left-closed, includes 5

    def test_none_when_t_equals_start_and_both_left_open(self):
        # self is (5, 10): 5 is excluded. open_left=True at t=5 would give
        # the empty interval (5, 5), so None is returned instead.
        self.assertIsNone(Interval(5, 10, left_open=True).complement(5, open_left=True))

    def test_point_interval_when_t_equals_open_start_with_open_left_false(self):
        # self is (5, 10), open_left=False at t=5 gives the point [5, 5].
        result = Interval(5, 10, left_open=True).complement(5, open_left=False)
        self.assertEqual(result, Interval.point(5))

    def test_raises_when_t_is_after_self_start_but_not_contained(self):
        # self is [5, 10) (10 excluded); t=10 is past self's start and not
        # contained in self.
        with self.assertRaises(ValueError):
            Interval(5, 10, right_open=True).complement(10)

    def test_raises_when_t_is_well_past_self(self):
        with self.assertRaises(ValueError):
            Interval(5, 10).complement(20)

    def test_raises_when_t_is_negative(self):
        with self.assertRaises(ValueError):
            Interval(5, 10).complement(-1)

    def test_self_left_closed_open_left_false_gives_right_open(self):
        # self is [a, b): complement is [t, a).
        for self_interval in (
            Interval(5, 10, right_open=True),
            Interval(5, 10, right_open=False),
            Interval(5),  # [5, +inf)
        ):
            result = self_interval.complement(2, open_left=False)
            self.assertEqual(result, Interval(2, 5, left_open=False, right_open=True))

    def test_self_left_open_open_left_false_gives_right_closed(self):
        # self is (a, b): complement is [t, a].
        for self_interval in (
            Interval(5, 10, left_open=True, right_open=True),
            Interval(5, 10, left_open=True, right_open=False),
            Interval(5, left_open=True),  # (5, +inf)
        ):
            result = self_interval.complement(2, open_left=False)
            self.assertEqual(result, Interval(2, 5, left_open=False, right_open=False))

    def test_self_left_closed_open_left_true_gives_right_open(self):
        # self is [a, b): complement is (t, a).
        result = Interval(5, 10, right_open=True).complement(2, open_left=True)
        self.assertEqual(result, Interval(2, 5, left_open=True, right_open=True))

    def test_self_left_open_open_left_true_gives_right_closed(self):
        # self is (a, b): complement is (t, a].
        result = Interval(5, 10, left_open=True, right_open=True).complement(2, open_left=True)
        self.assertEqual(result, Interval(2, 5, left_open=True, right_open=False))

    def test_complement_abuts_self_without_overlap_or_gap(self):
        # The complement is disjoint from self (so they never intersect()), but
        # exactly one of the two must include the shared boundary point.
        for self_interval in (
            Interval(5, 10, right_open=True),
            Interval(5, 10, left_open=True, right_open=True),
        ):
            gap = self_interval.complement(0)
            self.assertEqual(gap.end, self_interval.start)
            self.assertFalse(gap.intersect(self_interval))
            gap_includes_boundary = not gap.right_open
            self_includes_boundary = not self_interval.left_open
            self.assertNotEqual(gap_includes_boundary, self_includes_boundary)


class TestShift(unittest.TestCase):

    def test_shift_by_zero_returns_equal_interval(self):
        original = Interval(5, 10, right_open=True)
        self.assertEqual(original.shift(0), original)

    def test_shift_does_not_mutate_original(self):
        original = Interval(5, 10, right_open=True)
        original.shift(-2)
        original.shift(3)
        self.assertEqual(original, Interval(5, 10, right_open=True))

    def test_back_then_forward_is_identity_when_no_clipping(self):
        original = Interval(5, 10, right_open=True)
        self.assertEqual(original.shift(3).shift(-3), original)

    # Negative t: moves the interval back.

    def test_back_bounded_interval(self):
        result = Interval(5, 10, right_open=True).shift(-2)
        self.assertEqual(result, Interval(3, 8, right_open=True))

    def test_back_preserves_open_closed_flags(self):
        result = Interval(5, 10, left_open=True, right_open=False).shift(-2)
        self.assertEqual(result, Interval(3, 8, left_open=True, right_open=False))

    def test_back_right_unbounded_interval(self):
        result = Interval(5, left_open=True).shift(-2)
        self.assertEqual(result, Interval(3, left_open=True))
        self.assertTrue(result.is_right_unbounded)

    def test_back_to_exactly_zero_is_valid(self):
        result = Interval(5, 10, right_open=True).shift(-5)
        self.assertEqual(result, Interval(0, 5, right_open=True))

    def test_back_with_negative_start_returns_positive_part(self):
        # shifted would be [-1, 4); the positive part is [0, 4).
        result = Interval(5, 10, right_open=True).shift(-6)
        self.assertEqual(result, Interval(0, 4, right_open=True))

    def test_back_with_negative_start_unbounded_interval(self):
        # shifted would be (-2, +inf); the positive part is [0, +inf).
        result = Interval(3, left_open=True).shift(-5)
        self.assertEqual(result, Interval(0))

    def test_back_ending_exactly_at_zero_closed_gives_point(self):
        # shifted would be [-5, 0]; the positive part is the point {0}.
        result = Interval(5, 10, right_open=False).shift(-10)
        self.assertEqual(result, Interval.point(0.0))

    def test_back_ending_exactly_at_zero_open_returns_none(self):
        # shifted would be [-5, 0); 0 itself is excluded, so nothing is left.
        result = Interval(5, 10, right_open=True).shift(-10)
        self.assertIsNone(result)

    def test_back_entirely_negative_returns_none(self):
        # shifted would be [-6, -1): entirely negative.
        self.assertIsNone(Interval(5, 10, right_open=True).shift(-11))

    def test_back_point_interval(self):
        result = Interval.point(5).shift(-2)
        self.assertEqual(result, Interval.point(3))

    def test_back_point_interval_to_exactly_zero(self):
        result = Interval.point(5).shift(-5)
        self.assertEqual(result, Interval.point(0.0))

    def test_back_point_interval_past_zero_returns_none(self):
        self.assertIsNone(Interval.point(5).shift(-6))

    # Positive t: moves the interval forward.

    def test_forward_bounded_interval(self):
        result = Interval(5, 10, right_open=True).shift(3)
        self.assertEqual(result, Interval(8, 13, right_open=True))

    def test_forward_preserves_open_closed_flags(self):
        result = Interval(5, 10, left_open=True, right_open=False).shift(3)
        self.assertEqual(result, Interval(8, 13, left_open=True, right_open=False))

    def test_forward_right_unbounded_interval(self):
        result = Interval(5, left_open=True).shift(3)
        self.assertEqual(result, Interval(8, left_open=True))
        self.assertTrue(result.is_right_unbounded)

    def test_forward_point_interval(self):
        result = Interval.point(5).shift(3)
        self.assertEqual(result, Interval.point(8))

    def test_forward_from_zero(self):
        result = Interval(0, 5, right_open=True).shift(2)
        self.assertEqual(result, Interval(2, 7, right_open=True))

    def test_forward_is_never_none(self):
        # Moving forward can never produce an invalid interval.
        result = Interval(5, 10, right_open=True).shift(1000)
        self.assertIsInstance(result, Interval)


def _exists_witness(self_i: Interval, i_i: Interval, t: float) -> bool:
    """Brute-force check of the defining property of ``backward``: whether
    there is a ``t'`` with ``i_i.contains(t')`` and ``self_i.contains(t +
    t')``. Samples a dense NumPy grid over ``i_i`` (plus its exact
    endpoints) as candidate ``t'`` values."""
    lo = i_i.start
    hi = i_i.end if i_i.end is not None else lo + 50.0
    grid = np.linspace(lo, hi, 2001)
    candidates = np.union1d(grid, [i_i.start] if i_i.end is None else [i_i.start, i_i.end])
    return bool(any(i_i.contains(tp) and self_i.contains(t + tp) for tp in candidates))


class TestBackward(unittest.TestCase):

    def test_default_right_open_intervals(self):
        # Both sides are open in the result because i is right-open (so it
        # never actually reaches i.end, which is paired with self.start)
        # and self is right-open (paired with i.start).
        result = Interval(5, 10, right_open=True).backward(Interval(1, 3, right_open=True))
        self.assertEqual(result, Interval(2, 9, left_open=True, right_open=True))

    def test_start_openness_comes_from_i_right_open_not_i_left_open(self):
        # self is fully closed, but i is right-open: new_start pairs with
        # i.end, so the result is still open there.
        result = Interval(5, 10, right_open=False).backward(Interval(1, 3, right_open=True))
        self.assertEqual(result, Interval(2, 9, left_open=True, right_open=False))

    def test_end_openness_comes_from_i_left_open_not_i_right_open(self):
        # self is fully closed, but i is left-open: new_end pairs with
        # i.start, so the result is open there instead.
        result = Interval(5, 10, right_open=False).backward(
            Interval(1, 3, left_open=True, right_open=False)
        )
        self.assertEqual(result, Interval(2, 9, right_open=True))

    def test_self_start_below_i_end_clips_new_start_to_zero(self):
        result = Interval(0, 10, right_open=True).backward(Interval(2, 4, right_open=True))
        self.assertEqual(result, Interval(0, 8, right_open=True))

    def test_both_closed(self):
        result = Interval(5, 10, right_open=False).backward(Interval(0, 3, right_open=False))
        self.assertEqual(result, Interval(2, 10, right_open=False))

    def test_both_open(self):
        result = Interval(5, 10, left_open=True, right_open=True).backward(
            Interval(0, 3, left_open=True, right_open=True)
        )
        self.assertEqual(result, Interval(2, 10, left_open=True, right_open=True))

    def test_i_right_unbounded(self):
        result = Interval(5, 10, right_open=True).backward(Interval(1))
        self.assertEqual(result, Interval(0, 9, right_open=True))

    def test_point_intervals(self):
        result = Interval.point(3).backward(Interval.point(1))
        self.assertEqual(result, Interval.point(2))

    def test_none_when_new_end_negative(self):
        result = Interval(0, 2, right_open=True).backward(Interval(10, 15, right_open=True))
        self.assertIsNone(result)

    def test_none_when_clipped_result_is_degenerate_and_open(self):
        # new_start clips from -5 to 0, new_end is exactly 0, and
        # new_right_open ends up True: the result would be empty.
        result = Interval(3, 5, right_open=True).backward(Interval(5, 8, right_open=True))
        self.assertIsNone(result)

    def test_self_right_unbounded(self):
        # new_start pairs with i.end, and i is right-open, so the result
        # is open at its (only) bound too.
        result = Interval(5).backward(Interval(1, 3, right_open=True))
        self.assertEqual(result, Interval(2, left_open=True))

    def test_identity_like_case(self):
        result = Interval(0, 5, right_open=True).backward(Interval(0, 5, right_open=True))
        self.assertEqual(result, Interval(0, 5, right_open=True))

    def test_backward_with_non_interval_raises_type_error(self):
        with self.assertRaises(TypeError):
            Interval(0, 5).backward((0, 5))

    def test_backward_does_not_mutate_operands(self):
        self_interval = Interval(5, 10, right_open=True)
        i_interval = Interval(1, 3, right_open=True)
        self_interval.backward(i_interval)
        self.assertEqual(self_interval, Interval(5, 10, right_open=True))
        self.assertEqual(i_interval, Interval(1, 3, right_open=True))


class TestBackwardMatchesDefinition(unittest.TestCase):
    """Property-based check: backward()'s result must agree with the
    existential definition given in its docstring, verified by brute force
    over a dense NumPy grid of candidate t and t' values."""

    CONFIGS = [
        (Interval(5, 10, right_open=True), Interval(1, 3, right_open=True)),
        (Interval(5, 10, right_open=False), Interval(1, 3, right_open=True)),
        (Interval(5, 10, right_open=False), Interval(1, 3, left_open=True, right_open=False)),
        (Interval(0, 10, right_open=True), Interval(2, 4, right_open=True)),
        (Interval(5, 10, right_open=False), Interval(0, 3, right_open=False)),
        (Interval(5, 10, left_open=True, right_open=True), Interval(0, 3, left_open=True, right_open=True)),
        (Interval(5, 10, right_open=True), Interval(1)),
        (Interval(5), Interval(1, 3, right_open=True)),
        (Interval.point(3), Interval.point(1)),
        (Interval(0, 2, right_open=True), Interval(10, 15, right_open=True)),
        (Interval(3, 5, right_open=True), Interval(5, 8, right_open=True)),
        (Interval(0, 5, right_open=True), Interval(0, 5, right_open=True)),
    ]

    def test_backward_matches_definition_on_a_dense_grid(self):
        for self_i, i_i in self.CONFIGS:
            with self.subTest(self_i=self_i, i_i=i_i):
                res = self_i.backward(i_i)

                boundaries = [0.0]
                if res is not None:
                    boundaries.append(res.start)
                    if res.end is not None:
                        boundaries.append(res.end)
                span_end = max(boundaries) + 5.0
                t_grid = np.union1d(np.linspace(0.0, span_end, 300), boundaries)

                for t in t_grid:
                    expected = _exists_witness(self_i, i_i, float(t))
                    actual = res.contains(t) if res is not None else False
                    self.assertEqual(
                        actual, expected,
                        f"mismatch at t={t} for self={self_i!r}, i={i_i!r}: "
                        f"res={res!r}"
                    )


class TestIntersect(unittest.TestCase):

    def test_overlapping_intervals_intersect(self):
        self.assertTrue(Interval(0, 10).intersect(Interval(5, 15)))
        self.assertTrue(Interval(5, 15).intersect(Interval(0, 10)))

    def test_one_interval_contained_in_the_other_intersect(self):
        self.assertTrue(Interval(0, 10).intersect(Interval(2, 5)))

    def test_disjoint_intervals_do_not_intersect(self):
        self.assertFalse(Interval(0, 5).intersect(Interval(7, 10)))

    def test_adjacent_intervals_open_at_shared_point_do_not_intersect(self):
        self.assertFalse(Interval(0, 5).intersect(Interval(5, 10)))

    def test_adjacent_intervals_closed_at_shared_point_intersect(self):
        self.assertTrue(Interval(0, 5, right_open=False).intersect(Interval(5, 10)))

    def test_shared_point_excluded_by_left_open_does_not_intersect(self):
        self.assertFalse(
            Interval(0, 5, right_open=False).intersect(Interval(5, 10, left_open=True))
        )

    def test_point_intervals(self):
        self.assertTrue(Interval.point(5).intersect(Interval.point(5)))
        self.assertFalse(Interval.point(5).intersect(Interval.point(6)))
        self.assertTrue(Interval.point(5).intersect(Interval(0, 10)))
        self.assertFalse(Interval.point(10).intersect(Interval(0, 10)))

    def test_right_unbounded_intervals(self):
        self.assertTrue(Interval(5).intersect(Interval(10)))
        self.assertTrue(Interval(3).intersect(Interval(0, 5)))
        self.assertFalse(Interval(5, left_open=True).intersect(Interval(0, 5)))

    def test_intersect_is_symmetric(self):
        a, b = Interval(0, 5, right_open=False), Interval(5, 10, left_open=True)
        self.assertEqual(a.intersect(b), b.intersect(a))

    def test_intersect_with_non_interval_raises_type_error(self):
        with self.assertRaises(TypeError):
            Interval(0, 5).intersect((0, 5))


class TestIntersection(unittest.TestCase):

    def test_overlapping_intervals(self):
        self.assertEqual(Interval(0, 10).intersection(Interval(5, 15)), Interval(5, 10))
        self.assertEqual(Interval(5, 15).intersection(Interval(0, 10)), Interval(5, 10))

    def test_contained_interval(self):
        self.assertEqual(Interval(0, 10).intersection(Interval(2, 5)), Interval(2, 5))

    def test_disjoint_intervals_give_none(self):
        self.assertIsNone(Interval(0, 5).intersection(Interval(7, 10)))
        self.assertIsNone(Interval(0, 5).intersection(Interval(5, 10)))

    def test_shared_closed_point(self):
        self.assertEqual(
            Interval(0, 5, right_open=False).intersection(Interval(5, 10)), Interval.point(5)
        )

    def test_open_side_wins_on_equal_bounds(self):
        a = Interval(0, 5, left_open=True, right_open=False)
        b = Interval(0, 5, left_open=False, right_open=True)
        self.assertEqual(a.intersection(b), Interval(0, 5, left_open=True, right_open=True))
        self.assertEqual(b.intersection(a), Interval(0, 5, left_open=True, right_open=True))

    def test_right_unbounded_intervals(self):
        self.assertEqual(Interval(3).intersection(Interval(5)), Interval(5))
        self.assertEqual(Interval(3).intersection(Interval(0, 6, right_open=False)),
                         Interval(3, 6, right_open=False))

    def test_intersection_contains_exactly_the_common_values(self):
        intervals = [Interval(0, 5), Interval(0, 5, right_open=False), Interval(5, 10),
                     Interval(5, 10, left_open=True), Interval.point(5), Interval(3),
                     Interval(7, left_open=True), Interval(2, 8, left_open=True)]
        points = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2.5, 7.5]
        for a in intervals:
            for b in intervals:
                with self.subTest(a=a, b=b):
                    c = a.intersection(b)
                    for t in points:
                        expected = a.contains(t) and b.contains(t)
                        self.assertEqual(c is not None and c.contains(t), expected)

    def test_intersection_with_non_interval_raises_type_error(self):
        with self.assertRaises(TypeError):
            Interval(0, 5).intersection((0, 5))


class TestIsBefore(unittest.TestCase):

    def test_interval_ending_before_start_is_before(self):
        self.assertTrue(Interval(0, 5).is_before(Interval(7, 10)))
        self.assertTrue(Interval(0, 5, right_open=False).is_before(Interval(7, 10)))

    def test_later_interval_is_not_before(self):
        self.assertFalse(Interval(7, 10).is_before(Interval(0, 5)))

    def test_overlapping_intervals_are_not_before(self):
        self.assertFalse(Interval(0, 10).is_before(Interval(5, 15)))
        self.assertFalse(Interval(5, 15).is_before(Interval(0, 10)))

    def test_contained_interval_is_not_before(self):
        self.assertFalse(Interval(2, 5).is_before(Interval(0, 10)))

    def test_shared_point_excluded_by_self_is_before(self):
        self.assertTrue(Interval(0, 5).is_before(Interval(5, 10)))

    def test_shared_point_excluded_by_other_is_before(self):
        self.assertTrue(Interval(0, 5, right_open=False).is_before(Interval(5, 10, left_open=True)))

    def test_shared_point_excluded_by_both_is_before(self):
        self.assertTrue(Interval(0, 5).is_before(Interval(5, 10, left_open=True)))

    def test_shared_point_included_by_both_is_not_before(self):
        self.assertFalse(Interval(0, 5, right_open=False).is_before(Interval(5, 10)))

    def test_point_intervals(self):
        self.assertTrue(Interval.point(5).is_before(Interval.point(6)))
        self.assertFalse(Interval.point(5).is_before(Interval.point(5)))
        self.assertTrue(Interval.point(5).is_before(Interval(5, 10, left_open=True)))
        self.assertTrue(Interval(0, 5).is_before(Interval.point(5)))

    def test_right_unbounded_interval_is_never_before(self):
        self.assertFalse(Interval(0).is_before(Interval(100, 200)))
        self.assertFalse(Interval(0).is_before(Interval(5)))

    def test_interval_can_be_before_a_right_unbounded_interval(self):
        self.assertTrue(Interval(0, 5).is_before(Interval(5)))
        self.assertFalse(Interval(0, 5, right_open=False).is_before(Interval(5)))

    def test_intervals_are_not_before_themselves(self):
        for i in (Interval(0, 5), Interval.point(5), Interval(3)):
            with self.subTest(i=i):
                self.assertFalse(i.is_before(i))

    def test_disjoint_exactly_when_one_is_before_the_other(self):
        intervals = [Interval(0, 5), Interval(0, 5, right_open=False), Interval(5, 10),
                     Interval(5, 10, left_open=True), Interval.point(5), Interval(3),
                     Interval(7, left_open=True), Interval(10, 12)]
        for a in intervals:
            for b in intervals:
                with self.subTest(a=a, b=b):
                    self.assertEqual(not a.intersect(b), a.is_before(b) or b.is_before(a))

    def test_is_before_with_non_interval_raises_type_error(self):
        with self.assertRaises(TypeError):
            Interval(0, 5).is_before((7, 10))


class TestJustBefore(unittest.TestCase):

    def test_right_open_before_left_closed_is_just_before(self):
        # [0, 5) is just before [5, 10): 5 is excluded from the first,
        # included in the second.
        self.assertTrue(Interval(0, 5, right_open=True).just_before(Interval(5, 10)))

    def test_right_closed_before_left_open_is_just_before(self):
        # [0, 5] is just before (5, 10): 5 is included in the first,
        # excluded from the second.
        self.assertTrue(
            Interval(0, 5, right_open=False).just_before(Interval(5, 10, left_open=True))
        )

    def test_both_closed_at_shared_point_is_not_just_before(self):
        # [0, 5] and [5, 10) both include 5: they overlap, not abut.
        self.assertFalse(Interval(0, 5, right_open=False).just_before(Interval(5, 10)))

    def test_both_open_at_shared_point_is_not_just_before(self):
        # [0, 5) and (5, 10): 5 is excluded from both, leaving a gap.
        self.assertFalse(
            Interval(0, 5, right_open=True).just_before(Interval(5, 10, left_open=True))
        )

    def test_different_endpoints_is_not_just_before(self):
        self.assertFalse(Interval(0, 5, right_open=True).just_before(Interval(7, 10)))

    def test_right_unbounded_self_is_never_just_before_anything(self):
        self.assertFalse(Interval(0).just_before(Interval(5, 10)))

    def test_not_symmetric_in_general(self):
        a, b = Interval(0, 5, right_open=True), Interval(5, 10)
        self.assertTrue(a.just_before(b))
        self.assertFalse(b.just_before(a))

    def test_just_before_with_non_interval_raises_type_error(self):
        with self.assertRaises(TypeError):
            Interval(0, 5).just_before((5, 10))


class TestSplit(unittest.TestCase):

    def test_default_open_on_left_side(self):
        left, right = Interval(0, 10, right_open=True).split(5)
        self.assertEqual(left, Interval(0, 5, right_open=True))
        self.assertEqual(right, Interval(5, 10, right_open=True))

    def test_open_on_left_side_false(self):
        left, right = Interval(0, 10, right_open=True).split(5, open_on_left_side=False)
        self.assertEqual(left, Interval(0, 5, right_open=False))
        self.assertEqual(right, Interval(5, 10, left_open=True, right_open=True))

    def test_left_open_flag_of_self_is_kept_on_i_left(self):
        left, right = Interval(0, 10, left_open=True, right_open=True).split(5)
        self.assertEqual(left, Interval(0, 5, left_open=True, right_open=True))
        self.assertEqual(right, Interval(5, 10, right_open=True))

    def test_right_open_flag_of_self_is_kept_on_i_right(self):
        left, right = Interval(0, 10, right_open=False).split(5)
        self.assertEqual(left, Interval(0, 5, right_open=True))
        self.assertEqual(right, Interval(5, 10, right_open=False))

    def test_split_right_unbounded_interval(self):
        left, right = Interval(5, left_open=True).split(8)
        self.assertEqual(left, Interval(5, 8, left_open=True, right_open=True))
        self.assertEqual(right, Interval(8))

    def test_pieces_are_just_before_each_other(self):
        for open_on_left_side in (True, False):
            with self.subTest(open_on_left_side=open_on_left_side):
                left, right = Interval(0, 10, right_open=True).split(5, open_on_left_side)
                self.assertTrue(left.just_before(right))

    def test_pieces_rejoin_into_the_original_interval(self):
        original = Interval(0, 10, left_open=True, right_open=False)
        for t in (2, 5, 9.9):
            for open_on_left_side in (True, False):
                with self.subTest(t=t, open_on_left_side=open_on_left_side):
                    left, right = original.split(t, open_on_left_side)
                    self.assertEqual(left.join(right), original)

    def test_t_outside_interval_raises_value_error(self):
        with self.assertRaises(ValueError):
            Interval(0, 10, right_open=True).split(10)
        with self.assertRaises(ValueError):
            Interval(0, 10).split(-1)

    def test_split_exactly_at_closed_start_with_open_on_left_side_raises(self):
        # i_left would be the invalid, empty [0, 0) interval.
        with self.assertRaises(ValueError):
            Interval(0, 10, right_open=False).split(0, open_on_left_side=True)

    def test_split_exactly_at_closed_end_with_open_on_left_side_false_raises(self):
        # i_right would be the invalid, empty (10, 10] interval.
        with self.assertRaises(ValueError):
            Interval(0, 10, right_open=False).split(10, open_on_left_side=False)

    def test_split_does_not_mutate_original(self):
        original = Interval(0, 10, right_open=True)
        original.split(5)
        self.assertEqual(original, Interval(0, 10, right_open=True))


class TestJoin(unittest.TestCase):

    def test_join_overlapping_intervals(self):
        j = Interval(0, 10).join(Interval(5, 15))
        self.assertEqual(j, Interval(0, 15))

    def test_join_one_interval_contained_in_the_other(self):
        j = Interval(0, 10).join(Interval(2, 5))
        self.assertEqual(j, Interval(0, 10))

    def test_join_is_symmetric(self):
        a, b = Interval(0, 10), Interval(5, 15)
        self.assertEqual(a.join(b), b.join(a))

    def test_join_keeps_open_bound_from_the_extending_interval(self):
        # [0, 10) joined with [5, 15) -> [0, 15): the right-open bound comes
        # from the interval that reaches furthest (15, excluded).
        j = Interval(0, 10, right_open=True).join(Interval(5, 15, right_open=True))
        self.assertEqual(j, Interval(0, 15, right_open=True))

    def test_join_left_bound_open_only_if_both_are_open_at_the_tie(self):
        j = Interval(0, 10, left_open=True).join(Interval(0, 5, left_open=False))
        self.assertEqual(j, Interval(0, 10, left_open=False))

    def test_join_left_bound_stays_open_when_both_open_at_the_tie(self):
        j = Interval(0, 10, left_open=True).join(Interval(0, 5, left_open=True))
        self.assertEqual(j, Interval(0, 10, left_open=True))

    def test_join_right_bound_open_only_if_both_are_open_at_the_tie(self):
        j = Interval(0, 10, right_open=True).join(Interval(5, 10, right_open=False))
        self.assertEqual(j, Interval(0, 10, right_open=False))

    def test_join_adjacent_intersecting_intervals(self):
        # [0, 5] and [5, 10): they intersect at the shared closed point 5.
        j = Interval(0, 5, right_open=False).join(Interval(5, 10, right_open=True))
        self.assertEqual(j, Interval(0, 10, right_open=True))

    def test_join_with_right_unbounded_interval(self):
        j = Interval(0, 5, right_open=True).join(Interval(3))
        self.assertEqual(j, Interval(0))
        self.assertTrue(j.is_right_unbounded)

    def test_join_of_two_right_unbounded_intervals(self):
        j = Interval(5).join(Interval(0, 10, right_open=True))
        self.assertEqual(j, Interval(0))

    def test_join_point_intervals(self):
        self.assertEqual(Interval.point(5).join(Interval.point(5)), Interval.point(5))

    def test_join_non_intersecting_intervals_raises_value_error(self):
        with self.assertRaises(ValueError):
            Interval(0, 5, right_open=True).join(Interval(7, 10))

    def test_join_of_intervals_just_before_each_other_succeeds(self):
        # [0, 5) and [5, 10): they do not intersect (5 is excluded from [0, 5))
        # but self.just_before(other) holds, so they can still be joined.
        a, b = Interval(0, 5, right_open=True), Interval(5, 10, right_open=True)
        self.assertTrue(a.just_before(b))
        self.assertFalse(a.intersect(b))
        self.assertEqual(a.join(b), Interval(0, 10, right_open=True))

    def test_join_of_intervals_where_other_is_just_before_self_succeeds(self):
        a, b = Interval(0, 5, right_open=True), Interval(5, 10, right_open=True)
        self.assertTrue(a.just_before(b))
        self.assertEqual(b.join(a), Interval(0, 10, right_open=True))

    def test_join_gap_between_intervals_raises_value_error(self):
        # [0, 5) and (5, 10): a gap at exactly 5, excluded from both sides.
        with self.assertRaises(ValueError):
            Interval(0, 5, right_open=True).join(Interval(5, 10, left_open=True))

    def test_join_with_non_interval_raises_type_error(self):
        with self.assertRaises(TypeError):
            Interval(0, 5).join((0, 5))


class TestEqualityAndRepr(unittest.TestCase):

    def test_equal_intervals(self):
        self.assertEqual(Interval(1, 5), Interval(1, 5))
        self.assertEqual(Interval(1, 5, left_open=True), Interval(1, 5, left_open=True))

    def test_unbounded_intervals_are_equal_regardless_of_right_open_arg(self):
        self.assertEqual(Interval(1), Interval(1, right_open=False))

    def test_different_bounds_are_not_equal(self):
        self.assertNotEqual(Interval(1, 5), Interval(1, 6))
        self.assertNotEqual(Interval(1, 5), Interval(1, 5, left_open=True))

    def test_not_equal_to_other_types(self):
        self.assertNotEqual(Interval(1, 5), (1, 5))

    def test_hash_is_consistent_with_equality(self):
        self.assertEqual(hash(Interval(1, 5)), hash(Interval(1, 5)))

    def test_repr_default(self):
        self.assertEqual(repr(Interval(1, 5)), "[1.0,5.0)")

    def test_repr_closed(self):
        self.assertEqual(repr(Interval(1, 5, right_open=False)), "[1.0,5.0]")

    def test_repr_open(self):
        self.assertEqual(repr(Interval(1, 5, left_open=True, right_open=True)), "(1.0,5.0)")

    def test_repr_left_open_right_closed(self):
        self.assertEqual(repr(Interval(1, 5, left_open=True, right_open=False)), "(1.0,5.0]")

    def test_repr_right_unbounded_omits_to(self):
        self.assertEqual(repr(Interval(2)), "[2.0,)")

    def test_repr_right_unbounded_left_open_omits_to(self):
        self.assertEqual(repr(Interval(2, left_open=True)), "(2.0,)")


if __name__ == '__main__':
    unittest.main()
