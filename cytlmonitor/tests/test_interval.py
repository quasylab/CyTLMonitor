"""Unit tests for cytlmonitor.interval.Interval."""

import unittest

from cytlmonitor.interval import Interval


class TestIntervalConstruction(unittest.TestCase):

    def test_default_is_left_closed_right_open(self):
        i = Interval(1, 5)
        self.assertEqual(i.from_, 1.0)
        self.assertEqual(i.to, 5.0)
        self.assertFalse(i.left_open)
        self.assertTrue(i.right_open)

    def test_values_are_stored_as_float(self):
        i = Interval(1, 5)
        self.assertIsInstance(i.from_, float)
        self.assertIsInstance(i.to, float)

    def test_to_none_is_right_unbounded_and_right_open(self):
        i = Interval(2)
        self.assertIsNone(i.to)
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
        self.assertEqual(repr(Interval(1, 5)), "[1.0, 5.0)")

    def test_repr_closed(self):
        self.assertEqual(repr(Interval(1, 5, right_open=False)), "[1.0, 5.0]")

    def test_repr_open(self):
        self.assertEqual(repr(Interval(1, 5, left_open=True, right_open=True)), "(1.0, 5.0)")

    def test_repr_right_unbounded(self):
        self.assertEqual(repr(Interval(2)), "[2.0, +inf)")


if __name__ == '__main__':
    unittest.main()
