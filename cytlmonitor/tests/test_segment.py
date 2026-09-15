"""Unit tests for cytlmonitor.segment.Segment."""

import pytest

from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment


class TestConstruction:

    def test_interval_and_polynomial_are_accessible(self):
        interval = Interval(0, 10)
        polynomial = Polynomial([1, 2])
        segment = Segment(interval, polynomial)
        assert segment.interval == interval
        assert segment.polynomial == polynomial

    def test_compatibility_getters(self):
        interval = Interval(0, 10)
        polynomial = Polynomial([1, 2])
        segment = Segment(interval, polynomial)
        assert segment.get_interval() == interval
        assert segment.get_polynomial() == polynomial

    def test_invalid_interval_raises_type_error(self):
        with pytest.raises(TypeError):
            Segment((0, 10), Polynomial([1]))

    def test_invalid_polynomial_raises_type_error(self):
        with pytest.raises(TypeError):
            Segment(Interval(0, 10), [1, 2])


class TestContains:

    def test_contains_and_in_operator(self):
        segment = Segment(Interval(0, 10), Polynomial([1]))
        assert segment.contains(5)
        assert 5 in segment
        assert not segment.contains(15)
        assert 15 not in segment

    def test_default_interval_excludes_right_endpoint(self):
        segment = Segment(Interval(0, 10), Polynomial([1]))
        assert not segment.contains(10)
        assert 10 not in segment


class TestValueAt:

    def test_evaluate_inside_default_interval(self):
        # p(t) = 1 + 2t, valid on [0, 10)
        segment = Segment(Interval(0, 10), Polynomial([1, 2]))
        assert segment.value_at(3) == 7.0

    def test_evaluate_at_left_endpoint(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2]))
        assert segment.value_at(0) == 1.0

    def test_evaluate_rejects_excluded_right_endpoint(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2]))
        with pytest.raises(ValueError):
            segment.value_at(10)

    def test_evaluate_outside_interval_raises(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2]))
        with pytest.raises(ValueError):
            segment.value_at(-1)
        with pytest.raises(ValueError):
            segment.value_at(20)

    def test_evaluate_on_point_interval(self):
        segment = Segment(Interval.point(5), Polynomial([1, 2, 3]))
        assert segment.value_at(5) == 1 + 2 * 5 + 3 * 5 ** 2
        with pytest.raises(ValueError):
            segment.value_at(5.0001)

    def test_evaluate_uses_absolute_time(self):
        # p(t) = t, so value_at should equal the absolute timestamp, not a
        # duration relative to the interval start.
        segment = Segment(Interval(100, 200), Polynomial([0, 1]))
        assert segment.value_at(150) == 150.0

    def test_value_at_returns_float(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2]))
        assert isinstance(segment.value_at(3), float)


class TestEqualityAndRepr:

    def test_equal_segments(self):
        s1 = Segment(Interval(0, 10), Polynomial([1, 2]))
        s2 = Segment(Interval(0, 10), Polynomial([1, 2]))
        assert s1 == s2

    def test_different_interval_not_equal(self):
        s1 = Segment(Interval(0, 10), Polynomial([1, 2]))
        s2 = Segment(Interval(0, 5), Polynomial([1, 2]))
        assert s1 != s2

    def test_different_polynomial_not_equal(self):
        s1 = Segment(Interval(0, 10), Polynomial([1, 2]))
        s2 = Segment(Interval(0, 10), Polynomial([1, 3]))
        assert s1 != s2

    def test_not_equal_to_other_types(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2]))
        assert segment != (Interval(0, 10), Polynomial([1, 2]))

    def test_repr_contains_interval_and_polynomial(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2]))
        r = repr(segment)
        assert 'Segment' in r
        assert repr(Interval(0, 10)) in r
        assert repr(Polynomial([1, 2])) in r
