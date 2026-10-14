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


class TestSup:

    def test_sup_delegates_to_polynomial_sup(self):
        interval = Interval(0, 10, right_open=True)
        polynomial = Polynomial([1, 2])
        segment = Segment(interval, polynomial)
        assert segment.sup() == polynomial.sup(interval)

    def test_sup_of_linear_increasing_segment(self):
        # p(t) = 1 + 2t on [0, 10): sup at t=10 -> 21
        segment = Segment(Interval(0, 10, right_open=True), Polynomial([1, 2]))
        assert segment.sup() == 21.0

    def test_sup_of_downward_quadratic_with_vertex_inside(self):
        # p(t) = 4t - t^2, vertex at t=2, on [0, 10]: sup = p(2) = 4
        segment = Segment(Interval(0, 10), Polynomial([0, 4, -1]))
        assert segment.sup() == 4.0

    def test_sup_of_unbounded_upward_quadratic_is_infinite(self):
        segment = Segment(Interval(0), Polynomial([0, 0, 1]))
        assert segment.sup() == float('inf')

    def test_sup_raises_for_degree_greater_than_two(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2, 3, 4]))
        with pytest.raises(ValueError):
            segment.sup()


class TestInf:

    def test_inf_delegates_to_polynomial_inf(self):
        interval = Interval(0, 10, right_open=True)
        polynomial = Polynomial([1, 2])
        segment = Segment(interval, polynomial)
        assert segment.inf() == polynomial.inf(interval)

    def test_inf_of_linear_decreasing_segment(self):
        # p(t) = 1 - 2t on [0, 10]: inf at t=10 -> -19
        segment = Segment(Interval(0, 10), Polynomial([1, -2]))
        assert segment.inf() == -19.0

    def test_inf_of_upward_quadratic_with_vertex_inside(self):
        # p(t) = t^2, vertex at t=0, on [-3, 2]: inf = p(0) = 0
        segment = Segment(Interval(-3, 2), Polynomial([0, 0, 1]))
        assert segment.inf() == 0.0

    def test_inf_of_unbounded_downward_quadratic_is_negative_infinite(self):
        segment = Segment(Interval(0), Polynomial([0, 4, -1]))
        assert segment.inf() == float('-inf')

    def test_inf_le_sup(self):
        segment = Segment(Interval(-4, 6), Polynomial([2, -3, 1]))
        assert segment.inf() <= segment.sup()

    def test_inf_raises_for_degree_greater_than_two(self):
        segment = Segment(Interval(0, 10), Polynomial([1, 2, 3, 4]))
        with pytest.raises(ValueError):
            segment.inf()


class TestShift:

    def test_positive_t_shifts_forward(self):
        # 1 + 2x moved forward by 3 is 1 + 2(x - 3) = -5 + 2x
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([1, 2]))
        assert segment.shift(3) == Segment(Interval(8, 13, right_open=True), Polynomial([-5, 2]))

    def test_negative_t_shifts_back(self):
        # 1 + 2x moved back by 2 is 1 + 2(x + 2) = 5 + 2x
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([1, 2]))
        assert segment.shift(-2) == Segment(Interval(3, 8, right_open=True), Polynomial([5, 2]))

    def test_constant_polynomial_is_unchanged(self):
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([4]))
        assert segment.shift(3).polynomial == Polynomial([4])
        assert segment.shift(-2).polynomial == Polynomial([4])

    @pytest.mark.parametrize("t", [-4.0, -1.5, 0.0, 2.0, 7.25])
    @pytest.mark.parametrize("x", [5.0, 6.5, 9.75])
    def test_values_move_with_the_interval(self, t, x):
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([1, -2, 3]))
        assert segment.shift(t).value_at(x + t) == pytest.approx(segment.value_at(x))

    def test_shift_by_zero_returns_equal_segment(self):
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([1, 2]))
        assert segment.shift(0) == segment

    def test_clipped_positive_part_is_not_none(self):
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([1, 2]))
        result = segment.shift(-6)
        assert result == Segment(Interval(0, 4, right_open=True), Polynomial([13, 2]))

    def test_none_when_interval_shift_returns_none(self):
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([1]))
        assert segment.shift(-11) is None

    def test_back_then_forward_is_identity_when_no_clipping(self):
        segment = Segment(Interval(5, 10, right_open=True), Polynomial([1, 2]))
        assert segment.shift(-2).shift(2) == segment

    def test_does_not_mutate_original(self):
        original = Segment(Interval(5, 10, right_open=True), Polynomial([1, 2]))
        original.shift(-2)
        original.shift(3)
        assert original == Segment(Interval(5, 10, right_open=True), Polynomial([1, 2]))


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
