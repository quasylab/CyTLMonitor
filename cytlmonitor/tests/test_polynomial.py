"""Unit tests for cytlmonitor.polynomial.Polynomial."""

import pytest

from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial


class TestConstruction:

    def test_constant_polynomial(self):
        p = Polynomial([4])
        assert p.coefficients == (4.0,)

    def test_linear_polynomial(self):
        p = Polynomial([1, 2])
        assert p.coefficients == (1.0, 2.0)

    def test_quadratic_polynomial(self):
        p = Polynomial([1, 2, 3])
        assert p.coefficients == (1.0, 2.0, 3.0)

    def test_coefficients_are_converted_to_float(self):
        p = Polynomial([1, 2, 3])
        assert all(isinstance(c, float) for c in p.coefficients)

    def test_empty_coefficients_raises(self):
        with pytest.raises(ValueError):
            Polynomial([])


class TestZero:

    def test_zero_is_a_polynomial(self):
        assert isinstance(Polynomial.ZERO, Polynomial)

    def test_zero_coefficients(self):
        assert Polynomial.ZERO.coefficients == (0.0,)

    def test_zero_degree(self):
        assert Polynomial.ZERO.degree == 0

    def test_zero_evaluates_to_zero_everywhere(self):
        for t in (-100, 0, 3.14, 1e6):
            assert Polynomial.ZERO.evaluate(t) == 0.0

    def test_zero_equals_an_equivalent_constructed_polynomial(self):
        assert Polynomial.ZERO == Polynomial([0])
        assert Polynomial.ZERO == Polynomial([0, 0, 0])

    def test_zero_is_the_identity_for_add(self):
        p = Polynomial([1, 2, 3])
        assert p.add(Polynomial.ZERO) == p
        assert Polynomial.ZERO.add(p) == p

    def test_zero_is_absorbing_for_mul(self):
        p = Polynomial([1, 2, 3])
        assert p.mul(Polynomial.ZERO) == Polynomial.ZERO
        assert Polynomial.ZERO.mul(p) == Polynomial.ZERO


class TestTrailingZeroRemoval:

    def test_trailing_zeros_are_removed(self):
        p = Polynomial([4, 0, 0])
        assert p.coefficients == (4.0,)

    def test_all_zero_collapses_to_single_zero(self):
        p = Polynomial([0, 0])
        assert p.coefficients == (0.0,)

    def test_no_trailing_zeros_are_kept_unchanged(self):
        p = Polynomial([1, 0, 3])
        assert p.coefficients == (1.0, 0.0, 3.0)


class TestDegree:

    def test_constant_degree(self):
        assert Polynomial([4]).degree == 0

    def test_linear_degree(self):
        assert Polynomial([1, 2]).degree == 1

    def test_quadratic_degree(self):
        assert Polynomial([1, 2, 3]).degree == 2

    def test_zero_polynomial_degree(self):
        assert Polynomial([0, 0, 0]).degree == 0


class TestEvaluate:

    def test_constant_evaluate(self):
        p = Polynomial([4])
        assert p.evaluate(10) == 4.0
        assert p(10) == 4.0

    def test_linear_evaluate(self):
        # p(t) = 1 + 2t
        p = Polynomial([1, 2])
        assert p.evaluate(3) == 7.0
        assert p(3) == 7.0

    def test_quadratic_evaluate(self):
        # p(t) = 1 + 2t + 3t^2
        p = Polynomial([1, 2, 3])
        assert p.evaluate(2) == 1 + 2 * 2 + 3 * 2 ** 2
        assert p(2) == 1 + 2 * 2 + 3 * 2 ** 2

    def test_evaluate_and_call_are_equivalent(self):
        p = Polynomial([1, -2, 0.5])
        for t in (-5, 0, 0.5, 3.14, 100):
            assert p.evaluate(t) == p(t)

    def test_evaluate_returns_float(self):
        p = Polynomial([1, 2])
        assert isinstance(p.evaluate(3), float)


class TestEquality:

    def test_equal_polynomials(self):
        assert Polynomial([1, 2, 3]) == Polynomial([1, 2, 3])

    def test_equivalent_after_trailing_zero_removal(self):
        assert Polynomial([4, 0, 0]) == Polynomial([4])
        assert Polynomial([0, 0]) == Polynomial([0])

    def test_different_polynomials_are_not_equal(self):
        assert Polynomial([1, 2, 3]) != Polynomial([1, 2])

    def test_not_equal_to_other_types(self):
        assert Polynomial([1, 2]) != (1, 2)


class TestSup:

    def test_constant(self):
        assert Polynomial([4]).sup(Interval(0, 10)) == 4.0

    def test_linear_increasing_bounded(self):
        # p(t) = 1 + 2t, max on [0, 10) at t=10
        assert Polynomial([1, 2]).sup(Interval(0, 10, right_open=True)) == 21.0

    def test_linear_increasing_unbounded_is_infinite(self):
        assert Polynomial([1, 2]).sup(Interval(3)) == float('inf')

    def test_linear_decreasing_bounded(self):
        # p(t) = 1 - 2t, max on [0, 10] at t=0
        assert Polynomial([1, -2]).sup(Interval(0, 10)) == 1.0

    def test_linear_decreasing_unbounded_is_finite(self):
        # p(t) = 1 - 2t is decreasing, so the max over [3, +inf) is at t=3
        assert Polynomial([1, -2]).sup(Interval(3)) == -5.0

    def test_quadratic_upward_bounded_uses_endpoints(self):
        # p(t) = t^2 on [-3, 2]: max(p(-3), p(2)) = max(9, 4) = 9
        assert Polynomial([0, 0, 1]).sup(Interval(-3, 2)) == 9.0

    def test_quadratic_upward_unbounded_is_infinite(self):
        assert Polynomial([0, 0, 1]).sup(Interval(0)) == float('inf')

    def test_quadratic_downward_vertex_inside_interval(self):
        # p(t) = 4t - t^2, vertex at t=2, p(2) = 4
        assert Polynomial([0, 4, -1]).sup(Interval(0, 10)) == 4.0

    def test_quadratic_downward_vertex_left_of_interval(self):
        # vertex at t=2, interval [5, 10]: p decreasing there, max at t=5
        p = Polynomial([0, 4, -1])
        assert p.sup(Interval(5, 10)) == p.evaluate(5)

    def test_quadratic_downward_vertex_right_of_interval(self):
        # vertex at t=2, interval [-10, -5]: p increasing there, max at t=-5
        p = Polynomial([0, 4, -1])
        assert p.sup(Interval(-10, -5)) == p.evaluate(-5)

    def test_quadratic_downward_unbounded_uses_vertex(self):
        # vertex at t=2 falls within [0, +inf), so sup is finite despite
        # the interval being unbounded.
        p = Polynomial([0, 4, -1])
        assert p.sup(Interval(0)) == 4.0

    def test_sup_ignores_open_closed_at_the_maximizing_point(self):
        # The maximizing endpoint being excluded doesn't change the sup.
        p = Polynomial([1, 2])
        assert p.sup(Interval(0, 10, right_open=True)) == p.sup(Interval(0, 10, right_open=False))

    def test_degree_three_raises_value_error(self):
        with pytest.raises(ValueError):
            Polynomial([1, 2, 3, 4]).sup(Interval(0, 10))

    def test_sup_with_non_interval_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1, 2]).sup((0, 10))


class TestInf:

    def test_constant(self):
        assert Polynomial([4]).inf(Interval(0, 10)) == 4.0

    def test_linear_increasing_bounded(self):
        # p(t) = 1 + 2t, min on [0, 10) at t=0
        assert Polynomial([1, 2]).inf(Interval(0, 10, right_open=True)) == 1.0

    def test_linear_increasing_unbounded_is_finite(self):
        # p(t) = 1 + 2t is increasing, so the min over [3, +inf) is at t=3
        assert Polynomial([1, 2]).inf(Interval(3)) == 7.0

    def test_linear_decreasing_bounded(self):
        # p(t) = 1 - 2t, min on [0, 10] at t=10
        assert Polynomial([1, -2]).inf(Interval(0, 10)) == -19.0

    def test_linear_decreasing_unbounded_is_infinite(self):
        assert Polynomial([1, -2]).inf(Interval(3)) == float('-inf')

    def test_quadratic_upward_vertex_inside_interval(self):
        # p(t) = t^2, vertex at t=0, inside [-3, 2]
        assert Polynomial([0, 0, 1]).inf(Interval(-3, 2)) == 0.0

    def test_quadratic_upward_vertex_left_of_interval(self):
        # vertex at t=0, interval [1, 5]: p increasing there, min at t=1
        p = Polynomial([0, 0, 1])
        assert p.inf(Interval(1, 5)) == p.evaluate(1)

    def test_quadratic_upward_vertex_right_of_interval(self):
        # vertex at t=0, interval [-5, -1]: p decreasing there, min at t=-1
        p = Polynomial([0, 0, 1])
        assert p.inf(Interval(-5, -1)) == p.evaluate(-1)

    def test_quadratic_upward_unbounded_uses_vertex(self):
        assert Polynomial([0, 0, 1]).inf(Interval(0)) == 0.0

    def test_quadratic_downward_bounded_uses_endpoints(self):
        # p(t) = 4t - t^2 on [0, 10]: min(p(0), p(10)) = min(0, -60) = -60
        assert Polynomial([0, 4, -1]).inf(Interval(0, 10)) == -60.0

    def test_quadratic_downward_unbounded_is_infinite(self):
        assert Polynomial([0, 4, -1]).inf(Interval(0)) == float('-inf')

    def test_inf_ignores_open_closed_at_the_minimizing_point(self):
        p = Polynomial([1, -2])
        assert p.inf(Interval(0, 10, right_open=True)) == p.inf(Interval(0, 10, right_open=False))

    def test_inf_le_sup(self):
        p = Polynomial([2, -3, 1])
        interval = Interval(-4, 6, right_open=False)
        assert p.inf(interval) <= p.sup(interval)

    def test_degree_three_raises_value_error(self):
        with pytest.raises(ValueError):
            Polynomial([1, 2, 3, 4]).inf(Interval(0, 10))

    def test_inf_with_non_interval_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1, 2]).inf((0, 10))


class TestComputeIntegral:

    def test_constant(self):
        # integral of 4 over [0, 10] is 4*10 = 40
        assert Polynomial([4]).compute_integral(Interval(0, 10)) == 40.0

    def test_linear(self):
        # p(t) = t, integral over [0, 10] is t^2/2 -> 50
        assert Polynomial([0, 1]).compute_integral(Interval(0, 10)) == 50.0

    def test_quadratic(self):
        # p(t) = t^2, integral over [0, 3] is t^3/3 -> 9
        assert Polynomial([0, 0, 1]).compute_integral(Interval(0, 3)) == 9.0

    def test_higher_degree_is_supported(self):
        # p(t) = 1 + 2t + 3t^2 + 4t^3, antiderivative t + t^2 + t^3 + t^4,
        # over [0, 1]: F(1) - F(0) = 4 - 0 = 4
        assert Polynomial([1, 2, 3, 4]).compute_integral(Interval(0, 1)) == 4.0

    def test_negative_bounds(self):
        # p(t) = 1 + 2t + 3t^2, antiderivative t + t^2 + t^3,
        # over [-1, 2]: F(2) - F(-1) = 14 - (-1) = 15
        assert Polynomial([1, 2, 3]).compute_integral(Interval(-1, 2)) == 15.0

    def test_zero_width_interval_is_zero(self):
        assert Polynomial([1, 2, 3]).compute_integral(Interval.point(5)) == 0.0

    def test_open_and_closed_intervals_give_the_same_result(self):
        p = Polynomial([1, 2, 3])
        assert (
            p.compute_integral(Interval(0, 5, right_open=True))
            == p.compute_integral(Interval(0, 5, right_open=False))
        )

    def test_additivity_over_adjacent_subintervals(self):
        p = Polynomial([1, -2, 3])
        whole = p.compute_integral(Interval(0, 10))
        parts = p.compute_integral(Interval(0, 4)) + p.compute_integral(Interval(4, 10))
        assert whole == pytest.approx(parts)

    def test_right_unbounded_interval_raises_value_error(self):
        with pytest.raises(ValueError):
            Polynomial([1, 2]).compute_integral(Interval(0))

    def test_compute_integral_with_non_interval_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1, 2]).compute_integral((0, 10))


class TestAdd:

    def test_same_degree(self):
        assert Polynomial([1, 2]).add(Polynomial([3, 4])) == Polynomial([4, 6])

    def test_different_degree(self):
        # (1 + 2t + 3t^2) + (4 + 5t) = 5 + 7t + 3t^2
        assert Polynomial([1, 2, 3]).add(Polynomial([4, 5])) == Polynomial([5, 7, 3])

    def test_is_commutative(self):
        p, q = Polynomial([1, 2, 3]), Polynomial([4, 5])
        assert p.add(q) == q.add(p)

    def test_result_trims_trailing_zeros(self):
        # (1 + 2t) + (1 - 2t) = 2
        assert Polynomial([1, 2]).add(Polynomial([1, -2])) == Polynomial([2])

    def test_add_with_non_polynomial_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1, 2]).add((1, 2))


class TestSub:

    def test_same_degree(self):
        assert Polynomial([5, 7]).sub(Polynomial([2, 3])) == Polynomial([3, 4])

    def test_different_degree(self):
        # (1 + 2t + 3t^2) - (4 + 5t) = -3 - 3t + 3t^2
        assert Polynomial([1, 2, 3]).sub(Polynomial([4, 5])) == Polynomial([-3, -3, 3])

    def test_subtracting_self_gives_zero(self):
        p = Polynomial([1, 2, 3])
        assert p.sub(p) == Polynomial([0])

    def test_not_commutative(self):
        p, q = Polynomial([1, 2, 3]), Polynomial([4, 5])
        assert p.sub(q) == Polynomial([-3, -3, 3])
        assert q.sub(p) == Polynomial([3, 3, -3])

    def test_sub_with_non_polynomial_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1, 2]).sub((1, 2))


class TestMul:

    def test_by_constant(self):
        assert Polynomial([2]).mul(Polynomial([3, 4])) == Polynomial([6, 8])

    def test_two_linear_polynomials(self):
        # (1 + 2t)(3 + 4t) = 3 + 10t + 8t^2
        assert Polynomial([1, 2]).mul(Polynomial([3, 4])) == Polynomial([3, 10, 8])

    def test_quadratic_by_linear(self):
        # (1 + 2t + 3t^2)(4 + 5t) = 4 + 13t + 22t^2 + 15t^3
        assert Polynomial([1, 2, 3]).mul(Polynomial([4, 5])) == Polynomial([4, 13, 22, 15])

    def test_is_commutative(self):
        p, q = Polynomial([1, 2, 3]), Polynomial([4, 5])
        assert p.mul(q) == q.mul(p)

    def test_by_zero_polynomial(self):
        assert Polynomial([1, 2, 3]).mul(Polynomial([0])) == Polynomial([0])

    def test_degree_of_product(self):
        p, q = Polynomial([1, 2, 3]), Polynomial([4, 5])
        assert p.mul(q).degree == p.degree + q.degree

    def test_mul_with_non_polynomial_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1, 2]).mul((1, 2))


class TestDiv:

    def test_by_constant(self):
        assert Polynomial([2, 4, 6]).div(Polynomial([2])) == Polynomial([1, 2, 3])

    def test_by_negative_constant(self):
        assert Polynomial([1, -2]).div(Polynomial([-4])) == Polynomial([-0.25, 0.5])

    def test_by_one_is_identity(self):
        assert Polynomial([1, 2, 3]).div(Polynomial([1])) == Polynomial([1, 2, 3])

    def test_zero_divided_is_zero(self):
        assert Polynomial.ZERO.div(Polynomial([5])) == Polynomial.ZERO

    def test_evaluation_property(self):
        p = Polynomial([1, -2, 3])
        q = p.div(Polynomial([3]))
        for x in [-1.5, 0.0, 2.0]:
            assert q.evaluate(x) == pytest.approx(p.evaluate(x) / 3)

    def test_by_zero_polynomial_raises(self):
        with pytest.raises(ValueError):
            Polynomial([1, 2]).div(Polynomial.ZERO)

    def test_by_non_constant_raises(self):
        with pytest.raises(ValueError):
            Polynomial([1, 2]).div(Polynomial([1, 1]))

    def test_with_non_polynomial_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1, 2]).div(2)


class TestShift:

    def test_constant_is_unchanged(self):
        assert Polynomial([5]).shift(3.0) == Polynomial([5])

    def test_zero_shift_is_identity(self):
        assert Polynomial([1, 2, 3]).shift(0.0) == Polynomial([1, 2, 3])

    def test_linear(self):
        # p(t) = 1 + 2t, shifted by 3: 1 + 2(t - 3) = -5 + 2t
        assert Polynomial([1, 2]).shift(3.0) == Polynomial([-5, 2])

    def test_quadratic(self):
        # p(t) = t^2, shifted by 1: (t - 1)^2 = 1 - 2t + t^2
        assert Polynomial([0, 0, 1]).shift(1.0) == Polynomial([1, -2, 1])

    def test_preserves_degree(self):
        assert Polynomial([1, 2, 3, 4]).shift(2.5).degree == 3

    @pytest.mark.parametrize("v", [-2.0, 0.5, 1.0, 3.0])
    @pytest.mark.parametrize("x", [-1.5, 0.0, 2.0, 4.25])
    def test_evaluation_property(self, v, x):
        p = Polynomial([1, -2, 3, 0.5])
        assert p.shift(v).evaluate(x + v) == pytest.approx(p.evaluate(x))


class TestIntegral:

    def test_constant(self):
        # integral of 3 from x to x+2 is 6
        assert Polynomial([3]).integral(2.0) == Polynomial([6])

    def test_linear(self):
        # integral of 2t from x to x+1 is (x+1)^2 - x^2 = 1 + 2x
        assert Polynomial([0, 2]).integral(1.0) == Polynomial([1, 2])

    def test_zero_width_is_zero(self):
        assert Polynomial([1, 2, 3]).integral(0.0) == Polynomial.ZERO

    def test_preserves_degree(self):
        assert Polynomial([1, 2, 3, 4]).integral(2.5).degree == 3

    @pytest.mark.parametrize("v", [-2.0, 0.5, 1.0, 3.0])
    @pytest.mark.parametrize("x", [-1.5, 0.0, 2.0, 4.25])
    def test_matches_compute_integral(self, v, x):
        p = Polynomial([1, -2, 3, 0.5])
        start, end = min(x, x + v), max(x, x + v)
        expected = p.compute_integral(Interval(start, end))
        if v < 0:
            expected = -expected
        assert p.integral(v).evaluate(x) == pytest.approx(expected)


class TestPositive:

    def test_always_positive(self):
        i = Interval(0, 5)
        assert Polynomial([1, 0, 1]).positive(i) == [(i, True)]

    def test_always_negative(self):
        i = Interval(0, 5, right_open=False)
        assert Polynomial([-1, -1]).positive(i) == [(i, False)]

    def test_zero_polynomial_is_not_positive(self):
        i = Interval(0, 5)
        assert Polynomial.ZERO.positive(i) == [(i, False)]

    def test_linear_crossing_upward(self):
        # t - 2 on [0, 5): non-positive on [0, 2], positive on (2, 5)
        assert Polynomial([-2, 1]).positive(Interval(0, 5)) == [
            (Interval(0, 2, right_open=False), False),
            (Interval(2, 5, left_open=True), True),
        ]

    def test_linear_crossing_downward(self):
        # 2 - t on [0, 5): positive on [0, 2), non-positive on [2, 5)
        assert Polynomial([2, -1]).positive(Interval(0, 5)) == [
            (Interval(0, 2), True),
            (Interval(2, 5), False),
        ]

    def test_quadratic_two_roots(self):
        # (t - 1)(t - 3) = 3 - 4t + t^2 on [0, 5]
        assert Polynomial([3, -4, 1]).positive(Interval(0, 5, right_open=False)) == [
            (Interval(0, 1), True),
            (Interval(1, 3, right_open=False), False),
            (Interval(3, 5, left_open=True, right_open=False), True),
        ]

    def test_double_root_is_not_positive(self):
        # (t - 2)^2 is zero at 2
        assert Polynomial([4, -4, 1]).positive(Interval(0, 5)) == [
            (Interval(0, 2), True),
            (Interval.point(2), False),
            (Interval(2, 5, left_open=True), True),
        ]

    def test_negative_with_double_root_merges(self):
        i = Interval(0, 5)
        assert Polynomial([-4, 4, -1]).positive(i) == [(i, False)]

    def test_root_outside_interval(self):
        i = Interval(3, 5)
        assert Polynomial([-2, 1]).positive(i) == [(i, True)]

    def test_root_on_open_left_bound(self):
        i = Interval(2, 5, left_open=True)
        assert Polynomial([-2, 1]).positive(i) == [(i, True)]

    def test_root_on_closed_left_bound(self):
        assert Polynomial([-2, 1]).positive(Interval(2, 5)) == [
            (Interval.point(2), False),
            (Interval(2, 5, left_open=True), True),
        ]

    def test_root_on_open_right_bound(self):
        i = Interval(0, 2)
        assert Polynomial([2, -1]).positive(i) == [(i, True)]

    def test_root_on_closed_right_bound(self):
        assert Polynomial([2, -1]).positive(Interval(0, 2, right_open=False)) == [
            (Interval(0, 2), True),
            (Interval.point(2), False),
        ]

    def test_right_unbounded(self):
        assert Polynomial([-2, 1]).positive(Interval(0)) == [
            (Interval(0, 2, right_open=False), False),
            (Interval(2, left_open=True), True),
        ]

    def test_point_interval(self):
        assert Polynomial([-2, 1]).positive(Interval.point(3)) == [(Interval.point(3), True)]
        assert Polynomial([-2, 1]).positive(Interval.point(2)) == [(Interval.point(2), False)]

    def test_degree_above_two_raises(self):
        with pytest.raises(ValueError):
            Polynomial([0, 0, 0, 1]).positive(Interval(0, 1))

    def test_non_interval_raises_type_error(self):
        with pytest.raises(TypeError):
            Polynomial([1]).positive((0, 1))


class TestPositiveNonStrict:

    def test_zero_polynomial_is_non_negative(self):
        i = Interval(0, 5)
        assert Polynomial.ZERO.positive(i, strict=False) == [(i, True)]

    def test_root_joins_positive_part(self):
        # t - 2 on [0, 5): negative on [0, 2), non-negative on [2, 5)
        assert Polynomial([-2, 1]).positive(Interval(0, 5), strict=False) == [
            (Interval(0, 2), False),
            (Interval(2, 5), True),
        ]

    def test_quadratic_two_roots(self):
        # (t - 1)(t - 3) = 3 - 4t + t^2 on [0, 5]
        assert Polynomial([3, -4, 1]).positive(Interval(0, 5, right_open=False), strict=False) == [
            (Interval(0, 1, right_open=False), True),
            (Interval(1, 3, left_open=True), False),
            (Interval(3, 5, right_open=False), True),
        ]

    def test_double_root_merges_into_positive(self):
        i = Interval(0, 5)
        assert Polynomial([4, -4, 1]).positive(i, strict=False) == [(i, True)]

    def test_negative_with_double_root(self):
        # -(t - 2)^2 is zero only at 2
        assert Polynomial([-4, 4, -1]).positive(Interval(0, 5), strict=False) == [
            (Interval(0, 2), False),
            (Interval.point(2), True),
            (Interval(2, 5, left_open=True), False),
        ]

    def test_point_interval_at_root(self):
        assert Polynomial([-2, 1]).positive(Interval.point(2), strict=False) == [(Interval.point(2), True)]

    def test_strict_is_default(self):
        i = Interval(0, 5)
        assert Polynomial([4, -4, 1]).positive(i) == Polynomial([4, -4, 1]).positive(i, strict=True)
