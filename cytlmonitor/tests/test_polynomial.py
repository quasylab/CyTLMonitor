"""Unit tests for cytlmonitor.polynomial.Polynomial."""

import pytest

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
