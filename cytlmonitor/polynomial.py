"""
cytlmonitor.polynomial
========================
Representation of a real-valued univariate polynomial.

A :class:`Polynomial` represents the mathematical function

    p(t) = a_0 + a_1 * t + a_2 * t**2 + ... + a_n * t**n

where ``coefficients[i]`` is the coefficient of ``t**i``. It knows nothing
about intervals, segments, events, or signals: it is purely a function of
time. A future ``Segment`` will pair an :class:`~cytlmonitor.interval.Interval`
with a ``Polynomial`` and is responsible for deciding whether a given
timestamp falls within that interval.
"""

from __future__ import annotations

import math
from typing import Iterable, List, Tuple

from cytlmonitor.interval import Interval


class Polynomial:
    """A real-valued univariate polynomial p(t) = a_0 + a_1*t + ... + a_n*t**n.

    ``Polynomial.ZERO`` is the constant zero polynomial.
    """

    __slots__ = ('_coefficients',)

    def __init__(self, coefficients: Iterable[float]):
        coeffs = [float(c) for c in coefficients]
        if not coeffs:
            raise ValueError(
                "Polynomial requires at least one coefficient, got an empty sequence."
            )
        while len(coeffs) > 1 and coeffs[-1] == 0.0:
            coeffs.pop()
        self._coefficients = tuple(coeffs)

    @property
    def coefficients(self) -> Tuple[float, ...]:
        """The coefficients, ``coefficients[i]`` being the coefficient of ``t**i``."""
        return self._coefficients

    @property
    def degree(self) -> int:
        """The degree of the polynomial (0 for a nonzero constant or the zero polynomial)."""
        return len(self._coefficients) - 1

    def evaluate(self, time: float) -> float:
        """Evaluate p(time) using Horner's method. ``time`` is an absolute timestamp."""
        result = 0.0
        for coefficient in reversed(self._coefficients):
            result = result * float(time) + coefficient
        return result

    __call__ = evaluate

    def sup(self, interval: Interval) -> float:
        """Return the supremum of this polynomial over ``interval``.

        Only supports polynomials of degree <= 2 (constant, linear, or
        quadratic); raises a ``ValueError`` otherwise.
        """
        if not isinstance(interval, Interval):
            raise TypeError(f"Expected an Interval, got {type(interval).__name__}")
        if self.degree > 2:
            raise ValueError(
                f"sup is only supported for polynomials of degree <= 2, got degree {self.degree}."
            )

        if self.degree == 0:
            return self._coefficients[0]

        if self.degree == 1:
            a1 = self._coefficients[1]
            if a1 > 0:
                return float('inf') if interval.end is None else self.evaluate(interval.end)
            return self.evaluate(interval.start)

        # degree == 2: p(t) = a0 + a1*t + a2*t**2, a2 != 0.
        a1, a2 = self._coefficients[1], self._coefficients[2]
        if a2 > 0:
            # Upward parabola: convex, so its max over the interval is at
            # an endpoint (or +inf if unbounded).
            if interval.end is None:
                return float('inf')
            return max(self.evaluate(interval.start), self.evaluate(interval.end))

        # Downward parabola: global maximum at the vertex, if it falls
        # within the interval's numeric range (sup doesn't care whether
        # that point is actually included).
        vertex = -a1 / (2 * a2)
        if vertex < interval.start:
            return self.evaluate(interval.start)
        if interval.end is not None and vertex > interval.end:
            return self.evaluate(interval.end)
        return self.evaluate(vertex)

    def inf(self, interval: Interval) -> float:
        """Return the infimum of this polynomial over ``interval``.

        Only supports polynomials of degree <= 2 (constant, linear, or
        quadratic); raises a ``ValueError`` otherwise. Computed as
        ``-(-p).sup(interval)``, since ``inf(p) = -sup(-p)``.
        """
        if not isinstance(interval, Interval):
            raise TypeError(f"Expected an Interval, got {type(interval).__name__}")
        if self.degree > 2:
            raise ValueError(
                f"inf is only supported for polynomials of degree <= 2, got degree {self.degree}."
            )
        return -Polynomial([-c for c in self._coefficients]).sup(interval)

    def positive(self, interval: Interval, strict: bool = True) -> List[Tuple[Interval, bool]]:
        """Partition ``interval`` by the sign of this polynomial.

        Returns a list ``[(I1, b1), ..., (In, bn)]`` of disjoint intervals,
        ordered by time and fully covering ``interval``, where ``bi`` is
        True iff the polynomial is positive on ``Ii``. Adjacent intervals
        always carry different values, so ``[(interval, True)]`` (resp.
        ``[(interval, False)]``) is returned when the polynomial is
        positive (resp. not positive) everywhere in ``interval``.

        If ``strict`` is True (the default) positive means ``> 0``, so the
        points where the polynomial is 0 are not part of the positive
        part; if False it means ``>= 0``, and those points are included.

        Only supports polynomials of degree <= 2 (constant, linear, or
        quadratic); raises a ``ValueError`` otherwise.
        """
        if not isinstance(interval, Interval):
            raise TypeError(f"Expected an Interval, got {type(interval).__name__}")
        if self.degree > 2:
            raise ValueError(
                f"positive is only supported for polynomials of degree <= 2, got degree {self.degree}."
            )

        roots = [r for r in self._real_roots()
                 if r >= interval.start and (interval.end is None or r <= interval.end)]

        def is_positive(value: float) -> bool:
            return value > 0 if strict else value >= 0

        # Split at each root: open pieces between roots have a constant
        # sign, sampled at an inner point; roots are positive iff not strict.
        pieces: List[Tuple[Interval, bool]] = []
        start, left_open = interval.start, interval.left_open
        for root in roots:
            if root > start:
                pieces.append((Interval(start, root, left_open=left_open, right_open=True),
                               is_positive(self.evaluate((start + root) / 2))))
            if interval.contains(root):
                pieces.append((Interval.point(root), not strict))
            start, left_open = root, True
        if interval.end is None:
            pieces.append((Interval(start, None, left_open=left_open),
                           is_positive(self.evaluate(start + 1.0))))
        elif interval.end > start:
            pieces.append((Interval(start, interval.end, left_open=left_open,
                                    right_open=interval.right_open),
                           is_positive(self.evaluate((start + interval.end) / 2))))
        elif not roots:
            # Point interval with no root in it.
            pieces.append((interval, is_positive(self.evaluate(interval.start))))

        result: List[Tuple[Interval, bool]] = []
        for piece, value in pieces:
            if result and result[-1][1] == value:
                result[-1] = (result[-1][0].join(piece), value)
            else:
                result.append((piece, value))
        return result

    def _real_roots(self) -> List[float]:
        """Return the sorted distinct real roots of this polynomial (degree <= 2).

        The zero polynomial is reported as having no roots.
        """
        if self.degree == 0:
            return []
        if self.degree == 1:
            a0, a1 = self._coefficients
            return [-a0 / a1]
        a0, a1, a2 = self._coefficients
        discriminant = a1 * a1 - 4 * a2 * a0
        if discriminant < 0:
            return []
        if discriminant == 0:
            return [-a1 / (2 * a2)]
        # Numerically stable form, avoiding cancellation between -a1 and sqrt.
        q = -0.5 * (a1 + math.copysign(math.sqrt(discriminant), a1))
        return sorted({q / a2, a0 / q})

    def compute_integral(self, interval: Interval) -> float:
        """Return the definite integral of this polynomial over ``interval``.

        Raises a ``ValueError`` if ``interval`` is right-unbounded, since
        the integral would then not be finite in general.
        """
        if not isinstance(interval, Interval):
            raise TypeError(f"Expected an Interval, got {type(interval).__name__}")
        if interval.end is None:
            raise ValueError("compute_integral requires a right-bounded interval.")

        antiderivative = self._antiderivative()
        return antiderivative.evaluate(interval.end) - antiderivative.evaluate(interval.start)

    def integral(self, v: float) -> 'Polynomial':
        """Return the polynomial ``p`` such that ``p(x)`` is the integral of this polynomial from ``x`` to ``x + v``.

        With ``F`` the antiderivative of this polynomial, ``p(x) = F(x + v) - F(x)``.
        """
        antiderivative = self._antiderivative()
        return antiderivative.shift(-float(v)).sub(antiderivative)

    def _antiderivative(self) -> 'Polynomial':
        """Return the antiderivative of this polynomial with zero constant term."""
        return Polynomial(
            [0.0] + [c / (power + 1) for power, c in enumerate(self._coefficients)]
        )

    def add(self, other: 'Polynomial') -> 'Polynomial':
        """Return the sum of this polynomial and ``other``."""
        if not isinstance(other, Polynomial):
            raise TypeError(f"Expected a Polynomial, got {type(other).__name__}")
        n = max(len(self._coefficients), len(other._coefficients))
        a = self._coefficients + (0.0,) * (n - len(self._coefficients))
        b = other._coefficients + (0.0,) * (n - len(other._coefficients))
        return Polynomial([x + y for x, y in zip(a, b)])

    def sub(self, other: 'Polynomial') -> 'Polynomial':
        """Return this polynomial minus ``other``."""
        if not isinstance(other, Polynomial):
            raise TypeError(f"Expected a Polynomial, got {type(other).__name__}")
        n = max(len(self._coefficients), len(other._coefficients))
        a = self._coefficients + (0.0,) * (n - len(self._coefficients))
        b = other._coefficients + (0.0,) * (n - len(other._coefficients))
        return Polynomial([x - y for x, y in zip(a, b)])

    def mul(self, other: 'Polynomial') -> 'Polynomial':
        """Return the product of this polynomial and ``other``."""
        if not isinstance(other, Polynomial):
            raise TypeError(f"Expected a Polynomial, got {type(other).__name__}")
        result = [0.0] * (len(self._coefficients) + len(other._coefficients) - 1)
        for i, a in enumerate(self._coefficients):
            for j, b in enumerate(other._coefficients):
                result[i + j] += a * b
        return Polynomial(result)

    def div(self, other: 'Polynomial') -> 'Polynomial':
        """Return this polynomial divided by ``other``.

        ``other`` must be a nonzero constant polynomial: raises a
        ``ValueError`` if it has degree greater than 0 or is the zero
        polynomial.
        """
        if not isinstance(other, Polynomial):
            raise TypeError(f"Expected a Polynomial, got {type(other).__name__}")
        if other.degree > 0:
            raise ValueError(
                f"div is only supported by constant polynomials, got degree {other.degree}."
            )
        divisor = other._coefficients[0]
        if divisor == 0.0:
            raise ValueError("Cannot divide by the zero polynomial.")
        return Polynomial([c / divisor for c in self._coefficients])

    def shift(self, v: float) -> 'Polynomial':
        """Return the polynomial ``p`` such that ``self.evaluate(x) == p.evaluate(x + v)``.

        That is, ``p(t) = self(t - v)``, computed by Horner's method on
        the linear polynomial ``t - v``.
        """
        linear = Polynomial([-float(v), 1.0])
        result = Polynomial.ZERO
        for coefficient in reversed(self._coefficients):
            result = result.mul(linear).add(Polynomial([coefficient]))
        return result

    def __eq__(self, other) -> bool:
        if not isinstance(other, Polynomial):
            return NotImplemented
        return self._coefficients == other._coefficients

    def __repr__(self) -> str:
        return f"Polynomial({list(self._coefficients)!r})"


Polynomial.ZERO = Polynomial([0.0])
