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

from typing import Iterable, Tuple


class Polynomial:
    """A real-valued univariate polynomial p(t) = a_0 + a_1*t + ... + a_n*t**n."""

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

    def __eq__(self, other) -> bool:
        if not isinstance(other, Polynomial):
            return NotImplemented
        return self._coefficients == other._coefficients

    def __repr__(self) -> str:
        return f"Polynomial({list(self._coefficients)!r})"
