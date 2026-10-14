"""
cytlmonitor.division_expression
===============================
Stream expression dividing the signal of one expression by the signal of
another.

A :class:`DivisionExpression` wraps two nested
:class:`~cytlmonitor.stream_expression.StreamExpression` instances, ``arg1``
and ``arg2``, and publishes the signal

    f(t) = g1(t) / g2(t)

where ``g1`` and ``g2`` are the signals they publish. See
:mod:`cytlmonitor.binary_expression` for how the two signals are aligned
and when the result is published.

The quotient of two polynomials is not a polynomial in general, so, as
for :meth:`~cytlmonitor.polynomial.Polynomial.div`, every segment of
``g2`` must be a constant: a ``ValueError`` is raised otherwise. Where
``g2`` is 0, ``f`` is 0.
"""

from __future__ import annotations

from cytlmonitor.binary_expression import BinaryExpression
from cytlmonitor.polynomial import Polynomial


class DivisionExpression(BinaryExpression):
    """A StreamExpression publishing, for each time ``t``, the signal of
    ``arg1`` divided by the signal of ``arg2`` at ``t``, or 0 where the
    signal of ``arg2`` is 0."""

    __slots__ = ()

    @staticmethod
    def _apply(p1: Polynomial, p2: Polynomial) -> Polynomial:
        if p2 == Polynomial.ZERO:
            return Polynomial.ZERO
        return p1.div(p2)
