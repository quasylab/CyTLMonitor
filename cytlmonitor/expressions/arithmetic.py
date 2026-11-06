"""
cytlmonitor.expressions.arithmetic
==================================
Pointwise arithmetic stream expressions.


Stream expression adding the signals of two other expressions.

A :class:`SumExpression` wraps two nested
:class:`~cytlmonitor.expressions.base.StreamExpression` instances, ``arg1``
and ``arg2``, and publishes the signal

    f(t) = g1(t) + g2(t)

where ``g1`` and ``g2`` are the signals they publish. See
:mod:`cytlmonitor.expressions.base` for how the two signals are aligned
and when the result is published.

Stream expression subtracting the signal of one expression from the
signal of another.

A :class:`DifferenceExpression` wraps two nested
:class:`~cytlmonitor.expressions.base.StreamExpression` instances, ``arg1``
and ``arg2``, and publishes the signal

    f(t) = g1(t) - g2(t)

where ``g1`` and ``g2`` are the signals they publish. See
:mod:`cytlmonitor.expressions.base` for how the two signals are aligned
and when the result is published.

Stream expression multiplying the signals of two other expressions.

A :class:`ProductExpression` wraps two nested
:class:`~cytlmonitor.expressions.base.StreamExpression` instances, ``arg1``
and ``arg2``, and publishes the signal

    f(t) = g1(t) * g2(t)

where ``g1`` and ``g2`` are the signals they publish. See
:mod:`cytlmonitor.expressions.base` for how the two signals are aligned
and when the result is published.

Stream expression dividing the signal of one expression by the signal of
another.

A :class:`DivisionExpression` wraps two nested
:class:`~cytlmonitor.expressions.base.StreamExpression` instances, ``arg1``
and ``arg2``, and publishes the signal

    f(t) = g1(t) / g2(t)

where ``g1`` and ``g2`` are the signals they publish. See
:mod:`cytlmonitor.expressions.base` for how the two signals are aligned
and when the result is published.

The quotient of two polynomials is not a polynomial in general, so, as
for :meth:`~cytlmonitor.core.polynomial.Polynomial.div`, every segment of
``g2`` must be a constant: a ``ValueError`` is raised otherwise. Where
``g2`` is 0, ``f`` is 0.

Stream expression negating the signal of another expression.

A :class:`NegationExpression` wraps a nested
:class:`~cytlmonitor.expressions.base.StreamExpression` ``arg`` and
publishes the signal

    f(t) = -g(t)

where ``g`` is the signal published by ``arg``. Every segment ``arg``
publishes is negated and published at once, over the same interval.

Stream expression computing the absolute value of the signal of another
expression.

An :class:`AbsExpression` wraps a nested
:class:`~cytlmonitor.expressions.base.StreamExpression` ``arg`` and
publishes the signal

    f(t) = |g(t)|

where ``g`` is the signal published by ``arg``. Every segment ``arg``
publishes is split where its polynomial changes sign: the pieces where it
is not negative are published unchanged, the others negated. Splitting
relies on :meth:`~cytlmonitor.core.polynomial.Polynomial.positive`, so the
polynomials of ``arg`` must have degree at most 2: a ``ValueError`` is
raised otherwise.
"""

from __future__ import annotations

from typing import Iterable

from cytlmonitor.core.polynomial import Polynomial
from cytlmonitor.core.segment import Segment
from cytlmonitor.expressions.base import BinaryExpression, UnaryExpression


class SumExpression(BinaryExpression):
    """A StreamExpression publishing, for each time ``t``, the sum of the
    signals of ``arg1`` and ``arg2`` at ``t``."""

    __slots__ = ()

    @staticmethod
    def _apply(p1: Polynomial, p2: Polynomial) -> Polynomial:
        return p1.add(p2)


class DifferenceExpression(BinaryExpression):
    """A StreamExpression publishing, for each time ``t``, the signal of
    ``arg1`` minus the signal of ``arg2`` at ``t``."""

    __slots__ = ()

    @staticmethod
    def _apply(p1: Polynomial, p2: Polynomial) -> Polynomial:
        return p1.sub(p2)


class ProductExpression(BinaryExpression):
    """A StreamExpression publishing, for each time ``t``, the product of the
    signals of ``arg1`` and ``arg2`` at ``t``."""

    __slots__ = ()

    @staticmethod
    def _apply(p1: Polynomial, p2: Polynomial) -> Polynomial:
        return p1.mul(p2)


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


class NegationExpression(UnaryExpression):
    """A StreamExpression publishing, for each time ``t``, the opposite of
    the signal of ``arg`` at ``t``."""

    __slots__ = ()

    def _apply(self, s: Segment) -> Iterable[Segment]:
        return [Segment(s.interval, Polynomial.ZERO.sub(s.polynomial))]


class AbsExpression(UnaryExpression):
    """A StreamExpression publishing, for each time ``t``, the absolute
    value of the signal of ``arg`` at ``t``."""

    __slots__ = ()

    def _apply(self, s: Segment) -> Iterable[Segment]:
        p = s.polynomial
        negated = Polynomial.ZERO.sub(p)
        return [Segment(piece, p if non_negative else negated)
                for piece, non_negative in p.positive(s.interval, strict=False)]
