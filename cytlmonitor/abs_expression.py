"""
cytlmonitor.abs_expression
============================
Stream expression computing the absolute value of the signal of another
expression.

An :class:`AbsExpression` wraps a nested
:class:`~cytlmonitor.stream_expression.StreamExpression` ``arg`` and
publishes the signal

    f(t) = |g(t)|

where ``g`` is the signal published by ``arg``. Every segment ``arg``
publishes is split where its polynomial changes sign: the pieces where it
is not negative are published unchanged, the others negated. Splitting
relies on :meth:`~cytlmonitor.polynomial.Polynomial.positive`, so the
polynomials of ``arg`` must have degree at most 2: a ``ValueError`` is
raised otherwise.
"""

from __future__ import annotations

from typing import Iterable

from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.unary_expression import UnaryExpression


class AbsExpression(UnaryExpression):
    """A StreamExpression publishing, for each time ``t``, the absolute
    value of the signal of ``arg`` at ``t``."""

    __slots__ = ()

    def _apply(self, s: Segment) -> Iterable[Segment]:
        p = s.polynomial
        negated = Polynomial.ZERO.sub(p)
        return [Segment(piece, p if non_negative else negated)
                for piece, non_negative in p.positive(s.interval, strict=False)]
