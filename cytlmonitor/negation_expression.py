"""
cytlmonitor.negation_expression
=================================
Stream expression negating the signal of another expression.

A :class:`NegationExpression` wraps a nested
:class:`~cytlmonitor.stream_expression.StreamExpression` ``arg`` and
publishes the signal

    f(t) = -g(t)

where ``g`` is the signal published by ``arg``. Every segment ``arg``
publishes is negated and published at once, over the same interval.
"""

from __future__ import annotations

from typing import Iterable

from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.unary_expression import UnaryExpression


class NegationExpression(UnaryExpression):
    """A StreamExpression publishing, for each time ``t``, the opposite of
    the signal of ``arg`` at ``t``."""

    __slots__ = ()

    def _apply(self, s: Segment) -> Iterable[Segment]:
        return [Segment(s.interval, Polynomial.ZERO.sub(s.polynomial))]
