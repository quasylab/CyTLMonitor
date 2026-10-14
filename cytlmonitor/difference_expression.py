"""
cytlmonitor.difference_expression
=================================
Stream expression subtracting the signal of one expression from the
signal of another.

A :class:`DifferenceExpression` wraps two nested
:class:`~cytlmonitor.stream_expression.StreamExpression` instances, ``arg1``
and ``arg2``, and publishes the signal

    f(t) = g1(t) - g2(t)

where ``g1`` and ``g2`` are the signals they publish. See
:mod:`cytlmonitor.binary_expression` for how the two signals are aligned
and when the result is published.
"""

from __future__ import annotations

from cytlmonitor.binary_expression import BinaryExpression
from cytlmonitor.polynomial import Polynomial


class DifferenceExpression(BinaryExpression):
    """A StreamExpression publishing, for each time ``t``, the signal of
    ``arg1`` minus the signal of ``arg2`` at ``t``."""

    __slots__ = ()

    @staticmethod
    def _apply(p1: Polynomial, p2: Polynomial) -> Polynomial:
        return p1.sub(p2)
