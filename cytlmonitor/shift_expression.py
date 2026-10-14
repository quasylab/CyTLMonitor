"""
cytlmonitor.shift_expression
==============================
Stream expression shifting the signal of another expression in time.

A :class:`ShiftExpression` wraps a nested
:class:`~cytlmonitor.stream_expression.StreamExpression` ``arg`` and
publishes the signal

    f(x) = g(x - t)

for ``x >= 0``, where ``g`` is the signal published by ``arg``. Every
segment ``arg`` publishes is shifted by ``t`` with
:meth:`~cytlmonitor.segment.Segment.shift` and published at once:

- if ``t`` is positive, the signal moves forward, and the stretch before
  the first shifted segment is filled with a constant 0 segment,
  published just before it;
- if ``t`` is negative, the signal moves back: the parts falling before 0
  are dropped, and segments falling entirely before 0 are not published.
"""

from __future__ import annotations

from typing import Iterable, List

from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.unary_expression import UnaryExpression


class ShiftExpression(UnaryExpression):
    """A StreamExpression publishing, for each time ``x``, the signal of
    ``arg`` at ``x - t``."""

    __slots__ = ('_t', '_started')

    def __init__(self, arg: StreamExpression, t: float):
        super().__init__(arg)
        self._t = float(t)
        # True once the first shifted segment has been published.
        self._started = False

    @property
    def t(self) -> float:
        """The shift applied to the signal of ``arg``."""
        return self._t

    def _apply(self, s: Segment) -> Iterable[Segment]:
        shifted = s.shift(self._t)
        if shifted is None:
            return []
        result: List[Segment] = []
        if not self._started:
            self._started = True
            start = shifted.interval
            if self._t > 0 and start.start > 0:
                gap = Interval(0.0, start.start, right_open=not start.left_open)
                result.append(Segment(gap, Polynomial.ZERO))
        result.append(shifted)
        return result
