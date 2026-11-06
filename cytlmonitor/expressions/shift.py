"""
cytlmonitor.expressions.shift
=============================
Stream expression shifting the signal of another expression in time.

A :class:`ShiftExpression` wraps a nested
:class:`~cytlmonitor.expressions.base.StreamExpression` ``arg`` and
publishes the signal

    f(x) = g(x - t)

for ``x >= 0``, where ``g`` is the signal published by ``arg``. Every
segment ``arg`` publishes is shifted by ``t`` with
:meth:`~cytlmonitor.core.segment.Segment.shift` and published at once:

- if ``t`` is positive, the signal moves forward, and the stretch before
  the first shifted segment is filled with a constant 0 segment,
  published just before it;
- if ``t`` is negative, the signal moves back: the parts falling before 0
  are dropped, and segments falling entirely before 0 are not published.

With floats, shifting a very short interval may leave nothing of it:
``0.3`` and ``0.30000000000000004`` are both ``10.3`` once 10 is added. Such
a segment is dropped, and each published segment starts exactly where the
previous one ends, containing the shared point only if the previous one
does not, so that the published segments stay contiguous.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from cytlmonitor.core.interval import Interval
from cytlmonitor.core.polynomial import Polynomial
from cytlmonitor.core.segment import Segment
from cytlmonitor.expressions.base import StreamExpression, UnaryExpression


class ShiftExpression(UnaryExpression):
    """A StreamExpression publishing, for each time ``x``, the signal of
    ``arg`` at ``x - t``."""

    __slots__ = ('_t', '_started', '_published', '_end', '_end_included')

    def __init__(self, arg: StreamExpression, t: float):
        super().__init__(arg)
        self._t = float(t)
        # True once the first shifted segment has been published.
        self._started = False
        # True once a segment has been published; then where the last one
        # ends (None for +inf) and whether it holds that point.
        self._published = False
        self._end: Optional[float] = 0.0
        self._end_included = False

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
        return [c for c in (self._continue(r) for r in result) if c is not None]

    def _continue(self, s: Segment) -> Optional[Segment]:
        """``s`` made to start where the last published segment ends, or
        None if nothing of it is left. Shifting moves both ends of the
        intervals by the same ``t``, so a segment already starts there,
        unless rounding has emptied the segment before it: the shared point
        then belongs to the earlier one."""
        if self._published:
            if self._end is None:
                return None
            start, left_open = self._end, self._end_included
            end, right_open = s.interval.end, s.interval.right_open
            if end is not None and (end < start or (end == start and (left_open or right_open))):
                return None
            s = Segment(Interval(start, end, left_open=left_open, right_open=right_open),
                        s.polynomial)
        self._published = True
        self._end = s.interval.end
        self._end_included = not s.interval.right_open
        return s
