"""
cytlmonitor.binary_expression
===============================
Base class for stream expressions combining, point by point, the signals
of two other expressions.

A :class:`BinaryExpression` wraps two nested
:class:`~cytlmonitor.stream_expression.StreamExpression` instances, ``arg1``
and ``arg2``, and publishes the signal

    f(t) = g1(t) op g2(t)

where ``g1`` and ``g2`` are the signals they publish and ``op`` is chosen
by :meth:`BinaryExpression._apply`. Every consumed
:class:`~cytlmonitor.event.Event` is passed to both. Each of them must
publish contiguous :class:`~cytlmonitor.segment.Segment` instances
starting at 0, possibly at different paces and with different boundaries.

The segments received from each side are queued. As soon as both queues
are non-empty, their front segments start at the same point: the part
they have in common, up to the earlier of their two ends, is published
with their polynomials combined by ``_apply``, and the rest of the longer
one is kept at the front of its queue.
"""

from __future__ import annotations

from abc import abstractmethod
from collections import deque
from typing import Deque, Optional

from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression


def _ends_first(a: Interval, b: Interval) -> bool:
    """True if ``a`` ends strictly before ``b``, given that they start at
    the same point."""
    if a.end is None:
        return False
    if b.end is None:
        return True
    if a.end != b.end:
        return a.end < b.end
    return a.right_open and not b.right_open


class _Side:
    """The segments received from one argument, not yet combined, and where
    the next one must start."""

    __slots__ = ('queue', 'end', 'open')

    def __init__(self):
        self.queue: Deque[Segment] = deque()
        self.end: Optional[float] = 0.0
        self.open = False

    def append(self, s: Segment) -> None:
        interval = s.interval
        if self.end is None or interval.start != self.end or interval.left_open != self.open:
            raise ValueError(
                f"Segments must be contiguous from 0: {interval!r} does not start "
                f"where the previous segment ended."
            )
        self.end = interval.end
        self.open = not interval.right_open
        self.queue.append(s)


class _Collector(SignalConsumer):
    """SignalConsumer installed in an argument, forwarding its segments to
    the owning BinaryExpression."""

    __slots__ = ('_owner', '_side')

    def __init__(self, owner: 'BinaryExpression', side: _Side):
        self._owner = owner
        self._side = side

    def consume(self, s: Segment) -> None:
        self._side.append(s)
        self._owner._combine()


class BinaryExpression(StreamExpression):
    """A StreamExpression publishing, for each time ``t``, the signals of
    ``arg1`` and ``arg2`` at ``t`` combined by :meth:`_apply`."""

    __slots__ = ('_arg1', '_arg2', '_left', '_right')

    def __init__(self, arg1: StreamExpression, arg2: StreamExpression):
        super().__init__()
        for arg in (arg1, arg2):
            if not isinstance(arg, StreamExpression):
                raise TypeError(f"Expected a StreamExpression, got {type(arg).__name__}")
        self._arg1 = arg1
        self._arg2 = arg2
        self._left = _Side()
        self._right = _Side()
        arg1.add(_Collector(self, self._left))
        arg2.add(_Collector(self, self._right))

    @property
    def arg1(self) -> StreamExpression:
        """The first operand."""
        return self._arg1

    @property
    def arg2(self) -> StreamExpression:
        """The second operand."""
        return self._arg2

    def consume(self, event: Event) -> None:
        """Pass ``event`` to ``arg1`` and ``arg2``; the segments they
        publish are combined and published. When ``arg1`` and ``arg2`` are
        the same object, the event is passed only once."""
        self._arg1.consume(event)
        if self._arg2 is not self._arg1:
            self._arg2.consume(event)

    @staticmethod
    @abstractmethod
    def _apply(p1: Polynomial, p2: Polynomial) -> Polynomial:
        """Combine the polynomials of ``arg1`` and ``arg2`` over a stretch
        both of them cover."""

    def _combine(self) -> None:
        """Publish the combined signal over every stretch covered by both
        sides."""
        left, right = self._left.queue, self._right.queue
        while left and right:
            a, b = left[0], right[0]
            if _ends_first(b.interval, a.interval):
                shorter, longer, longer_queue = b, a, left
                right.popleft()
            elif _ends_first(a.interval, b.interval):
                shorter, longer, longer_queue = a, b, right
                left.popleft()
            else:
                shorter, longer, longer_queue = a, None, None
                left.popleft()
                right.popleft()

            common = shorter.interval
            self.publish(Segment(common, self._apply(a.polynomial, b.polynomial)))

            if longer is not None:
                rest = Interval(common.end, longer.interval.end,
                                left_open=not common.right_open,
                                right_open=longer.interval.right_open)
                longer_queue[0] = Segment(rest, longer.polynomial)
