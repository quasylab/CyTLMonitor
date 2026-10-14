"""
cytlmonitor.constant_expression
=================================
Stream expression whose signal is a constant.

A :class:`ConstantExpression` publishes the signal ``f(t) = value``. At
each consumed :class:`~cytlmonitor.event.Event` it publishes a constant
segment over ``[last, e.time)``, from the time of the previous event (0 at
the beginning) up to the new one, so that its signal is known exactly as
far as the stream has been read. It is typically compared with another
expression, as a threshold.
"""

from __future__ import annotations

from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.stream_expression import StreamExpression


class ConstantExpression(StreamExpression):
    """A StreamExpression publishing a constant signal up to the last
    consumed event."""

    __slots__ = ('_value', '_last')

    def __init__(self, value: float):
        super().__init__()
        self._value = float(value)
        self._last = 0.0

    @property
    def value(self) -> float:
        """The constant value of the signal."""
        return self._value

    def consume(self, e: Event) -> None:
        """Publish ``value`` over ``[last, e.time)`` and set ``last`` to
        ``e.time``.

        Nothing is published when ``e.time`` equals ``last``. Raises a
        ``ValueError`` if ``e.time`` is smaller than ``last``.
        """
        if not isinstance(e, Event):
            raise TypeError(f"Expected an Event, got {type(e).__name__}")
        time = e.time
        if time < self._last:
            raise ValueError(
                f"Events must be ordered by time: got {time} after {self._last}."
            )
        if time > self._last:
            self.publish(Segment(Interval(self._last, time), Polynomial([self._value])))
        self._last = time
