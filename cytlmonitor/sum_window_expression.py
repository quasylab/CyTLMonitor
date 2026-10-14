"""
cytlmonitor.sum_window_expression
==================================
Stream expression computing a sliding-window sum over events.

A :class:`SumWindowExpression` consumes a stream of :class:`~cytlmonitor.event.Event`
instances, ordered by time, and publishes the piecewise-constant signal

    f(t) = sum of w(e) over the events e with t + from <= e.time <= t + to

for ``t >= 0``, as a sequence of :class:`~cytlmonitor.segment.Segment`
instances.

The value of ``f`` at ``t`` is only known once every event up to
``t + to`` has been seen. Events may share a timestamp, so when an event
at time ``τ`` arrives the signal is published up to ``τ - to``, excluded.
The expression keeps:

- a sliding window holding the events whose time lies in
  ``[cursor + from, cursor + to]``, so it spans at most ``to - from``;
- a time cursor, starting from 0, marking where the next segment begins;
- an accumulator holding the sum of ``w`` over the window.

An event enters the window at ``t = e.time - to``, included, and leaves it
just after ``t = e.time - from``.
"""

from __future__ import annotations

from collections import deque
from typing import Callable, Deque, Optional, Tuple

from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.stream_expression import StreamExpression


class SumWindowExpression(StreamExpression):
    """A StreamExpression publishing, for each time ``t``, the sum of ``w``
    over the events occurring in ``[t + from, t + to]``."""

    __slots__ = ('_w', '_from', '_to', '_window', '_cursor', '_cursor_open',
                 '_accumulator', '_last_time')

    def __init__(self, w: Callable[[Event], float], from_: float, to: float):
        super().__init__()
        if not callable(w):
            raise TypeError(f"Expected a callable, got {type(w).__name__}")
        from_ = float(from_)
        to = float(to)
        if from_ < 0 or to < 0:
            raise ValueError(f"'from' ({from_}) and 'to' ({to}) must be non negative.")
        if from_ >= to:
            raise ValueError(f"'from' ({from_}) must be smaller than 'to' ({to}).")
        self._w = w
        self._from = from_
        self._to = to
        # Pairs (event time, w(event)), ordered by time.
        self._window: Deque[Tuple[float, float]] = deque()
        self._cursor = 0.0
        # True when the cursor time itself has already been published.
        self._cursor_open = False
        self._accumulator = 0.0
        self._last_time: Optional[float] = None

    @property
    def w(self) -> Callable[[Event], float]:
        """The function evaluated on each event."""
        return self._w

    @property
    def from_(self) -> float:
        """Offset, from ``t``, of the start of the window."""
        return self._from

    @property
    def to(self) -> float:
        """Offset, from ``t``, of the end of the window."""
        return self._to

    def consume(self, event: Event) -> None:
        """Publish the signal up to ``event.time - to``, excluded, then add
        ``event`` to the window."""
        if not isinstance(event, Event):
            raise TypeError(f"Expected an Event, got {type(event).__name__}")
        time = event.time
        if self._last_time is not None and time < self._last_time:
            raise ValueError(
                f"Events must be ordered by time: got {time} after {self._last_time}."
            )
        self._last_time = time

        self._advance(time - self._to)

        leaves_at = time - self._from
        if leaves_at < self._cursor or (leaves_at == self._cursor and self._cursor_open):
            # The event leaves the window before the cursor: it never counts.
            return
        value = float(self._w(event))
        self._window.append((time, value))
        self._accumulator += value

    def _advance(self, target: float) -> None:
        """Publish the signal from the cursor up to ``target``, excluded,
        removing the events that leave the window on the way."""
        while self._window and self._window[0][0] - self._from < target:
            leaves_at = self._window[0][0] - self._from
            self._publish_until(leaves_at, right_open=False)
            while self._window and self._window[0][0] - self._from == leaves_at:
                self._accumulator -= self._window.popleft()[1]
            if not self._window:
                # Avoid drift from floating point subtractions.
                self._accumulator = 0.0
        if self._cursor < target:
            self._publish_until(target, right_open=True)

    def _publish_until(self, end: float, right_open: bool) -> None:
        """Publish ``accumulator`` from the cursor up to ``end`` and move the
        cursor to ``end``."""
        interval = Interval(self._cursor, end, left_open=self._cursor_open,
                            right_open=right_open)
        self.publish(Segment(interval, Polynomial([self._accumulator])))
        self._cursor = end
        self._cursor_open = not right_open
