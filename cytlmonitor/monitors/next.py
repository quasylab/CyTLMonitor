"""
cytlmonitor.monitors.next
=========================
Monitor for the next modality.

A :class:`NextMonitor` wraps a predicate ``beta`` on events, two bounds
``0 <= a < b`` (``b`` may be ``math.inf``) and a nested
:class:`~cytlmonitor.monitors.base.EventMonitor` ``inner``, and publishes
the signal of the formula ``<beta>[a, b] inner``: true at ``t`` exactly when
the next event after ``t``, observed at some time ``t'``, satisfies

- ``t + a <= t' <= t + b``,
- ``beta`` holds for it, and
- the signal of ``inner`` is true at ``t'``.

The *next event after* ``t`` is the first event, in stream order, whose time
is strictly greater than ``t``. When several events share that time, only the
first of them is the next event, and only it is tested with ``beta``.

Every consumed :class:`~cytlmonitor.events.event.Event` is passed to
``inner``, and a :class:`~cytlmonitor.monitors.base.MonitorInput` installed
in it collects the intervals and horizons it publishes.

Let ``l`` be the time of the latest event (0 at the beginning). When an event
arrives at a time ``τ > l``, it is the next event for every ``t`` in
``[l, τ)``, so the signal on that stretch is settled up to the value of
``inner`` at ``τ``: if ``beta`` holds for the event, the signal is true on

    [max(l, τ - b), τ - a] ∩ [l, τ)

when ``inner`` is true at ``τ``, and false on the rest of ``[l, τ)``; if
``beta`` does not hold, the signal is false on the whole of ``[l, τ)``.
Events at time ``l`` are not the next event for any ``t`` and only reach
``inner``.

The stretches waiting for the value of ``inner`` are queued in time order.
That value is known as soon as ``inner`` publishes an interval containing
``τ``, or a horizon beyond ``τ``; the stretches are then settled in order, and
those found true are published. The signal is known up to the start of the
first stretch still waiting, or up to ``l`` if there is none: after ``l`` it
depends on when the next event arrives. That point is published as the new
horizon when it has grown.

As for the binary monitors, the signal is advanced once ``inner`` has
processed the event, so that the stretch the event opens is settled at once
when ``inner`` already knows its value at ``τ``.

This relies on ``inner`` never publishing, after horizon ``h``, an interval
starting before ``h``.
"""

from __future__ import annotations

from collections import deque
from typing import Callable, Deque, Optional, Tuple

from cytlmonitor.core.interval import Interval
from cytlmonitor.core.node import function_name, operand, window
from cytlmonitor.events.event import Event
from cytlmonitor.monitors.base import EventMonitor, MonitorInput


class NextMonitor(EventMonitor):
    """An EventMonitor publishing where the next event arrives within
    ``[a, b]`` from now, satisfies ``beta``, and finds the signal of
    ``inner`` true."""

    __slots__ = ('_beta', '_a', '_b', '_inner', '_input', '_pending', '_last',
                 '_horizon', '_consuming')

    @property
    def operands(self) -> tuple:
        return (self.inner,)

    def __str__(self) -> str:
        return f"<{function_name(self.beta, 'beta')}>{window(self.a, self.b)} {operand(self.inner)}"

    def __init__(self, beta: Callable[[Event], bool], a: float, b: float,
                 inner: EventMonitor):
        super().__init__()
        if not callable(beta):
            raise TypeError(f"Expected a callable, got {type(beta).__name__}")
        if not isinstance(inner, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(inner).__name__}")
        a = float(a)
        b = float(b)
        if not 0.0 <= a < b:
            raise ValueError(f"Expected 0 <= a < b, got a = {a} and b = {b}.")
        self._beta = beta
        self._a = a
        self._b = b
        self._inner = inner
        self._input = MonitorInput(self)
        # Pairs (time of a next event, stretch made true by it if inner is
        # true at that time), ordered by time, waiting for inner.
        self._pending: Deque[Tuple[float, Interval]] = deque()
        # Time of the latest event (0 at the beginning).
        self._last = 0.0
        # The output is published on [0, horizon).
        self._horizon = 0.0
        # True while an event is passed to inner: advancing waits until it
        # has processed it.
        self._consuming = False
        inner.add(self._input)

    @property
    def beta(self) -> Callable[[Event], bool]:
        """The predicate the next event must satisfy."""
        return self._beta

    @property
    def a(self) -> float:
        """The earliest delay, from now, of the next event."""
        return self._a

    @property
    def b(self) -> float:
        """The latest delay, from now, of the next event."""
        return self._b

    @property
    def inner(self) -> EventMonitor:
        """The monitor whose signal must be true when the next event arrives."""
        return self._inner

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``inner``; if ``e`` is later than the previous
        event, record the stretch for which it is the next event, then
        publish what has been settled."""
        if not isinstance(e, Event):
            raise TypeError(f"Expected an Event, got {type(e).__name__}")
        time = e.time
        if time < self._last:
            raise ValueError(
                f"Events must be ordered by time: got {time} after {self._last}."
            )
        self._consuming = True
        try:
            self._inner.consume(e)
        finally:
            self._consuming = False
        if time > self._last:
            if self._beta(e):
                stretch = self._stretch(time)
                if stretch is not None:
                    self._pending.append((time, stretch))
            self._last = time
        self._advance()

    def _stretch(self, time: float) -> Optional[Interval]:
        """The part of ``[last, time)`` lying in ``[time - b, time - a]``,
        or None if it is empty."""
        start = max(self._last, time - self._b)
        if self._a == 0.0:
            return Interval(start, time)
        end = time - self._a
        if end < start:
            return None
        return Interval(start, end, right_open=False)

    def _inner_at(self, time: float) -> Optional[bool]:
        """The signal of ``inner`` at ``time``, or None if not known yet."""
        for i in self._input.intervals:
            if i.contains(time):
                return True
            if i.start > time:
                break
        return False if self._input.horizon > time else None

    def _advance(self) -> None:
        """Settle the waiting stretches whose value of ``inner`` is known,
        publish those that are true, then the new horizon."""
        if self._consuming:
            return
        while self._pending:
            time, stretch = self._pending[0]
            value = self._inner_at(time)
            if value is None:
                break
            self._pending.popleft()
            if value:
                self.publish(stretch)
        if self._pending:
            time, stretch = self._pending[0]
            target = stretch.start
            self._input.discard_before(time)
        else:
            target = self._last
            self._input.discard_before(self._last)
        if target > self._horizon:
            self._horizon = target
            self.publish_horizon(target)
