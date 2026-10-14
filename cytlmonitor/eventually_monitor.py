"""
cytlmonitor.eventually_monitor
================================
Monitor checking whether the boolean signal of another monitor becomes
true within a time window.

An :class:`EventuallyMonitor` wraps a nested
:class:`~cytlmonitor.event_monitor.EventMonitor` ``arg`` and an
:class:`~cytlmonitor.interval.Interval` ``i_arg``, and publishes a signal
that is true at ``t`` exactly when the signal of ``arg`` is true at some
``t + t'`` with ``t'`` in ``i_arg``.

Every consumed :class:`~cytlmonitor.event.Event` is passed to ``arg``.
Every time ``arg`` publishes an interval ``i2``, the interval
``i3 = i2.backward(i_arg)`` (see
:meth:`~cytlmonitor.interval.Interval.backward`) is computed: the part of
it after ``last``, the end of what was published so far (0 at the
beginning), is published, ``last`` is moved to ``i3.end``, and the
horizon is published at ``last`` when it has grown. Consecutive ``i3``
may overlap, so starting from ``last`` keeps the published intervals
disjoint; nothing is published when ``i3`` does not reach beyond
``last``.

Every time ``arg`` publishes a horizon ``h``, the window ``[t + a, t + b]``
of every ``t < h - b`` (``a`` and ``b`` being the bounds of ``i_arg``)
lies where ``arg`` is known, so ``h - b`` is published as the horizon when
it is greater than both the previous horizon and ``last``. When ``i_arg``
is right unbounded, the horizons of ``arg`` give nothing.

A right-unbounded ``i3`` has no end, so it is published but no horizon
follows, and nothing is published after it.
"""

from __future__ import annotations

from typing import Optional

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval


class _Collector(BooleanSignalConsumer):
    """BooleanSignalConsumer installed in ``arg``, forwarding its intervals
    to the owning EventuallyMonitor."""

    __slots__ = ('_owner',)

    def __init__(self, owner: 'EventuallyMonitor'):
        self._owner = owner

    def consume(self, i: Interval) -> None:
        self._owner._receive(i)

    def set_horizon(self, t: float) -> None:
        self._owner._advance(t)


class EventuallyMonitor(EventMonitor):
    """An EventMonitor publishing where the signal of ``arg`` is true at
    some point of ``i_arg`` from now."""

    __slots__ = ('_arg', '_i_arg', '_last', '_last_included', '_horizon')

    def __init__(self, arg: EventMonitor, i_arg: Interval):
        super().__init__()
        if not isinstance(arg, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(arg).__name__}")
        if not isinstance(i_arg, Interval):
            raise TypeError(f"Expected an Interval, got {type(i_arg).__name__}")
        self._arg = arg
        self._i_arg = i_arg
        # End of what was published so far (None for +inf).
        self._last: Optional[float] = 0.0
        # True if the point ``last`` itself has been published.
        self._last_included = False
        # The last horizon published.
        self._horizon = 0.0
        arg.add(_Collector(self))

    @property
    def arg(self) -> EventMonitor:
        """The monitor whose signal is looked ahead at."""
        return self._arg

    @property
    def i_arg(self) -> Interval:
        """The window, relative to the current time, where ``arg`` must
        become true."""
        return self._i_arg

    @property
    def last(self) -> Optional[float]:
        """The end of what was published so far (None for +inf)."""
        return self._last

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``arg``; the intervals it publishes are moved back
        by ``i_arg`` and published."""
        self._arg.consume(e)

    def _receive(self, i2: Interval) -> None:
        """Publish the part of ``i2.backward(i_arg)`` after ``last``, then
        the new horizon."""
        if self._last is None:
            return
        i3 = i2.backward(self._i_arg)
        if i3 is None:
            return

        last, included = self._last, self._last_included
        if i3.start > last:
            start, left_open = i3.start, i3.left_open
        elif i3.start == last:
            start, left_open = last, i3.left_open or included
        else:
            start, left_open = last, included
        end, right_open = i3.end, i3.right_open
        if end is not None and (end < start or (end == start and (left_open or right_open))):
            return

        self.publish(Interval(start, end, left_open=left_open, right_open=right_open))
        self._last = end
        self._last_included = not right_open
        if end is not None and end > self._horizon:
            self._horizon = end
            self.publish_horizon(end)

    def _advance(self, h: float) -> None:
        """``arg`` is known up to ``h``: publish ``h - i_arg.end`` as the
        horizon if it is beyond both the previous horizon and ``last``."""
        if self._last is None or self._i_arg.end is None:
            return
        known = h - self._i_arg.end
        if known > self._horizon and known >= self._last:
            self._horizon = known
            self.publish_horizon(known)
