"""
cytlmonitor.monitors.constants
==============================
Constant monitors.


Monitor whose boolean signal is always true.

A :class:`TrueMonitor` is an :class:`~cytlmonitor.monitors.base.EventMonitor`
that, at each consumed :class:`~cytlmonitor.events.event.Event`, publishes the
interval ``[last, e.time)`` going from the time of the previous event (0
at the beginning) up to the new one. The published intervals therefore
cover ``[0, t)``, where ``t`` is the time of the last event, without gaps,
each lying before the next. After each event the horizon of every
consumer is moved forward to the event's time.

Monitor whose boolean signal is always false.

A :class:`FalseMonitor` is an :class:`~cytlmonitor.monitors.base.EventMonitor`
that never publishes an interval: a boolean signal is published as the
intervals where it is true, and this one is true nowhere. Each consumed
:class:`~cytlmonitor.events.event.Event` only moves the horizon of its consumers
forward to the event's time. Consumed events must be ordered by time, as
for :class:`~cytlmonitor.monitors.constants.TrueMonitor`.
"""

from __future__ import annotations

from cytlmonitor.core.interval import Interval
from cytlmonitor.events.event import Event
from cytlmonitor.monitors.base import EventMonitor


class TrueMonitor(EventMonitor):
    """An EventMonitor publishing a signal that is true everywhere up to the
    last consumed event."""

    __slots__ = ('_last',)

    def __str__(self) -> str:
        return 'true'

    def __init__(self):
        super().__init__()
        self._last = 0.0

    def consume(self, e: Event) -> None:
        """Publish ``[last, e.time)``, invoke ``set_horizon(e.time)`` on
        every consumer and set ``last`` to ``e.time``.

        No interval is published when ``e.time`` equals ``last``, since it
        would be empty; the horizon is still set. Raises a ``ValueError``
        if ``e.time`` is smaller than ``last``.
        """
        if not isinstance(e, Event):
            raise TypeError(f"Expected an Event, got {type(e).__name__}")
        time = e.time
        if time < self._last:
            raise ValueError(
                f"Events must be ordered by time: got {time} after {self._last}."
            )
        if time > self._last:
            self.publish(Interval(self._last, time))
        self._last = time
        self.publish_horizon(time)


class FalseMonitor(EventMonitor):
    """An EventMonitor publishing a signal that is false everywhere."""

    __slots__ = ('_last',)

    def __str__(self) -> str:
        return 'false'

    def __init__(self):
        super().__init__()
        self._last = 0.0

    def consume(self, e: Event) -> None:
        """Invoke ``set_horizon(e.time)`` on every consumer and set
        ``last`` to ``e.time``, without publishing any interval.

        Raises a ``ValueError`` if ``e.time`` is smaller than ``last``.
        """
        if not isinstance(e, Event):
            raise TypeError(f"Expected an Event, got {type(e).__name__}")
        time = e.time
        if time < self._last:
            raise ValueError(
                f"Events must be ordered by time: got {time} after {self._last}."
            )
        self._last = time
        self.publish_horizon(time)
