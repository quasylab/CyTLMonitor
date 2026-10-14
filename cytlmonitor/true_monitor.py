"""
cytlmonitor.true_monitor
==========================
Monitor whose boolean signal is always true.

A :class:`TrueMonitor` is an :class:`~cytlmonitor.event_monitor.EventMonitor`
that, at each consumed :class:`~cytlmonitor.event.Event`, publishes the
interval ``[last, e.time)`` going from the time of the previous event (0
at the beginning) up to the new one. The published intervals therefore
cover ``[0, t)``, where ``t`` is the time of the last event, without gaps,
each lying before the next. After each event the horizon of every
consumer is moved forward to the event's time.
"""

from __future__ import annotations

from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval


class TrueMonitor(EventMonitor):
    """An EventMonitor publishing a signal that is true everywhere up to the
    last consumed event."""

    __slots__ = ('_last',)

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
