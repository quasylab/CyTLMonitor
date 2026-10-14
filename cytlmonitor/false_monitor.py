"""
cytlmonitor.false_monitor
===========================
Monitor whose boolean signal is always false.

A :class:`FalseMonitor` is an :class:`~cytlmonitor.event_monitor.EventMonitor`
that never publishes an interval: a boolean signal is published as the
intervals where it is true, and this one is true nowhere. Each consumed
:class:`~cytlmonitor.event.Event` only moves the horizon of its consumers
forward to the event's time. Consumed events must be ordered by time, as
for :class:`~cytlmonitor.true_monitor.TrueMonitor`.
"""

from __future__ import annotations

from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor


class FalseMonitor(EventMonitor):
    """An EventMonitor publishing a signal that is false everywhere."""

    __slots__ = ('_last',)

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
