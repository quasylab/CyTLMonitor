"""
cytlmonitor.not_monitor
=========================
Monitor computing the negation of the boolean signal of another monitor.

A :class:`NotMonitor` wraps a nested
:class:`~cytlmonitor.event_monitor.EventMonitor` ``m``. Every consumed
:class:`~cytlmonitor.event.Event` is passed to ``m``, and a
:class:`~cytlmonitor.monitor_input.MonitorInput` installed in it collects
the intervals and horizons it publishes. The published signal is true
exactly where the signal of ``m`` is false.

The signal of ``m`` is known on ``[0, h)``, ``h`` being its horizon.
Whenever ``h`` grows, the part of the newly known stretch where ``m`` is
false is published, followed by the new horizon.

This relies on ``m`` never publishing, after horizon ``h``, an interval
starting before ``h``.
"""

from __future__ import annotations

from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.monitor_input import MonitorInput, complement_within


class NotMonitor(EventMonitor):
    """An EventMonitor publishing the negation of the boolean signal of
    ``m``."""

    __slots__ = ('_m', '_input', '_horizon')

    def __init__(self, m: EventMonitor):
        super().__init__()
        if not isinstance(m, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        self._m = m
        self._input = MonitorInput(self)
        # The output is published on [0, horizon).
        self._horizon = 0.0
        m.add(self._input)

    @property
    def m(self) -> EventMonitor:
        """The monitor being negated."""
        return self._m

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``m``; the intervals and horizons it publishes are
        negated and published."""
        self._m.consume(e)

    def _advance(self) -> None:
        """Publish where ``m`` is false over the newly known part
        ``[horizon, h)``, then the new horizon."""
        target = self._input.horizon
        if target <= self._horizon:
            return
        window = Interval(self._horizon, target)
        for i in complement_within(self._input.restricted_to(window), window):
            self.publish(i)
        self._horizon = target
        self._input.discard_before(target)
        self.publish_horizon(target)
