"""
cytlmonitor.binary_monitor
============================
Base class for monitors combining, point by point, the boolean signals of
two other monitors.

A :class:`BinaryMonitor` wraps two nested
:class:`~cytlmonitor.event_monitor.EventMonitor` instances, ``m1`` and
``m2``. Every consumed :class:`~cytlmonitor.event.Event` is passed to
both, and a :class:`~cytlmonitor.boolean_signal_consumer.BooleanSignalConsumer`
installed in each (a :class:`~cytlmonitor.monitor_input.MonitorInput`)
collects the intervals and horizons it publishes.

A monitor whose horizon is ``h`` is known on ``[0, h)``, so the combined
signal is known on ``[0, min(h1, h2))``. Whenever that grows, the two
signals restricted to the newly known part are combined by
:meth:`BinaryMonitor._combine`, which is also given that part, and the
resulting intervals are published,
followed by the new horizon. Intervals lying entirely within the known
part are then discarded.

This relies on a monitor never publishing, after horizon ``h``, an
interval starting before ``h``.
"""

from __future__ import annotations

from abc import abstractmethod

from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.monitor_input import MonitorInput


class BinaryMonitor(EventMonitor):
    """An EventMonitor publishing the boolean signals of ``m1`` and ``m2``
    combined by :meth:`_combine`."""

    __slots__ = ('_m1', '_m2', '_left', '_right', '_horizon')

    def __init__(self, m1: EventMonitor, m2: EventMonitor):
        super().__init__()
        for m in (m1, m2):
            if not isinstance(m, EventMonitor):
                raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        self._m1 = m1
        self._m2 = m2
        self._left = MonitorInput(self)
        self._right = MonitorInput(self)
        # The output is published on [0, horizon).
        self._horizon = 0.0
        m1.add(self._left)
        m2.add(self._right)

    @property
    def m1(self) -> EventMonitor:
        """The first operand."""
        return self._m1

    @property
    def m2(self) -> EventMonitor:
        """The second operand."""
        return self._m2

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``m1`` and ``m2``; the intervals and horizons they
        publish are combined and published. When ``m1`` and ``m2`` are the
        same object, the event is passed only once."""
        self._m1.consume(e)
        if self._m2 is not self._m1:
            self._m2.consume(e)

    @staticmethod
    @abstractmethod
    def _combine(s1: BooleanSignal, s2: BooleanSignal, window: Interval) -> BooleanSignal:
        """Combine the signals of ``m1`` and ``m2``, both restricted to the
        newly known part ``window``. The result must lie within
        ``window``."""

    def _advance(self) -> None:
        """Publish the combined signal over the newly known part
        ``[horizon, min(h1, h2))``, then the new horizon."""
        target = min(self._left.horizon, self._right.horizon)
        if target <= self._horizon:
            return
        window = Interval(self._horizon, target)
        combined = self._combine(self._left.restricted_to(window),
                                 self._right.restricted_to(window), window)
        for i in combined:
            self.publish(i)
        self._horizon = target
        self._left.discard_before(target)
        self._right.discard_before(target)
        self.publish_horizon(target)
