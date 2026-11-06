"""
cytlmonitor.monitors.base
=========================
Base class of the online monitors and the input buffer they use.


Base class for monitors that turn a stream of events into a boolean
signal.

An :class:`EventMonitor` is an :class:`~cytlmonitor.events.consumer.EventConsumer`
whose :meth:`EventMonitor.consume` method is left to concrete classes. The
intervals those classes compute are sent, via :meth:`EventMonitor.publish`,
to every :class:`~cytlmonitor.consumers.boolean_signal_consumer.BooleanSignalConsumer`
attached with :meth:`EventMonitor.add`, and how far the signal is known
is sent to them via :meth:`EventMonitor.publish_horizon`. As those
consumers expect, intervals should be published in order, each before the
next (see :meth:`~cytlmonitor.core.interval.Interval.is_before`), and horizons
should never move back, nor before the end of a published interval.

Buffer collecting the boolean signal published by a nested monitor.

A :class:`MonitorInput` is the
:class:`~cytlmonitor.consumers.boolean_signal_consumer.BooleanSignalConsumer` that
monitors built on other monitors install in each of them. It keeps the
intervals received that may still matter and the latest horizon, and asks
its owner to advance every time the horizon moves.

:func:`complement_within` negates a signal collected this way within the
stretch it was restricted to.
"""

from __future__ import annotations

from abc import abstractmethod
from collections import deque
from typing import List, Deque

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.core.boolean_signal import BooleanSignal
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.consumer import EventConsumer
from cytlmonitor.events.event import Event


class EventMonitor(EventConsumer):
    """An EventConsumer that publishes Intervals to a list of
    BooleanSignalConsumers."""

    __slots__ = ('_consumers',)

    def __init__(self):
        self._consumers: List[BooleanSignalConsumer] = []

    def add(self, c: BooleanSignalConsumer) -> None:
        """Append ``c`` to the end of the list of consumers."""
        if not isinstance(c, BooleanSignalConsumer):
            raise TypeError(f"Expected a BooleanSignalConsumer, got {type(c).__name__}")
        self._consumers.append(c)

    def publish(self, i: Interval) -> None:
        """Pass ``i`` to every consumer, in the order they were added."""
        for c in self._consumers:
            c.consume(i)

    def publish_horizon(self, t: float) -> None:
        """Invoke ``set_horizon(t)`` on every consumer, in the order they
        were added."""
        for c in self._consumers:
            c.set_horizon(t)

    @abstractmethod
    def consume(self, e: Event) -> None:
        """Process a single incoming event ``e``."""


def complement_within(signal: BooleanSignal, window: Interval) -> BooleanSignal:
    """Return the parts of ``window`` where ``signal``, whose intervals all
    lie within ``window``, is false. ``window`` must be bounded and open on
    the right, as are the stretches monitors advance by."""
    signal.set_horizon(window.end)
    return signal.complement().intersection(BooleanSignal([window]))


class MonitorInput(BooleanSignalConsumer):
    """BooleanSignalConsumer installed in a nested monitor: keeps the
    intervals it publishes that may still matter, and its horizon. Every
    time the horizon is set, ``owner._advance()`` is invoked."""

    __slots__ = ('_owner', 'intervals', 'horizon')

    def __init__(self, owner):
        self._owner = owner
        self.intervals: Deque[Interval] = deque()
        self.horizon = 0.0

    def consume(self, i: Interval) -> None:
        self.intervals.append(i)

    def set_horizon(self, t: float) -> None:
        self.horizon = float(t)
        self._owner._advance()

    def restricted_to(self, window: Interval) -> BooleanSignal:
        """The part of the collected signal lying within ``window``."""
        signal = BooleanSignal()
        for i in self.intervals:
            part = i.intersection(window)
            if part is not None:
                signal.add(part)
        return signal

    def compact(self) -> None:
        """Merge adjacent intervals, so that a long stretch received in
        pieces is kept as a single interval."""
        self.intervals = deque(BooleanSignal(self.intervals))

    def discard_before(self, t: float) -> None:
        """Drop the intervals lying entirely within ``[0, t)``."""
        while self.intervals and self.intervals[0].is_before(Interval(t)):
            self.intervals.popleft()

    def discard_ending_before(self, t: float) -> None:
        """Drop the intervals ending before ``t``, keeping those ending at
        ``t`` even when they exclude it."""
        while self.intervals and self.intervals[0].end is not None \
                and self.intervals[0].end < t:
            self.intervals.popleft()
