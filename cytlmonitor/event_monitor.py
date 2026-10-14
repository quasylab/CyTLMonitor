"""
cytlmonitor.event_monitor
===========================
Base class for monitors that turn a stream of events into a boolean
signal.

An :class:`EventMonitor` is an :class:`~cytlmonitor.event_consumer.EventConsumer`
whose :meth:`EventMonitor.consume` method is left to concrete classes. The
intervals those classes compute are sent, via :meth:`EventMonitor.publish`,
to every :class:`~cytlmonitor.boolean_signal_consumer.BooleanSignalConsumer`
attached with :meth:`EventMonitor.add`, and how far the signal is known
is sent to them via :meth:`EventMonitor.publish_horizon`. As those
consumers expect, intervals should be published in order, each before the
next (see :meth:`~cytlmonitor.interval.Interval.is_before`), and horizons
should never move back, nor before the end of a published interval.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import List

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.interval import Interval


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
