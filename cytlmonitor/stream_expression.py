"""
cytlmonitor.stream_expression
===============================
Base class for expressions that turn a stream of events into a stream of
signal segments.

A :class:`StreamExpression` is an :class:`~cytlmonitor.event_consumer.EventConsumer`
whose :meth:`~cytlmonitor.event_consumer.EventConsumer.consume` method is
left to concrete classes. The segments those classes compute are sent, via
:meth:`StreamExpression.publish`, to every
:class:`~cytlmonitor.signal_consumer.SignalConsumer` attached with
:meth:`StreamExpression.add`.
"""

from __future__ import annotations

from typing import List, Optional

from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer


class StreamExpression(EventConsumer):
    """An EventConsumer that publishes Segments to a list of
    SignalConsumers. :meth:`consume` remains abstract."""

    __slots__ = ('_consumers',)

    def __init__(self):
        self._consumers: List[SignalConsumer] = []

    def add(self, sc: Optional[SignalConsumer]) -> None:
        """Append ``sc`` to the end of the list of consumers, unless it is
        ``None``."""
        if sc is None:
            return
        if not isinstance(sc, SignalConsumer):
            raise TypeError(f"Expected a SignalConsumer, got {type(sc).__name__}")
        self._consumers.append(sc)

    def publish(self, s: Optional[Segment]) -> None:
        """Pass ``s`` to every consumer, unless it is ``None``."""
        if s is None:
            return
        for sc in self._consumers:
            sc.consume(s)
