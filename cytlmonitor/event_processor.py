"""
cytlmonitor.event_processor
=============================
Base class for consumers that transform events and forward them downstream.

An :class:`EventProcessor` is an :class:`~cytlmonitor.event_consumer.EventConsumer`
that maps each incoming :class:`~cytlmonitor.event.Event` through
:meth:`EventProcessor.process`. When the result is not ``None``, it is
forwarded, in registration order, to every consumer attached with
:meth:`EventProcessor.add`.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import List, Optional

from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer


class EventProcessor(EventConsumer):
    """An EventConsumer that processes events and forwards the results to
    a list of downstream consumers."""

    __slots__ = ('_consumers',)

    def __init__(self):
        self._consumers: List[EventConsumer] = []

    def add(self, ec: EventConsumer) -> None:
        """Append ``ec`` to the end of the list of downstream consumers."""
        if not isinstance(ec, EventConsumer):
            raise TypeError(f"Expected an EventConsumer, got {type(ec).__name__}")
        self._consumers.append(ec)

    @abstractmethod
    def process(self, e: Event) -> Optional[Event]:
        """Process ``e`` and return the Event to forward, or ``None`` if
        nothing has to be forwarded."""

    def consume(self, e: Event) -> None:
        """Process ``e`` and, if the result is not ``None``, pass it to
        every downstream consumer."""
        e2 = self.process(e)
        if e2 is not None:
            for ec in self._consumers:
                ec.consume(e2)
