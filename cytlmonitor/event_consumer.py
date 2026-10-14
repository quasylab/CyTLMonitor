"""
cytlmonitor.event_consumer
============================
Interface for objects that process streams of events.

An :class:`EventConsumer` receives :class:`~cytlmonitor.event.Event`
instances one at a time through :meth:`EventConsumer.consume`. Concrete
classes implement this method to define how each incoming event is
processed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from cytlmonitor.event import Event


class EventConsumer(ABC):
    """Interface implemented by classes that process a stream of Events."""

    __slots__ = ()

    @abstractmethod
    def consume(self, event: Event) -> None:
        """Process a single incoming ``event``."""
