"""
cytlmonitor.event_relation
============================
Base class for processors that relate each event to a previous one.

An :class:`EventRelation` is an :class:`~cytlmonitor.event_processor.EventProcessor`
that forwards every incoming :class:`~cytlmonitor.event.Event` unchanged.
Before forwarding, it calls :meth:`EventRelation.record`, which concrete
relations implement to store, in a private map, the event each incoming
event is related to. That event can then be looked up with
:meth:`EventRelation.get`.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Dict, Optional

from cytlmonitor.event import Event
from cytlmonitor.event_processor import EventProcessor


class EventRelation(EventProcessor):
    """An EventProcessor that records, for each processed event, the event
    it is related to."""

    __slots__ = ('_map',)

    def __init__(self):
        super().__init__()
        self._map: Dict[Event, Event] = {}

    def get(self, e: Event) -> Optional[Event]:
        """Return the event ``e`` is mapped to, or ``None`` if there is none."""
        return self._map.get(e)

    @abstractmethod
    def record(self, e: Event) -> None:
        """Store in ``_map`` the event ``e`` is related to, if any."""

    def process(self, e: Event) -> Optional[Event]:
        """Record ``e`` and return it unchanged."""
        self.record(e)
        return e
