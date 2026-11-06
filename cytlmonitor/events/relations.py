"""
cytlmonitor.events.relations
============================
Relations between consecutive events of a stream.


Base class for processors that relate each event to a previous one.

An :class:`EventRelation` is an :class:`~cytlmonitor.events.processor.EventProcessor`
that forwards every incoming :class:`~cytlmonitor.events.event.Event` unchanged.
Before forwarding, it calls :meth:`EventRelation.record`, which concrete
relations implement to store, in a private map, the event each incoming
event is related to. That event can then be looked up with
:meth:`EventRelation.get`.

Relation associating each event with the one preceding it in a stream.

A :class:`PreviousRelation` is an :class:`~cytlmonitor.events.relations.EventRelation`
that maps every recorded :class:`~cytlmonitor.events.event.Event` to the event
recorded just before it. The first event of the stream has no previous
event, so it is left unmapped.

Relation associating each event with the one following it in a stream.

A :class:`NextRelation` is an :class:`~cytlmonitor.events.relations.EventRelation`
that maps every recorded :class:`~cytlmonitor.events.event.Event` to the event
recorded just after it. An event becomes mapped only once its successor
has been recorded, so the last event seen so far is left unmapped.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Dict, Optional

from cytlmonitor.events.event import Event
from cytlmonitor.events.processor import EventProcessor


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


class PreviousRelation(EventRelation):
    """An EventRelation associating each event with its previous event in
    the stream."""

    __slots__ = ('_previous',)

    def __init__(self):
        super().__init__()
        self._previous: Optional[Event] = None

    def record(self, e: Event) -> None:
        """Map ``e`` to the previously recorded event, if any, then make
        ``e`` the previous event."""
        if self._previous is not None:
            self._map[e] = self._previous
        self._previous = e


class NextRelation(EventRelation):
    """An EventRelation associating each event with its next event in the
    stream."""

    __slots__ = ('_previous',)

    def __init__(self):
        super().__init__()
        self._previous: Optional[Event] = None

    def record(self, e: Event) -> None:
        """Map the previously recorded event, if any, to ``e``, then make
        ``e`` the previous event."""
        if self._previous is not None:
            self._map[self._previous] = e
        self._previous = e
