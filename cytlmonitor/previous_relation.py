"""
cytlmonitor.previous_relation
===============================
Relation associating each event with the one preceding it in a stream.

A :class:`PreviousRelation` is an :class:`~cytlmonitor.event_relation.EventRelation`
that maps every recorded :class:`~cytlmonitor.event.Event` to the event
recorded just before it. The first event of the stream has no previous
event, so it is left unmapped.
"""

from __future__ import annotations

from typing import Optional

from cytlmonitor.event import Event
from cytlmonitor.event_relation import EventRelation


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
