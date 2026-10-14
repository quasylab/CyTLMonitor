"""
cytlmonitor.next_relation
===========================
Relation associating each event with the one following it in a stream.

A :class:`NextRelation` is an :class:`~cytlmonitor.event_relation.EventRelation`
that maps every recorded :class:`~cytlmonitor.event.Event` to the event
recorded just after it. An event becomes mapped only once its successor
has been recorded, so the last event seen so far is left unmapped.
"""

from __future__ import annotations

from typing import Optional

from cytlmonitor.event import Event
from cytlmonitor.event_relation import EventRelation


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
