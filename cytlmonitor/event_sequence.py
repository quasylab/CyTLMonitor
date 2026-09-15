"""
cytlmonitor.event_sequence
=============================
Representation of a strictly time-ordered sequence of events.

An :class:`EventSequence` holds :class:`~cytlmonitor.event.Event` instances
ordered by their occurrence time: if ``e1`` precedes ``e2`` in the sequence,
then ``e1.get_time() < e2.get_time()``. Events can only be appended at the
end, and only if their time is strictly greater than the time of every event
already in the sequence.
"""

from __future__ import annotations

from typing import Iterable, Iterator, List, Optional

from cytlmonitor.event import Event


class EventSequence:
    """A sequence of Events strictly ordered by occurrence time."""

    __slots__ = ('_events',)

    def __init__(self, events: Optional[Iterable[Event]] = None):
        self._events: List[Event] = []
        if events is not None:
            for event in events:
                self.add(event)

    def add(self, event: Event) -> None:
        """Append ``event`` at the end of the sequence.

        Raises a ``ValueError`` if ``event``'s time is not strictly greater
        than the time of the last event currently in the sequence.
        """
        if not isinstance(event, Event):
            raise TypeError(f"Expected an Event, got {type(event).__name__}")
        if self._events and event.get_time() <= self._events[-1].get_time():
            raise ValueError(
                f"Event time ({event.get_time()}) must be strictly greater than "
                f"the time of the last event in the sequence ({self._events[-1].get_time()})."
            )
        self._events.append(event)

    def length(self) -> int:
        """The number of events in the sequence."""
        return len(self._events)

    def __len__(self) -> int:
        return self.length()

    def __getitem__(self, i: int) -> Event:
        return self._events[i]

    def __iter__(self) -> Iterator[Event]:
        return iter(self._events)

    def __repr__(self) -> str:
        return f"EventSequence({self._events!r})"
