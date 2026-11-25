"""
cytlmonitor.events.relations
============================
Relations associating each event of a stream with an event of its past.


Base class for processors that relate each event to a past one.

An :class:`EventRelation` is an :class:`~cytlmonitor.events.processor.EventProcessor`
that forwards every incoming :class:`~cytlmonitor.events.event.Event` unchanged.
Before forwarding, it calls :meth:`EventRelation.record`, which concrete
relations implement to return the event the incoming one is related to, or
``None``. That event can then be looked up with :meth:`EventRelation.get`,
and :meth:`EventRelation.eval` lifts a function on events to one evaluated on
the related event.

An event can only be related to an event of its past: one processed by the
relation before it. The relation is therefore known as soon as the event
arrives, and it never changes afterwards. :meth:`EventRelation.process`
raises :class:`ValueError` if :meth:`EventRelation.record` returns any other
event, the incoming event itself included.

Relation associating each event with the one preceding it in a stream.

A :class:`PreviousRelation` is an :class:`~cytlmonitor.events.relations.EventRelation`
that maps every recorded :class:`~cytlmonitor.events.event.Event` to the event
recorded just before it. The first event of the stream has no previous
event, so it is left unmapped.

Relation associating each event with the event that opened its session.

A :class:`SessionRelation` is an :class:`~cytlmonitor.events.relations.EventRelation`
built from two functions ``f_open`` and ``f_close``, each mapping an event to
an optional integer, the index of a session. It keeps the open sessions, a map
from indexes to the events that opened them. When an event ``e`` arrives:

1. if ``f_close(e)`` is an index ``i`` mapped to an event ``e'``, then ``e``
   is related to ``e'``; otherwise ``e`` is left unmapped;
2. then, if ``f_open(e)`` is an index ``j``, ``j`` is mapped to ``e``,
   replacing any event previously mapped to ``j``.

Closing is evaluated first, so ``e`` is never related to itself, and an event
that closes and reopens the same index is related to the event that opened
it before. Closing an index does not remove it from the open sessions: it is
only replaced by the next event opening it.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Callable, Dict, Optional, Set

from cytlmonitor.events.event import Event
from cytlmonitor.events.processor import EventProcessor


class EventRelation(EventProcessor):
    """An EventProcessor that records, for each processed event, the past
    event it is related to."""

    __slots__ = ('_map', '_past')

    def __init__(self):
        super().__init__()
        self._map: Dict[Event, Event] = {}
        # The events processed so far.
        self._past: Set[Event] = set()

    def get(self, e: Event) -> Optional[Event]:
        """Return the event ``e`` is mapped to, or ``None`` if there is none."""
        return self._map.get(e)

    def eval(self, f: Callable[[Event], float], v: float) -> Callable[[Event], float]:
        """Return the function mapping an event ``e`` to ``f(e')`` if ``e``
        is mapped to ``e'``, and to ``v`` if it is not mapped.

        The returned function looks the mapping up each time it is called,
        so it reflects the events processed so far.
        """
        if not callable(f):
            raise TypeError(f"Expected a callable, got {type(f).__name__}")

        def evaluate(e: Event) -> float:
            related = self._map.get(e)
            return v if related is None else f(related)

        return evaluate

    @abstractmethod
    def record(self, e: Event) -> Optional[Event]:
        """Return the event ``e`` is related to, which must have been
        processed before ``e``, or ``None`` if there is none."""

    def process(self, e: Event) -> Optional[Event]:
        """Record the past event ``e`` is related to and return ``e``
        unchanged.

        Raises ValueError if :meth:`record` returns an event not processed
        before ``e``.
        """
        related = self.record(e)
        if related is None:
            self._map.pop(e, None)
        elif related in self._past:
            self._map[e] = related
        else:
            raise ValueError(
                f"An event can only be related to a past event: {related} "
                f"was not processed before {e}."
            )
        self._past.add(e)
        return e


class PreviousRelation(EventRelation):
    """An EventRelation associating each event with its previous event in
    the stream."""

    __slots__ = ('_previous',)

    def __init__(self):
        super().__init__()
        self._previous: Optional[Event] = None

    def record(self, e: Event) -> Optional[Event]:
        """Return the previously recorded event, if any, then make ``e``
        the previous event."""
        previous, self._previous = self._previous, e
        return previous


class SessionRelation(EventRelation):
    """An EventRelation associating each event closing a session with the
    latest event that opened it."""

    __slots__ = ('_f_open', '_f_close', '_open')

    def __init__(self, f_open: Callable[[Event], Optional[int]],
                 f_close: Callable[[Event], Optional[int]]):
        super().__init__()
        if not callable(f_open):
            raise TypeError(f"Expected a callable, got {type(f_open).__name__}")
        if not callable(f_close):
            raise TypeError(f"Expected a callable, got {type(f_close).__name__}")
        self._f_open = f_open
        self._f_close = f_close
        # The latest event opening each index.
        self._open: Dict[int, Event] = {}

    @property
    def f_open(self) -> Callable[[Event], Optional[int]]:
        """The function giving the index of the session an event opens."""
        return self._f_open

    @property
    def f_close(self) -> Callable[[Event], Optional[int]]:
        """The function giving the index of the session an event closes."""
        return self._f_close

    def opened(self, i: int) -> Optional[Event]:
        """Return the latest event that opened index ``i``, or ``None``."""
        return self._open.get(i)

    def record(self, e: Event) -> Optional[Event]:
        """Return the event that opened the index ``e`` closes, if any, then
        make ``e`` the event opening the index it opens, if any."""
        i = self._f_close(e)
        related = None if i is None else self._open.get(i)
        j = self._f_open(e)
        if j is not None:
            self._open[j] = e
        return related
