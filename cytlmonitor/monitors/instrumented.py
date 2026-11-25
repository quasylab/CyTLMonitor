"""
cytlmonitor.monitors.instrumented
=================================
Monitor keeping a list of event relations up to date for another monitor.

An :class:`InstrumentedMonitor` wraps a list of
:class:`~cytlmonitor.events.relations.EventRelation` objects and a nested
:class:`~cytlmonitor.monitors.base.EventMonitor` ``m``. Every consumed
:class:`~cytlmonitor.events.event.Event` is first passed to each relation, in
list order, and then to ``m``. Every interval and horizon that ``m``
publishes is published again, unchanged.

The relations have therefore recorded the event when ``m`` receives it, so
the predicates and functions used inside ``m`` can look it up, for instance
through :meth:`~cytlmonitor.events.relations.EventRelation.get` or
:meth:`~cytlmonitor.events.relations.EventRelation.eval`. The relations
receive the event through their ``consume`` method, so they also forward it
to any consumer attached to them.
"""

from __future__ import annotations

from typing import Iterable, Tuple

from cytlmonitor.events.event import Event
from cytlmonitor.events.relations import EventRelation
from cytlmonitor.monitors.base import EventMonitor
from cytlmonitor.monitors.filter import _Forwarder


class InstrumentedMonitor(EventMonitor):
    """An EventMonitor publishing the signal of ``m``, whose events are first
    recorded by a list of relations."""

    __slots__ = ('_relations', '_m')

    @property
    def operands(self) -> tuple:
        return (self.m,)

    def __str__(self) -> str:
        return str(self.m)

    def __init__(self, relations: Iterable[EventRelation], m: EventMonitor):
        super().__init__()
        relations = tuple(relations)
        for r in relations:
            if not isinstance(r, EventRelation):
                raise TypeError(f"Expected an EventRelation, got {type(r).__name__}")
        if not isinstance(m, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        self._relations = relations
        self._m = m
        m.add(_Forwarder(self))

    @property
    def relations(self) -> Tuple[EventRelation, ...]:
        """The relations updated with every event, in the order they are."""
        return self._relations

    @property
    def m(self) -> EventMonitor:
        """The monitor fed with the events once the relations are updated."""
        return self._m

    def consume(self, e: Event) -> None:
        """Pass ``e`` to every relation, in order, then to ``m``."""
        if not isinstance(e, Event):
            raise TypeError(f"Expected an Event, got {type(e).__name__}")
        for r in self._relations:
            r.consume(e)
        self._m.consume(e)
