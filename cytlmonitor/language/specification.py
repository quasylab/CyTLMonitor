"""
cytlmonitor.language.specification
==================================
The monitors and expressions built from a specification, fed together.

A :class:`Specification` is what :func:`cytlmonitor.language.parse` returns.
It holds one monitor per property and one expression per measure of the
specification, each built once, and is the
:class:`~cytlmonitor.events.consumer.EventConsumer` to feed the events to:
for every event it first updates, in the order they are written, the links
(the :class:`~cytlmonitor.events.relations.EventRelation` instances), the
counters and the time averages, and then passes the event to every property
and to every measure. The properties and the measures read the links and the
counters, so they must not be fed directly.

The monitors and expressions are ordinary nodes: consumers, plots for
instance, can be attached to them, or to any node of their trees (see
:mod:`cytlmonitor.core.node`), before the events are fed. :meth:`plot`
plots some of them by name.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional, Sequence, Union

from cytlmonitor.core.node import FormulaNode
from cytlmonitor.events.consumer import EventConsumer
from cytlmonitor.events.event import Event
from cytlmonitor.events.relations import EventRelation


class Counter:
    """A counter: a number changed by the events satisfying some
    conditions. Its value at an event includes the change the event
    makes."""

    __slots__ = ('name', 'value', 'changes')

    def __init__(self, name: str, start: float, changes: Sequence[tuple]):
        self.name = name
        self.value = float(start)
        self.changes = tuple(changes)

    def update(self, e: Event) -> None:
        for delta, condition in self.changes:
            if condition(e):
                self.value += delta


class Holding:
    """The weights of a time average: a value is taken to hold from each
    event up to the next one. At each event, ``gap`` is the time since the
    previous event and ``weight`` the value at the previous event times
    ``gap`` (both 0 at the first event, or if the value was none)."""

    __slots__ = ('value', 'last_value', 'last_time', 'weight', 'gap')

    def __init__(self, value: Callable[[Event], object]):
        self.value = value
        self.last_value = None
        self.last_time = None
        self.weight = 0.0
        self.gap = 0.0

    def update(self, e: Event) -> None:
        if self.last_time is None or self.last_value is None:
            self.weight = self.gap = 0.0
        else:
            self.gap = e.time - self.last_time
            self.weight = self.last_value * self.gap
        current = self.value(e)
        self.last_value = None if current is None else float(current)
        self.last_time = e.time


Builder = Callable[[], FormulaNode]


class Specification(EventConsumer):
    """The properties and the measures of a specification, built once each,
    with the links and counters they read."""

    def __init__(self, constants: Dict[str, float], properties: Dict[str, Builder],
                 measures: Dict[str, Builder], show: Sequence[str],
                 relations: Sequence[EventRelation], updaters: Sequence[Callable[[Event], None]]):
        self.constants = dict(constants)
        self._builders = {**measures, **properties}
        self.properties = {name: build() for name, build in properties.items()}
        self.measures = {name: build() for name, build in measures.items()}
        self.relations = tuple(relations)
        self._updaters = tuple(updaters)
        self.show = tuple(show) if show else (*self.properties, *self.measures)
        self._nodes = (*self.properties.values(), *self.measures.values())

    def consume(self, e: Event) -> None:
        """Update the links, the counters and the time averages with ``e``,
        then pass it to every property and to every measure."""
        for relation in self.relations:
            relation.consume(e)
        for update in self._updaters:
            update(e)
        for node in self._nodes:
            node.consume(e)

    def run(self, events: Iterable[Event]) -> 'Specification':
        """Consume ``events``, in order; return this specification."""
        for e in events:
            self.consume(e)
        return self

    def __getitem__(self, name: str) -> FormulaNode:
        """The monitor of the property ``name``, or the expression of the
        measure ``name``."""
        if name in self.properties:
            return self.properties[name]
        if name in self.measures:
            return self.measures[name]
        raise KeyError(f"no property or measure named {name!r}")

    def __contains__(self, name: str) -> bool:
        return name in self.properties or name in self.measures

    def build(self, name: str) -> FormulaNode:
        """A new monitor for the property ``name``, or a new expression for
        the measure ``name``, independent of those held here: it is not fed
        by :meth:`consume`."""
        if name not in self._builders:
            raise KeyError(f"no property or measure named {name!r}")
        return self._builders[name]()

    def plot(self, *names: str, titles: Optional[Dict[str, str]] = None,
             **options) -> List:
        """Plot the properties and measures ``names`` (by default those of
        the ``show`` section, or all of them), each titled with its name or
        with ``titles[name]``; ``options`` are passed to
        :func:`cytlmonitor.consumers.plot.plot`. Return the plotting
        consumers, in order."""
        from cytlmonitor.consumers.plot import plot

        names = names or self.show
        nodes = [self[name] for name in names]
        labels: Dict[FormulaNode, str] = {
            node: (titles or {}).get(name, name) for name, node in zip(names, nodes)}
        return plot(nodes[0], nodes=nodes, titles=labels, **options)

    def __repr__(self) -> str:
        return (f"Specification(properties={list(self.properties)}, "
                f"measures={list(self.measures)})")


__all__: Union[tuple, list] = ('Specification', 'Counter', 'Holding')
