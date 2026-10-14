"""
cytlmonitor.measure
=====================
Representation of a measure.

A :class:`Measure` wraps a callable that maps an :class:`~cytlmonitor.event.Event`
to a float value. It knows nothing about intervals, signals, or how the
underlying function computes its result; it is purely a named, validated
function of an event, used as the quantitative building block for
monitoring formulas (e.g. counting/min/max operators over a window).
"""

from __future__ import annotations

from typing import Callable, Optional

from cytlmonitor.event import Event


class Measure:
    """A named function mapping an Event to a float value."""

    __slots__ = ('_function', '_name')

    def __init__(self, function: Callable[[Event], float], name: Optional[str] = None):
        if not callable(function):
            raise TypeError(f"Expected a callable, got {type(function).__name__}")
        self._function = function
        self._name = name

    @property
    def name(self) -> Optional[str]:
        """An optional human-readable name for this measure (None if unnamed)."""
        return self._name

    def evaluate(self, event: Event) -> float:
        """Return the value of this measure on ``event``."""
        if not isinstance(event, Event):
            raise TypeError(f"Expected an Event, got {type(event).__name__}")
        return float(self._function(event))

    __call__ = evaluate

    def __repr__(self) -> str:
        if self._name is not None:
            return f"Measure({self._name!r})"
        return f"Measure({self._function!r})"
