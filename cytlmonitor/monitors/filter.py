"""
cytlmonitor.monitors.filter
===========================
Monitor running another monitor on the events satisfying a predicate.

A :class:`FilterMonitor` wraps a predicate ``beta`` on events and a nested
:class:`~cytlmonitor.monitors.base.EventMonitor` ``m``. Every consumed
:class:`~cytlmonitor.events.event.Event` ``e`` is passed to ``m`` if
``beta(e)`` is true, and dropped otherwise. Every interval and horizon that
``m`` publishes is published again, unchanged.

``m`` therefore monitors the sub-stream of the events satisfying ``beta``:
it only sees time advance at those events, so its horizon, and that of the
filter, stays at the time of the last event that passed, however many
events have been dropped since.
"""

from __future__ import annotations

from typing import Callable

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.core.interval import Interval
from cytlmonitor.core.node import function_name, operand
from cytlmonitor.events.event import Event
from cytlmonitor.monitors.base import EventMonitor


class _Forwarder(BooleanSignalConsumer):
    """BooleanSignalConsumer installed in ``m``, publishing again everything
    it receives from the owning FilterMonitor."""

    __slots__ = ('_owner',)

    def __init__(self, owner: 'FilterMonitor'):
        self._owner = owner

    def consume(self, i: Interval) -> None:
        self._owner.publish(i)

    def set_horizon(self, t: float) -> None:
        self._owner.publish_horizon(t)


class FilterMonitor(EventMonitor):
    """An EventMonitor publishing the signal of ``m`` computed on the events
    satisfying ``beta``."""

    __slots__ = ('_beta', '_m')

    @property
    def operands(self) -> tuple:
        return (self.m,)

    def __str__(self) -> str:
        return f"filter[{function_name(self.beta, 'beta')}] {operand(self.m)}"

    def __init__(self, beta: Callable[[Event], bool], m: EventMonitor):
        super().__init__()
        if not callable(beta):
            raise TypeError(f"Expected a callable, got {type(beta).__name__}")
        if not isinstance(m, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        self._beta = beta
        self._m = m
        m.add(_Forwarder(self))

    @property
    def beta(self) -> Callable[[Event], bool]:
        """The predicate selecting the events passed to ``m``."""
        return self._beta

    @property
    def m(self) -> EventMonitor:
        """The monitor fed with the selected events."""
        return self._m

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``m`` if ``beta(e)`` is true; drop it otherwise."""
        if not isinstance(e, Event):
            raise TypeError(f"Expected an Event, got {type(e).__name__}")
        if self._beta(e):
            self._m.consume(e)
