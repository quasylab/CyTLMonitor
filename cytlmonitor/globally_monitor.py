"""
cytlmonitor.globally_monitor
==============================
Monitor checking whether the boolean signal of another monitor stays true
over a time window.

A :class:`GloballyMonitor` wraps a nested
:class:`~cytlmonitor.event_monitor.EventMonitor` ``arg`` and an
:class:`~cytlmonitor.interval.Interval` ``i_arg``, and publishes a signal
that is true at ``t`` exactly when the signal of ``arg`` is true at every
``t + t'`` with ``t'`` in ``i_arg``.

It works as ``not eventually_{i_arg} not arg``: an inner
:class:`~cytlmonitor.not_monitor.NotMonitor` of an
:class:`~cytlmonitor.eventually_monitor.EventuallyMonitor` of a
:class:`~cytlmonitor.not_monitor.NotMonitor` of ``arg`` computes the
signal, and every interval and horizon it publishes is published again.
Every consumed :class:`~cytlmonitor.event.Event` is passed to it, and so
to ``arg``.
"""

from __future__ import annotations

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.eventually_monitor import EventuallyMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.not_monitor import NotMonitor


class _Forwarder(BooleanSignalConsumer):
    """BooleanSignalConsumer installed in the inner monitor, publishing
    again everything it receives from the owning GloballyMonitor."""

    __slots__ = ('_owner',)

    def __init__(self, owner: 'GloballyMonitor'):
        self._owner = owner

    def consume(self, i: Interval) -> None:
        self._owner.publish(i)

    def set_horizon(self, t: float) -> None:
        self._owner.publish_horizon(t)


class GloballyMonitor(EventMonitor):
    """An EventMonitor publishing where the signal of ``arg`` is true at
    every point of ``i_arg`` from now."""

    __slots__ = ('_arg', '_i_arg', '_inner')

    def __init__(self, arg: EventMonitor, i_arg: Interval):
        super().__init__()
        if not isinstance(arg, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(arg).__name__}")
        if not isinstance(i_arg, Interval):
            raise TypeError(f"Expected an Interval, got {type(i_arg).__name__}")
        self._arg = arg
        self._i_arg = i_arg
        self._inner = NotMonitor(EventuallyMonitor(NotMonitor(arg), i_arg))
        self._inner.add(_Forwarder(self))

    @property
    def arg(self) -> EventMonitor:
        """The monitor whose signal is looked ahead at."""
        return self._arg

    @property
    def i_arg(self) -> Interval:
        """The window, relative to the current time, where ``arg`` must
        stay true."""
        return self._i_arg

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``arg``, through the inner monitors computing the
        signal."""
        self._inner.consume(e)
