"""
cytlmonitor.boolean_signal_consumer
=====================================
Interface for objects that process streams of intervals of a boolean
signal.

A :class:`BooleanSignalConsumer` receives
:class:`~cytlmonitor.interval.Interval` instances one at a time through
:meth:`BooleanSignalConsumer.consume`, and is told how far the signal is
known through :meth:`BooleanSignalConsumer.set_horizon`. Concrete classes
implement both methods to define how the signal is processed.

Intervals are assumed to arrive in order: if ``consume(i1)`` is invoked
before ``consume(i2)``, then ``i1.is_before(i2)``. Horizons never move
back: each one is greater than or equal to every previous horizon and to
the end of every interval consumed before it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from cytlmonitor.interval import Interval


class BooleanSignalConsumer(ABC):
    """Interface implemented by classes that process a stream of Intervals,
    each lying entirely before the next, together with the horizon up to
    which the stream is known."""

    __slots__ = ()

    @abstractmethod
    def consume(self, i: Interval) -> None:
        """Process a single incoming interval ``i``. Every interval
        consumed before ``i`` is before it (see
        :meth:`~cytlmonitor.interval.Interval.is_before`)."""

    @abstractmethod
    def set_horizon(self, t: float) -> None:
        """Record that the signal is known up to time ``t``. ``t`` is
        greater than or equal to every previous horizon and to the end of
        every interval consumed so far."""
