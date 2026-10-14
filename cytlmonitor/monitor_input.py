"""
cytlmonitor.monitor_input
===========================
Buffer collecting the boolean signal published by a nested monitor.

A :class:`MonitorInput` is the
:class:`~cytlmonitor.boolean_signal_consumer.BooleanSignalConsumer` that
monitors built on other monitors install in each of them. It keeps the
intervals received that may still matter and the latest horizon, and asks
its owner to advance every time the horizon moves.

:func:`complement_within` negates a signal collected this way within the
stretch it was restricted to.
"""

from __future__ import annotations

from collections import deque
from typing import Deque

from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.interval import Interval


def complement_within(signal: BooleanSignal, window: Interval) -> BooleanSignal:
    """Return the parts of ``window`` where ``signal``, whose intervals all
    lie within ``window``, is false. ``window`` must be bounded and open on
    the right, as are the stretches monitors advance by."""
    signal.set_horizon(window.end)
    return signal.complement().intersection(BooleanSignal([window]))


class MonitorInput(BooleanSignalConsumer):
    """BooleanSignalConsumer installed in a nested monitor: keeps the
    intervals it publishes that may still matter, and its horizon. Every
    time the horizon is set, ``owner._advance()`` is invoked."""

    __slots__ = ('_owner', 'intervals', 'horizon')

    def __init__(self, owner):
        self._owner = owner
        self.intervals: Deque[Interval] = deque()
        self.horizon = 0.0

    def consume(self, i: Interval) -> None:
        self.intervals.append(i)

    def set_horizon(self, t: float) -> None:
        self.horizon = float(t)
        self._owner._advance()

    def restricted_to(self, window: Interval) -> BooleanSignal:
        """The part of the collected signal lying within ``window``."""
        signal = BooleanSignal()
        for i in self.intervals:
            part = i.intersection(window)
            if part is not None:
                signal.add(part)
        return signal

    def compact(self) -> None:
        """Merge adjacent intervals, so that a long stretch received in
        pieces is kept as a single interval."""
        self.intervals = deque(BooleanSignal(self.intervals))

    def discard_before(self, t: float) -> None:
        """Drop the intervals lying entirely within ``[0, t)``."""
        while self.intervals and self.intervals[0].is_before(Interval(t)):
            self.intervals.popleft()

    def discard_ending_before(self, t: float) -> None:
        """Drop the intervals ending before ``t``, keeping those ending at
        ``t`` even when they exclude it."""
        while self.intervals and self.intervals[0].end is not None \
                and self.intervals[0].end < t:
            self.intervals.popleft()
