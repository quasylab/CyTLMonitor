"""
cytlmonitor.imply_monitor
===========================
Monitor computing the implication between the boolean signals of two
other monitors.

An :class:`ImplyMonitor` wraps two nested
:class:`~cytlmonitor.event_monitor.EventMonitor` instances, ``m1`` and
``m2``, and publishes a signal that is true exactly where the signal of
``m1`` is false or the signal of ``m2`` is true, i.e. ``(not m1) or m2``.
See :mod:`cytlmonitor.binary_monitor` for how the two signals are
collected and when the result is published.
"""

from __future__ import annotations

from cytlmonitor.binary_monitor import BinaryMonitor
from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.interval import Interval
from cytlmonitor.monitor_input import complement_within


class ImplyMonitor(BinaryMonitor):
    """An EventMonitor publishing the implication from the boolean signal
    of ``m1`` to that of ``m2``."""

    __slots__ = ()

    @staticmethod
    def _combine(s1: BooleanSignal, s2: BooleanSignal, window: Interval) -> BooleanSignal:
        return complement_within(s1, window).union(s2)
