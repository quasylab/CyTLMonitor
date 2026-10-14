"""
cytlmonitor.or_monitor
========================
Monitor computing the disjunction of the boolean signals of two other
monitors.

An :class:`OrMonitor` wraps two nested
:class:`~cytlmonitor.event_monitor.EventMonitor` instances, ``m1`` and
``m2``, and publishes a signal that is true exactly where at least one of
theirs is true. See :mod:`cytlmonitor.binary_monitor` for how the two
signals are collected and when the result is published.
"""

from __future__ import annotations

from cytlmonitor.binary_monitor import BinaryMonitor
from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.interval import Interval


class OrMonitor(BinaryMonitor):
    """An EventMonitor publishing the disjunction of the boolean signals of
    ``m1`` and ``m2``."""

    __slots__ = ()

    @staticmethod
    def _combine(s1: BooleanSignal, s2: BooleanSignal, window: Interval) -> BooleanSignal:
        return s1.union(s2)
