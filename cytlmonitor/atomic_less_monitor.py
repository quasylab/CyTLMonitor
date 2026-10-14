"""
cytlmonitor.atomic_less_monitor
===============================
Monitor checking where the signal of a stream expression is less than the
signal of another.

An :class:`AtomicLessMonitor` wraps two
:class:`~cytlmonitor.stream_expression.StreamExpression` instances,
``arg1`` and ``arg2``, and publishes a boolean signal that is true exactly
where the signal of ``arg1`` is less than the signal of ``arg2``. See
:mod:`cytlmonitor.atomic_comparison_monitor` for how the two signals are
compared and when the result is published.
"""

from __future__ import annotations

from cytlmonitor.atomic_comparison_monitor import AtomicComparisonMonitor


class AtomicLessMonitor(AtomicComparisonMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` is less than
    the signal of ``arg2``."""

    __slots__ = ()

    _strict = True
