"""
cytlmonitor.monitors.boolean
============================
Monitors for the boolean connectives.


Base class for monitors combining, point by point, the boolean signals of
two other monitors.

A :class:`BinaryMonitor` wraps two nested
:class:`~cytlmonitor.monitors.base.EventMonitor` instances, ``m1`` and
``m2``. Every consumed :class:`~cytlmonitor.events.event.Event` is passed to
both, and a :class:`~cytlmonitor.consumers.boolean_signal_consumer.BooleanSignalConsumer`
installed in each (a :class:`~cytlmonitor.monitors.base.MonitorInput`)
collects the intervals and horizons it publishes.

A monitor whose horizon is ``h`` is known on ``[0, h)``, so the combined
signal is known on ``[0, min(h1, h2))``. It is also known beyond, as far as
the operand known further keeps its *dominant* value, the one deciding the
result on its own (false for a conjunction, true for a disjunction, a false
premise or a true conclusion for an implication): ``False and m2`` is
false whatever ``m2`` turns out to be. The result is thus not held back by
an operand that lags behind, such as an eventually with a wide window.

Whenever the known part grows, the two signals restricted to the newly
known part are combined by :meth:`BinaryMonitor._combine`, which is also
given that part, and the resulting intervals are published, followed by
the new horizon. Intervals lying entirely within the known part are then
discarded; whatever an operand publishes later within it is ignored.

This relies on a monitor never publishing, after horizon ``h``, an
interval starting before ``h``.

Monitor computing the conjunction of the boolean signals of two other
monitors.

An :class:`AndMonitor` wraps two nested
:class:`~cytlmonitor.monitors.base.EventMonitor` instances, ``m1`` and
``m2``, and publishes a signal that is true exactly where both of theirs
are true. See :mod:`cytlmonitor.monitors.boolean` for how the two signals
are collected and when the result is published.

Monitor computing the disjunction of the boolean signals of two other
monitors.

An :class:`OrMonitor` wraps two nested
:class:`~cytlmonitor.monitors.base.EventMonitor` instances, ``m1`` and
``m2``, and publishes a signal that is true exactly where at least one of
theirs is true. See :mod:`cytlmonitor.monitors.boolean` for how the two
signals are collected and when the result is published.

Monitor computing the implication between the boolean signals of two
other monitors.

An :class:`ImplyMonitor` wraps two nested
:class:`~cytlmonitor.monitors.base.EventMonitor` instances, ``m1`` and
``m2``, and publishes a signal that is true exactly where the signal of
``m1`` is false or the signal of ``m2`` is true, i.e. ``(not m1) or m2``.
See :mod:`cytlmonitor.monitors.boolean` for how the two signals are
collected and when the result is published.

Monitor computing the negation of the boolean signal of another monitor.

A :class:`NotMonitor` wraps a nested
:class:`~cytlmonitor.monitors.base.EventMonitor` ``m``. Every consumed
:class:`~cytlmonitor.events.event.Event` is passed to ``m``, and a
:class:`~cytlmonitor.monitors.base.MonitorInput` installed in it collects
the intervals and horizons it publishes. The published signal is true
exactly where the signal of ``m`` is false.

The signal of ``m`` is known on ``[0, h)``, ``h`` being its horizon.
Whenever ``h`` grows, the part of the newly known stretch where ``m`` is
false is published, followed by the new horizon.

This relies on ``m`` never publishing, after horizon ``h``, an interval
starting before ``h``.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Optional, Tuple

from cytlmonitor.core.boolean_signal import BooleanSignal
from cytlmonitor.core.interval import Interval
from cytlmonitor.core.node import operand
from cytlmonitor.events.event import Event
from cytlmonitor.monitors.base import EventMonitor, MonitorInput, complement_within


class BinaryMonitor(EventMonitor):
    """An EventMonitor publishing the boolean signals of ``m1`` and ``m2``
    combined by :meth:`_combine`."""

    __slots__ = ('_m1', '_m2', '_left', '_right', '_horizon', '_consuming')

    _infix = True

    @property
    def operands(self) -> tuple:
        return (self.m1, self.m2)

    def __str__(self) -> str:
        return f'{operand(self.m1)} {self._symbol} {operand(self.m2)}'

    def __init__(self, m1: EventMonitor, m2: EventMonitor):
        super().__init__()
        for m in (m1, m2):
            if not isinstance(m, EventMonitor):
                raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        self._m1 = m1
        self._m2 = m2
        self._left = MonitorInput(self)
        self._right = MonitorInput(self)
        # The output is published on [0, horizon).
        self._horizon = 0.0
        # True while an event is passed to m1 and m2: advancing waits until
        # both have processed it.
        self._consuming = False
        m1.add(self._left)
        m2.add(self._right)

    @property
    def m1(self) -> EventMonitor:
        """The first operand."""
        return self._m1

    @property
    def m2(self) -> EventMonitor:
        """The second operand."""
        return self._m2

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``m1`` and ``m2``; the intervals and horizons they
        publish are combined and published. When ``m1`` and ``m2`` are the
        same object, the event is passed only once. The result is advanced
        once both have processed ``e``, so that it is published in as few
        pieces as possible."""
        self._consuming = True
        try:
            self._m1.consume(e)
            if self._m2 is not self._m1:
                self._m2.consume(e)
        finally:
            self._consuming = False
        self._advance()

    #: For ``m1`` and ``m2``, the value that alone determines the result
    #: (e.g. false for a conjunction), or None if there is none.
    _dominant: Tuple[Optional[bool], Optional[bool]] = (None, None)

    @staticmethod
    @abstractmethod
    def _combine(s1: BooleanSignal, s2: BooleanSignal, window: Interval) -> BooleanSignal:
        """Combine the signals of ``m1`` and ``m2``, both restricted to the
        newly known part ``window``. The result must lie within
        ``window``. Where one of the two signals takes its dominant value,
        the result must not depend on the other one, which may still be
        unknown there."""

    @staticmethod
    def _settled(lead: MonitorInput, dominant: Optional[bool], h: float) -> float:
        """How far past ``h`` the result is decided by ``lead`` alone: the
        end of the stretch from ``h`` where ``lead`` keeps its ``dominant``
        value, without going past the horizon of ``lead``."""
        if dominant is None or lead.horizon <= h:
            return h
        window = Interval(h, lead.horizon)
        # The intervals of ``lead`` are ordered, so the scan stops at the
        # first one deciding the answer.
        frontier, covered = h, False
        for i in lead.intervals:
            part = i.intersection(window)
            if part is None:
                if i.start >= lead.horizon:
                    break
                continue
            if not dominant:
                return part.start
            if part.start > frontier or (part.start == frontier and part.left_open
                                         and not covered):
                break
            if part.end >= frontier:
                frontier, covered = part.end, not part.right_open
        return frontier if dominant else lead.horizon

    def _advance(self) -> None:
        """Publish the combined signal over the newly known part, then the
        new horizon. The known part extends to ``min(h1, h2)`` and, past it,
        as long as the operand known further keeps its dominant value."""
        if self._consuming:
            return
        h = max(self._horizon, min(self._left.horizon, self._right.horizon))
        target = max(self._settled(self._left, self._dominant[0], h),
                     self._settled(self._right, self._dominant[1], h))
        if target <= self._horizon:
            return
        window = Interval(self._horizon, target)
        combined = self._combine(self._left.restricted_to(window),
                                 self._right.restricted_to(window), window)
        for i in combined:
            self.publish(i)
        self._horizon = target
        self._left.discard_before(target)
        self._right.discard_before(target)
        self.publish_horizon(target)


class AndMonitor(BinaryMonitor):
    """An EventMonitor publishing the conjunction of the boolean signals of
    ``m1`` and ``m2``."""

    __slots__ = ()

    _symbol = '&'
    _dominant = (False, False)

    @staticmethod
    def _combine(s1: BooleanSignal, s2: BooleanSignal, window: Interval) -> BooleanSignal:
        return s1.intersection(s2)


class OrMonitor(BinaryMonitor):
    """An EventMonitor publishing the disjunction of the boolean signals of
    ``m1`` and ``m2``."""

    __slots__ = ()

    _symbol = '|'
    _dominant = (True, True)

    @staticmethod
    def _combine(s1: BooleanSignal, s2: BooleanSignal, window: Interval) -> BooleanSignal:
        return s1.union(s2)


class ImplyMonitor(BinaryMonitor):
    """An EventMonitor publishing the implication from the boolean signal
    of ``m1`` to that of ``m2``."""

    __slots__ = ()

    _symbol = '->'
    _dominant = (False, True)

    @staticmethod
    def _combine(s1: BooleanSignal, s2: BooleanSignal, window: Interval) -> BooleanSignal:
        return complement_within(s1, window).union(s2)


class NotMonitor(EventMonitor):
    """An EventMonitor publishing the negation of the boolean signal of
    ``m``."""

    __slots__ = ('_m', '_input', '_horizon')

    @property
    def operands(self) -> tuple:
        return (self.m,)

    def __str__(self) -> str:
        return f'not {operand(self.m)}'

    def __init__(self, m: EventMonitor):
        super().__init__()
        if not isinstance(m, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        self._m = m
        self._input = MonitorInput(self)
        # The output is published on [0, horizon).
        self._horizon = 0.0
        m.add(self._input)

    @property
    def m(self) -> EventMonitor:
        """The monitor being negated."""
        return self._m

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``m``; the intervals and horizons it publishes are
        negated and published."""
        self._m.consume(e)

    def _advance(self) -> None:
        """Publish where ``m`` is false over the newly known part
        ``[horizon, h)``, then the new horizon."""
        target = self._input.horizon
        if target <= self._horizon:
            return
        window = Interval(self._horizon, target)
        for i in complement_within(self._input.restricted_to(window), window):
            self.publish(i)
        self._horizon = target
        self._input.discard_before(target)
        self.publish_horizon(target)
