"""
cytlmonitor.since_monitor
===========================
Monitor checking whether the boolean signal of a monitor has stayed true
since the signal of another was true, within a time window in the past.

A :class:`SinceMonitor` wraps two nested
:class:`~cytlmonitor.event_monitor.EventMonitor` instances, ``arg1`` and
``arg2``, and an :class:`~cytlmonitor.interval.Interval` ``i_arg``, and
publishes a signal that is true at ``t`` exactly when there is a ``t'``
with ``t - t'`` in ``i_arg`` where the signal of ``arg2`` is true and the
signal of ``arg1`` is true on the whole of ``(t', t]``. ``arg1`` is not
required at ``t'`` itself, so ``arg1`` may start exactly where ``arg2``
stops; when ``i_arg`` contains 0, ``t' = t`` is allowed and ``arg2`` alone
makes the signal true.

``t'`` may also be the closing end of an interval where ``arg2`` is true,
even when that interval excludes it, as long as ``t' < t``: monitors
publish right-open intervals such as ``[0, 3)``, and ``arg1`` starting at
3 right after ``arg2`` on ``[0, 3)`` makes the signal true after 3. With
``t' = t``, ``arg2`` must really hold at ``t``.

Every consumed :class:`~cytlmonitor.event.Event` is passed to ``arg1`` and
then to ``arg2`` (only to ``arg1`` when they are the same object), and a
:class:`~cytlmonitor.monitor_input.MonitorInput` installed in each
collects the intervals and horizons it publishes.

The signal only looks at the past, so it is known wherever both arguments
are: once both are known up to ``h``, given the maximal intervals ``I``
where ``arg1`` is true and ``J`` where ``arg2`` is true, it is the union of
``(Ī ∩ J) ⊕ i_arg ∩ I`` over every pair (``Ī`` being ``I`` closed on the
left, since ``t'`` may be its start, and ``⊕`` adding ``i_arg`` to every
point), of ``{e} ⊕ i_arg⁺ ∩ I`` for the open end ``e`` of every ``J``
lying in ``Ī`` (``i_arg⁺`` being ``i_arg`` without 0), and of the ``J``
themselves when ``i_arg`` contains 0, and
the part of it up to ``h`` not yet published is published,
followed by ``h`` as the new horizon. ``i_arg`` may be right unbounded.

Only the intervals that may still matter are kept: those of ``arg1`` from
the start of the stretch where it is still true at ``h``, and those of
``arg2`` from where they can still be reached. Adjacent intervals are
merged, so a long stretch received in pieces is kept as one.

This relies on a monitor never publishing, after horizon ``h``, an
interval starting before ``h``.
"""

from __future__ import annotations

from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.monitor_input import MonitorInput


def _forward(x: Interval, i: Interval) -> Interval:
    """The set of ``t + s`` with ``t`` in ``x`` and ``s`` in ``i``."""
    end = None if x.end is None or i.end is None else x.end + i.end
    return Interval(x.start + i.start, end, left_open=x.left_open or i.left_open,
                    right_open=x.right_open or i.right_open)


class SinceMonitor(EventMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` has stayed
    true since the signal of ``arg2`` was true, within ``i_arg`` in the
    past."""

    __slots__ = ('_arg1', '_arg2', '_i_arg', '_left', '_right', '_horizon')

    def __init__(self, arg1: EventMonitor, arg2: EventMonitor, i_arg: Interval):
        super().__init__()
        for m in (arg1, arg2):
            if not isinstance(m, EventMonitor):
                raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        if not isinstance(i_arg, Interval):
            raise TypeError(f"Expected an Interval, got {type(i_arg).__name__}")
        self._arg1 = arg1
        self._arg2 = arg2
        self._i_arg = i_arg
        self._left = MonitorInput(self)
        self._right = MonitorInput(self)
        # The output is published on [0, horizon).
        self._horizon = 0.0
        arg1.add(self._left)
        arg2.add(self._right)

    @property
    def arg1(self) -> EventMonitor:
        """The monitor whose signal must have stayed true."""
        return self._arg1

    @property
    def arg2(self) -> EventMonitor:
        """The monitor whose signal must have been true."""
        return self._arg2

    @property
    def i_arg(self) -> Interval:
        """The window, back from the current time, where ``arg2`` must have
        been true."""
        return self._i_arg

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``arg1`` and then to ``arg2`` (only to ``arg1``
        when they are the same object); the intervals and horizons they
        publish are combined and published."""
        self._arg1.consume(e)
        if self._arg2 is not self._arg1:
            self._arg2.consume(e)

    def _advance(self) -> None:
        """Publish the signal over the newly known part
        ``[horizon, min(h1, h2))``, then the new horizon."""
        target = min(self._left.horizon, self._right.horizon)
        if target <= self._horizon:
            return
        known_part = Interval(0.0, target)
        holding = self._left.restricted_to(known_part)
        reached = self._right.restricted_to(known_part)

        result = reached if self._i_arg.contains(0) else BooleanSignal()
        positive = self._positive_offsets()
        for i in holding:
            closed = Interval(i.start, i.end, left_open=False, right_open=i.right_open)
            for j in reached:
                common = closed.intersection(j)
                if common is not None:
                    part = _forward(common, self._i_arg).intersection(i)
                    if part is not None:
                        result = result.union(BooleanSignal([part]))
                # t' may be the open end of j, as long as t' < t.
                if (positive is not None and j.end is not None and j.right_open
                        and closed.contains(j.end)):
                    part = _forward(Interval.point(j.end), positive).intersection(i)
                    if part is not None:
                        result = result.union(BooleanSignal([part]))

        window = BooleanSignal([Interval(self._horizon, target)])
        for i in result.intersection(window):
            self.publish(i)
        self._horizon = target
        self._discard(holding, target)
        self._left.compact()
        self._right.compact()
        self.publish_horizon(target)

    def _positive_offsets(self):
        """``i_arg`` without 0 (None if it is just 0)."""
        i = self._i_arg
        if not i.contains(0):
            return i
        if i.end == 0:
            return None
        return Interval(0.0, i.end, left_open=True, right_open=i.right_open)

    def _discard(self, holding: BooleanSignal, target: float) -> None:
        """Drop the intervals that can no longer make any time after
        ``target`` true."""
        last = holding[-1] if holding.length() else None
        if last is None or last.end != target:
            # arg1 is not true just before target: only new stretches of
            # arg1, starting at target or later, matter.
            self._left.discard_before(target)
            # An interval of arg2 ending at target may still be followed by
            # arg1 starting there.
            self._right.discard_ending_before(target)
            return
        # The stretch of arg1 still true at target starts at last.start.
        self._left.discard_before(last.start)
        reach = last.start
        if self._i_arg.end is not None:
            reach = max(reach, target - self._i_arg.end)
        self._right.discard_ending_before(reach)
