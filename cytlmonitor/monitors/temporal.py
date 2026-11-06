"""
cytlmonitor.monitors.temporal
=============================
Monitors for the temporal operators.


Monitor checking whether the boolean signal of another monitor becomes
true within a time window.

An :class:`EventuallyMonitor` wraps a nested
:class:`~cytlmonitor.monitors.base.EventMonitor` ``arg`` and an
:class:`~cytlmonitor.core.interval.Interval` ``i_arg``, and publishes a signal
that is true at ``t`` exactly when the signal of ``arg`` is true at some
``t + t'`` with ``t'`` in ``i_arg``.

Every consumed :class:`~cytlmonitor.events.event.Event` is passed to ``arg``.
Every time ``arg`` publishes an interval ``i2``, the interval
``i3 = i2.backward(i_arg)`` (see
:meth:`~cytlmonitor.core.interval.Interval.backward`) is computed: the part of
it after ``last``, the end of what was published so far (0 at the
beginning), is published, ``last`` is moved to ``i3.end``, and the
horizon is published at ``last`` when it has grown. Consecutive ``i3``
may overlap, so starting from ``last`` keeps the published intervals
disjoint; nothing is published when ``i3`` does not reach beyond
``last``.

Every time ``arg`` publishes a horizon ``h``, the window ``[t + a, t + b]``
of every ``t < h - b`` (``a`` and ``b`` being the bounds of ``i_arg``)
lies where ``arg`` is known, so ``h - b`` is published as the horizon when
it is greater than both the previous horizon and ``last``. When ``i_arg``
is right unbounded, the horizons of ``arg`` give nothing.

A right-unbounded ``i3`` has no end, so it is published but no horizon
follows, and nothing is published after it.

Monitor checking whether the boolean signal of another monitor stays true
over a time window.

A :class:`GloballyMonitor` wraps a nested
:class:`~cytlmonitor.monitors.base.EventMonitor` ``arg`` and an
:class:`~cytlmonitor.core.interval.Interval` ``i_arg``, and publishes a signal
that is true at ``t`` exactly when the signal of ``arg`` is true at every
``t + t'`` with ``t'`` in ``i_arg``.

It works as ``not eventually_{i_arg} not arg``: an inner
:class:`~cytlmonitor.monitors.boolean.NotMonitor` of an
:class:`~cytlmonitor.monitors.temporal.EventuallyMonitor` of a
:class:`~cytlmonitor.monitors.boolean.NotMonitor` of ``arg`` computes the
signal, and every interval and horizon it publishes is published again.
Every consumed :class:`~cytlmonitor.events.event.Event` is passed to it, and so
to ``arg``.

Monitor checking whether the boolean signal of a monitor stays true until
the signal of another becomes true, within a time window.

An :class:`UntilMonitor` wraps two nested
:class:`~cytlmonitor.monitors.base.EventMonitor` instances, ``arg1`` and
``arg2``, and an :class:`~cytlmonitor.core.interval.Interval` ``i_arg``, and
publishes a signal that is true at ``t`` exactly when there is a ``t'`` in
``t + i_arg`` where the signal of ``arg2`` is true and the signal of
``arg1`` is true on the whole of ``[t, t')``. ``arg1`` is not required at
``t'`` itself, so ``arg1`` may stop exactly where ``arg2`` starts; when
``i_arg`` contains 0, ``t' = t`` is allowed and ``arg2`` alone makes the
signal true.

Every consumed :class:`~cytlmonitor.events.event.Event` is passed to ``arg1`` and
then to ``arg2`` (only to ``arg1`` when they are the same object), and a
:class:`~cytlmonitor.monitors.base.MonitorInput` installed in each
collects the intervals and horizons it publishes.

Once both are known up to ``h``, the window ``t + i_arg`` of every
``t < h - b`` (``b`` being the end of ``i_arg``) lies where both signals
are known, so the signal is computed up to ``h - b``: given the maximal
intervals ``I`` where ``arg1`` is true and ``J`` where ``arg2`` is true, it
is the union of ``(Ī ∩ J).backward(i_arg) ∩ I`` over every pair, ``Ī``
being ``I`` closed on the right (``t'`` may be its end), together with the
``J`` themselves when ``i_arg`` contains 0. The newly
computed part is published, followed by ``h - b`` as the new horizon.
``i_arg`` must therefore be bounded.

Only the intervals that may still matter are kept, those reaching beyond
the published part, and adjacent intervals are merged, so a long stretch
received in pieces is kept as one.

This relies on a monitor never publishing, after horizon ``h``, an
interval starting before ``h``.

Monitor checking whether the boolean signal of a monitor has stayed true
since the signal of another was true, within a time window in the past.

A :class:`SinceMonitor` wraps two nested
:class:`~cytlmonitor.monitors.base.EventMonitor` instances, ``arg1`` and
``arg2``, and an :class:`~cytlmonitor.core.interval.Interval` ``i_arg``, and
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

Every consumed :class:`~cytlmonitor.events.event.Event` is passed to ``arg1`` and
then to ``arg2`` (only to ``arg1`` when they are the same object), and a
:class:`~cytlmonitor.monitors.base.MonitorInput` installed in each
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

from typing import Optional

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.core.boolean_signal import BooleanSignal
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.event import Event
from cytlmonitor.monitors.base import EventMonitor, MonitorInput
from cytlmonitor.monitors.boolean import NotMonitor


class _Collector(BooleanSignalConsumer):
    """BooleanSignalConsumer installed in ``arg``, forwarding its intervals
    to the owning EventuallyMonitor."""

    __slots__ = ('_owner',)

    def __init__(self, owner: 'EventuallyMonitor'):
        self._owner = owner

    def consume(self, i: Interval) -> None:
        self._owner._receive(i)

    def set_horizon(self, t: float) -> None:
        self._owner._advance(t)


class EventuallyMonitor(EventMonitor):
    """An EventMonitor publishing where the signal of ``arg`` is true at
    some point of ``i_arg`` from now."""

    __slots__ = ('_arg', '_i_arg', '_last', '_last_included', '_horizon')

    def __init__(self, arg: EventMonitor, i_arg: Interval):
        super().__init__()
        if not isinstance(arg, EventMonitor):
            raise TypeError(f"Expected an EventMonitor, got {type(arg).__name__}")
        if not isinstance(i_arg, Interval):
            raise TypeError(f"Expected an Interval, got {type(i_arg).__name__}")
        self._arg = arg
        self._i_arg = i_arg
        # End of what was published so far (None for +inf).
        self._last: Optional[float] = 0.0
        # True if the point ``last`` itself has been published.
        self._last_included = False
        # The last horizon published.
        self._horizon = 0.0
        arg.add(_Collector(self))

    @property
    def arg(self) -> EventMonitor:
        """The monitor whose signal is looked ahead at."""
        return self._arg

    @property
    def i_arg(self) -> Interval:
        """The window, relative to the current time, where ``arg`` must
        become true."""
        return self._i_arg

    @property
    def last(self) -> Optional[float]:
        """The end of what was published so far (None for +inf)."""
        return self._last

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``arg``; the intervals it publishes are moved back
        by ``i_arg`` and published."""
        self._arg.consume(e)

    def _receive(self, i2: Interval) -> None:
        """Publish the part of ``i2.backward(i_arg)`` after ``last``, then
        the new horizon."""
        if self._last is None:
            return
        i3 = i2.backward(self._i_arg)
        if i3 is None:
            return

        last, included = self._last, self._last_included
        if i3.start > last:
            start, left_open = i3.start, i3.left_open
        elif i3.start == last:
            start, left_open = last, i3.left_open or included
        else:
            start, left_open = last, included
        end, right_open = i3.end, i3.right_open
        if end is not None and (end < start or (end == start and (left_open or right_open))):
            return

        self.publish(Interval(start, end, left_open=left_open, right_open=right_open))
        self._last = end
        self._last_included = not right_open
        if end is not None and end > self._horizon:
            self._horizon = end
            self.publish_horizon(end)

    def _advance(self, h: float) -> None:
        """``arg`` is known up to ``h``: publish ``h - i_arg.end`` as the
        horizon if it is beyond both the previous horizon and ``last``."""
        if self._last is None or self._i_arg.end is None:
            return
        known = h - self._i_arg.end
        if known > self._horizon and known >= self._last:
            self._horizon = known
            self.publish_horizon(known)


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


class UntilMonitor(EventMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` stays true
    until the signal of ``arg2`` is true, within ``i_arg``."""

    __slots__ = ('_arg1', '_arg2', '_i_arg', '_left', '_right', '_horizon')

    def __init__(self, arg1: EventMonitor, arg2: EventMonitor, i_arg: Interval):
        super().__init__()
        for m in (arg1, arg2):
            if not isinstance(m, EventMonitor):
                raise TypeError(f"Expected an EventMonitor, got {type(m).__name__}")
        if not isinstance(i_arg, Interval):
            raise TypeError(f"Expected an Interval, got {type(i_arg).__name__}")
        if i_arg.end is None:
            raise ValueError(f"i_arg must be bounded, got {i_arg!r}.")
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
        """The monitor whose signal must stay true."""
        return self._arg1

    @property
    def arg2(self) -> EventMonitor:
        """The monitor whose signal must become true."""
        return self._arg2

    @property
    def i_arg(self) -> Interval:
        """The window, relative to the current time, where ``arg2`` must
        become true."""
        return self._i_arg

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``arg1`` and then to ``arg2`` (only to ``arg1``
        when they are the same object); the intervals and horizons they
        publish are combined and published."""
        self._arg1.consume(e)
        if self._arg2 is not self._arg1:
            self._arg2.consume(e)

    def _advance(self) -> None:
        """Publish the signal over the newly computable part
        ``[horizon, min(h1, h2) - b)``, then the new horizon."""
        known = min(self._left.horizon, self._right.horizon)
        target = known - self._i_arg.end
        if target <= self._horizon:
            return
        known_part = Interval(0.0, known)
        holding = self._left.restricted_to(known_part)
        reached = self._right.restricted_to(known_part)

        result = reached if self._i_arg.contains(0) else BooleanSignal()
        for i in holding:
            closed = Interval(i.start, i.end, left_open=i.left_open, right_open=False)
            for j in reached:
                common = closed.intersection(j)
                if common is None:
                    continue
                start = common.backward(self._i_arg)
                if start is None:
                    continue
                part = start.intersection(i)
                if part is not None:
                    result = result.union(BooleanSignal([part]))

        window = BooleanSignal([Interval(self._horizon, target)])
        for i in result.intersection(window):
            self.publish(i)
        self._horizon = target
        self._left.discard_before(target)
        self._right.discard_before(target)
        self._left.compact()
        self._right.compact()
        self.publish_horizon(target)


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
