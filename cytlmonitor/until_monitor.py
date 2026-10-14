"""
cytlmonitor.until_monitor
===========================
Monitor checking whether the boolean signal of a monitor stays true until
the signal of another becomes true, within a time window.

An :class:`UntilMonitor` wraps two nested
:class:`~cytlmonitor.event_monitor.EventMonitor` instances, ``arg1`` and
``arg2``, and an :class:`~cytlmonitor.interval.Interval` ``i_arg``, and
publishes a signal that is true at ``t`` exactly when there is a ``t'`` in
``t + i_arg`` where the signal of ``arg2`` is true and the signal of
``arg1`` is true on the whole of ``[t, t')``. ``arg1`` is not required at
``t'`` itself, so ``arg1`` may stop exactly where ``arg2`` starts; when
``i_arg`` contains 0, ``t' = t`` is allowed and ``arg2`` alone makes the
signal true.

Every consumed :class:`~cytlmonitor.event.Event` is passed to ``arg1`` and
then to ``arg2`` (only to ``arg1`` when they are the same object), and a
:class:`~cytlmonitor.monitor_input.MonitorInput` installed in each
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
"""

from __future__ import annotations

from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.monitor_input import MonitorInput


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
