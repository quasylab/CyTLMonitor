"""
cytlmonitor.atomic_comparison_monitor
=======================================
Base class for monitors comparing the signals of two stream expressions.

An :class:`AtomicComparisonMonitor` wraps two
:class:`~cytlmonitor.stream_expression.StreamExpression` instances,
``arg1`` and ``arg2``, and publishes a boolean signal that is true exactly
where the signal of ``arg1`` is less than the signal of ``arg2`` or, for
non-strict comparisons (see :attr:`AtomicComparisonMonitor._strict`),
less than or equal to it. Reversed comparisons (see
:attr:`AtomicComparisonMonitor._reversed`) check greater than, or greater
than or equal to, instead.

The two signals are aligned by an inner
:class:`~cytlmonitor.difference_expression.DifferenceExpression`
computing ``arg2 - arg1`` (``arg1 - arg2`` when reversed). Every consumed
event is passed to ``arg1`` and then to ``arg2`` (only to ``arg1`` when
they are the same object). Each segment of that
difference is split where its polynomial changes sign (see
:meth:`~cytlmonitor.polynomial.Polynomial.positive`): the pieces where it
is positive (or, if not strict, not negative) are published, followed by
the end of the segment as the new horizon when it is greater than the
previous one. As for ``positive``, the polynomials of the difference must
have degree at most 2: a ``ValueError`` is raised otherwise.

A right-unbounded segment has no end, so its pieces are published but no
horizon follows.
"""

from __future__ import annotations

from abc import abstractmethod

from cytlmonitor.difference_expression import DifferenceExpression
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression


class _Collector(SignalConsumer):
    """SignalConsumer installed in the difference ``arg2 - arg1``,
    forwarding its segments to the owning AtomicComparisonMonitor."""

    __slots__ = ('_owner',)

    def __init__(self, owner: 'AtomicComparisonMonitor'):
        self._owner = owner

    def consume(self, s: Segment) -> None:
        self._owner._compare(s)


class AtomicComparisonMonitor(EventMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` is less than
    (or, if not :attr:`_strict`, less than or equal to) the signal of
    ``arg2``, or greater than (or equal to) it if :attr:`_reversed`."""

    __slots__ = ('_arg1', '_arg2', '_difference', '_horizon')

    #: True if ``arg1`` must be greater than ``arg2`` rather than less.
    _reversed = False

    def __init__(self, arg1: StreamExpression, arg2: StreamExpression):
        super().__init__()
        for arg in (arg1, arg2):
            if not isinstance(arg, StreamExpression):
                raise TypeError(f"Expected a StreamExpression, got {type(arg).__name__}")
        self._arg1 = arg1
        self._arg2 = arg2
        if self._reversed:
            self._difference = DifferenceExpression(arg1, arg2)
        else:
            self._difference = DifferenceExpression(arg2, arg1)
        self._difference.add(_Collector(self))
        self._horizon = 0.0

    @property
    @abstractmethod
    def _strict(self) -> bool:
        """True if equal values make the comparison false."""

    @property
    def arg1(self) -> StreamExpression:
        """The expression on the left of the comparison."""
        return self._arg1

    @property
    def arg2(self) -> StreamExpression:
        """The expression on the right of the comparison."""
        return self._arg2

    def consume(self, e: Event) -> None:
        """Pass ``e`` to ``arg1`` and then to ``arg2`` (only to ``arg1``
        when they are the same object); the segments they publish are
        compared and the result published."""
        self._arg1.consume(e)
        if self._arg2 is not self._arg1:
            self._arg2.consume(e)

    def _compare(self, s: Segment) -> None:
        """Publish where the difference segment ``s`` is positive (or, if
        not strict, not negative), then the end of ``s`` as the new horizon
        if it has grown."""
        for piece, holds in s.polynomial.positive(s.interval, strict=self._strict):
            if holds:
                self.publish(piece)
        end = s.interval.end
        if end is not None and end > self._horizon:
            self._horizon = end
            self.publish_horizon(end)
