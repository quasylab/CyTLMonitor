"""
cytlmonitor.monitors.atomic
===========================
Atomic monitors comparing two stream expressions.


Base class for monitors comparing the signals of two stream expressions.

An :class:`AtomicComparisonMonitor` wraps two
:class:`~cytlmonitor.expressions.base.StreamExpression` instances,
``arg1`` and ``arg2``, and publishes a boolean signal that is true exactly
where the signal of ``arg1`` is less than the signal of ``arg2`` or, for
non-strict comparisons (see :attr:`AtomicComparisonMonitor._strict`),
less than or equal to it. Reversed comparisons (see
:attr:`AtomicComparisonMonitor._reversed`) check greater than, or greater
than or equal to, instead.

The two signals are aligned by an inner
:class:`~cytlmonitor.expressions.arithmetic.DifferenceExpression`
computing ``arg2 - arg1`` (``arg1 - arg2`` when reversed). Every consumed
event is passed to ``arg1`` and then to ``arg2`` (only to ``arg1`` when
they are the same object). Each segment of that
difference is split where its polynomial changes sign (see
:meth:`~cytlmonitor.core.polynomial.Polynomial.positive`): the pieces where it
is positive (or, if not strict, not negative) are published, followed by
the end of the segment as the new horizon when it is greater than the
previous one. As for ``positive``, the polynomials of the difference must
have degree at most 2: a ``ValueError`` is raised otherwise.

A right-unbounded segment has no end, so its pieces are published but no
horizon follows.

Monitor checking where the signal of a stream expression is less than or
equal to the signal of another.

An :class:`AtomicLeqMonitor` wraps two
:class:`~cytlmonitor.expressions.base.StreamExpression` instances,
``arg1`` and ``arg2``, and publishes a boolean signal that is true exactly
where the signal of ``arg1`` is less than or equal to the signal of
``arg2``. See :mod:`cytlmonitor.monitors.atomic` for how the two
signals are compared and when the result is published.

Monitor checking where the signal of a stream expression is less than the
signal of another.

An :class:`AtomicLessMonitor` wraps two
:class:`~cytlmonitor.expressions.base.StreamExpression` instances,
``arg1`` and ``arg2``, and publishes a boolean signal that is true exactly
where the signal of ``arg1`` is less than the signal of ``arg2``. See
:mod:`cytlmonitor.monitors.atomic` for how the two signals are
compared and when the result is published.

Monitor checking where the signal of a stream expression is greater than
or equal to the signal of another.

An :class:`AtomicGeqMonitor` wraps two
:class:`~cytlmonitor.expressions.base.StreamExpression` instances,
``arg1`` and ``arg2``, and publishes a boolean signal that is true exactly
where the signal of ``arg1`` is greater than or equal to the signal of
``arg2``. See :mod:`cytlmonitor.monitors.atomic` for how the two
signals are compared and when the result is published.

Monitor checking where the signal of a stream expression is greater than
the signal of another.

An :class:`AtomicGreaterMonitor` wraps two
:class:`~cytlmonitor.expressions.base.StreamExpression` instances,
``arg1`` and ``arg2``, and publishes a boolean signal that is true exactly
where the signal of ``arg1`` is greater than the signal of ``arg2``. See
:mod:`cytlmonitor.monitors.atomic` for how the two signals are
compared and when the result is published.
"""

from __future__ import annotations

from abc import abstractmethod

from cytlmonitor.consumers.signal_consumer import SignalConsumer
from cytlmonitor.core.node import operand
from cytlmonitor.core.segment import Segment
from cytlmonitor.events.event import Event
from cytlmonitor.expressions.arithmetic import DifferenceExpression
from cytlmonitor.expressions.base import StreamExpression
from cytlmonitor.monitors.base import EventMonitor


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

    _infix = True

    @property
    def operands(self) -> tuple:
        return (self.arg1, self.arg2)

    def __str__(self) -> str:
        return f'{operand(self.arg1)} {self._symbol} {operand(self.arg2)}'

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


class AtomicLeqMonitor(AtomicComparisonMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` is less than
    or equal to the signal of ``arg2``."""

    __slots__ = ()

    _symbol = '<='

    _strict = False


class AtomicLessMonitor(AtomicComparisonMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` is less than
    the signal of ``arg2``."""

    __slots__ = ()

    _symbol = '<'

    _strict = True


class AtomicGeqMonitor(AtomicComparisonMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` is greater
    than or equal to the signal of ``arg2``."""

    __slots__ = ()

    _symbol = '>='

    _strict = False
    _reversed = True


class AtomicGreaterMonitor(AtomicComparisonMonitor):
    """An EventMonitor publishing where the signal of ``arg1`` is greater
    than the signal of ``arg2``."""

    __slots__ = ()

    _symbol = '>'

    _strict = True
    _reversed = True
