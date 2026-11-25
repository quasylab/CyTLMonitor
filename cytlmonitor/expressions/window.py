"""
cytlmonitor.expressions.window
==============================
Sliding-window stream expressions.


Stream expression computing a sliding-window sum over events.

A :class:`SumWindowExpression` consumes a stream of :class:`~cytlmonitor.events.event.Event`
instances, ordered by time, and publishes the piecewise-constant signal

    f(t) = sum of w(e) over the events e with t + from <= e.time <= t + to

for ``t >= 0``, as a sequence of :class:`~cytlmonitor.core.segment.Segment`
instances.

The value of ``f`` at ``t`` is only known once every event up to
``t + to`` has been seen. Events may share a timestamp, so when an event
at time ``τ`` arrives the signal is published up to ``τ - to``, excluded.
The expression keeps:

- a sliding window holding the events whose time lies in
  ``[cursor + from, cursor + to]``, so it spans at most ``to - from``;
- a time cursor, starting from 0, marking where the next segment begins;
- an accumulator holding the sum of ``w`` over the window.

An event enters the window at ``t = e.time - to``, included, and leaves it
just after ``t = e.time - from``.

Base class for stream expressions computing a sliding-window maximum or
minimum over another expression's signal.

A :class:`WindowExtremumExpression` wraps a nested
:class:`~cytlmonitor.expressions.base.StreamExpression` ``arg``. Every
consumed :class:`~cytlmonitor.events.event.Event` is passed to ``arg``, and every
:class:`~cytlmonitor.core.segment.Segment` that ``arg`` publishes is collected
to build the signal

    f(t) = extremum of g(s) over s in [t + from, t + to]

for ``t >= 0``, where ``g`` is the signal published by ``arg`` and the
extremum is chosen by :meth:`WindowExtremumExpression._supersedes`. ``g``
must be piecewise constant, start at 0 and be published as a sequence of
contiguous segments.

An input segment over ``I`` with value ``v`` contributes ``v`` to every
``t`` whose window ``[t + from, t + to]`` meets ``I``, that is to ``t`` in
``I`` shifted back by ``to`` at its start and by ``from`` at its end. Once
the input is known up to ``e``, ``f`` is known up to ``e - to``: each new
input segment therefore lets the output advance, and the newly computed
part of ``f`` is published at once.

The candidates are kept in a sliding window holding the input segments
that can still affect ``f``, which span at most ``to - from`` beyond the
output cursor. A segment is dropped as soon as a later one superseding it
arrives, so the window is ordered from the best candidate to the worst.

Stream expression computing a sliding-window maximum over another
expression's signal.

A :class:`MaxWindowExpression` wraps a nested
:class:`~cytlmonitor.expressions.base.StreamExpression` ``arg`` and
publishes the signal

    f(t) = max of g(s) over s in [t + from, t + to]

for ``t >= 0``, where ``g`` is the piecewise-constant signal published by
``arg``. See :mod:`cytlmonitor.expressions.window` for how the
signal is computed and when it is published.

Stream expression computing a sliding-window minimum over another
expression's signal.

A :class:`MinWindowExpression` wraps a nested
:class:`~cytlmonitor.expressions.base.StreamExpression` ``arg`` and
publishes the signal

    f(t) = min of g(s) over s in [t + from, t + to]

for ``t >= 0``, where ``g`` is the piecewise-constant signal published by
``arg``. See :mod:`cytlmonitor.expressions.window` for how the
signal is computed and when it is published.
"""

from __future__ import annotations

from abc import abstractmethod
from collections import deque
from typing import Callable, Deque, Optional, Tuple

from cytlmonitor.consumers.signal_consumer import SignalConsumer
from cytlmonitor.core.interval import Interval
from cytlmonitor.core.node import function_name, operand, window
from cytlmonitor.core.polynomial import Polynomial
from cytlmonitor.core.segment import Segment
from cytlmonitor.events.event import Event
from cytlmonitor.expressions.base import StreamExpression


class SumWindowExpression(StreamExpression):
    """A StreamExpression publishing, for each time ``t``, the sum of ``w``
    over the events occurring in ``[t + from, t + to]``."""

    __slots__ = ('_w', '_from', '_to', '_window', '_cursor', '_cursor_open',
                 '_accumulator', '_last_time')

    def __str__(self) -> str:
        return f"sum{window(self.from_, self.to)} {function_name(self.w, 'w')}"

    def __init__(self, w: Callable[[Event], float], from_: float, to: float):
        super().__init__()
        if not callable(w):
            raise TypeError(f"Expected a callable, got {type(w).__name__}")
        from_ = float(from_)
        to = float(to)
        if from_ < 0 or to < 0:
            raise ValueError(f"'from' ({from_}) and 'to' ({to}) must be non negative.")
        if from_ >= to:
            raise ValueError(f"'from' ({from_}) must be smaller than 'to' ({to}).")
        self._w = w
        self._from = from_
        self._to = to
        # Pairs (event time, w(event)), ordered by time.
        self._window: Deque[Tuple[float, float]] = deque()
        self._cursor = 0.0
        # True when the cursor time itself has already been published.
        self._cursor_open = False
        self._accumulator = 0.0
        self._last_time: Optional[float] = None

    @property
    def w(self) -> Callable[[Event], float]:
        """The function evaluated on each event."""
        return self._w

    @property
    def from_(self) -> float:
        """Offset, from ``t``, of the start of the window."""
        return self._from

    @property
    def to(self) -> float:
        """Offset, from ``t``, of the end of the window."""
        return self._to

    def consume(self, event: Event) -> None:
        """Publish the signal up to ``event.time - to``, excluded, then add
        ``event`` to the window."""
        if not isinstance(event, Event):
            raise TypeError(f"Expected an Event, got {type(event).__name__}")
        time = event.time
        if self._last_time is not None and time < self._last_time:
            raise ValueError(
                f"Events must be ordered by time: got {time} after {self._last_time}."
            )
        self._last_time = time

        self._advance(time - self._to)

        leaves_at = time - self._from
        if leaves_at < self._cursor or (leaves_at == self._cursor and self._cursor_open):
            # The event leaves the window before the cursor: it never counts.
            return
        value = float(self._w(event))
        self._window.append((time, value))
        self._accumulator += value

    def _advance(self, target: float) -> None:
        """Publish the signal from the cursor up to ``target``, excluded,
        removing the events that leave the window on the way."""
        while self._window and self._window[0][0] - self._from < target:
            leaves_at = self._window[0][0] - self._from
            self._publish_until(leaves_at, right_open=False)
            while self._window and self._window[0][0] - self._from == leaves_at:
                self._accumulator -= self._window.popleft()[1]
            if not self._window:
                # Avoid drift from floating point subtractions.
                self._accumulator = 0.0
        if self._cursor < target:
            self._publish_until(target, right_open=True)

    def _publish_until(self, end: float, right_open: bool) -> None:
        """Publish ``accumulator`` from the cursor up to ``end`` and move the
        cursor to ``end``."""
        interval = Interval(self._cursor, end, left_open=self._cursor_open,
                            right_open=right_open)
        self.publish(Segment(interval, Polynomial([self._accumulator])))
        self._cursor = end
        self._cursor_open = not right_open


def _before(end: Optional[float], right_open: bool,
            other_end: Optional[float], other_right_open: bool) -> bool:
    """True if a region ending at ``end`` stops strictly before one ending
    at ``other_end``. ``None`` stands for +inf."""
    if end is None:
        return False
    if other_end is None:
        return True
    if end != other_end:
        return end < other_end
    return right_open and not other_right_open


class _Collector(SignalConsumer):
    """SignalConsumer installed in ``arg``, forwarding its segments to the
    owning WindowExtremumExpression."""

    __slots__ = ('_owner',)

    def __init__(self, owner: 'WindowExtremumExpression'):
        self._owner = owner

    def consume(self, s: Segment) -> None:
        self._owner._accumulate(s)


class WindowExtremumExpression(StreamExpression):
    """A StreamExpression publishing, for each time ``t``, the extremum of
    the signal of ``arg`` over ``[t + from, t + to]``. Subclasses choose
    the extremum by implementing :meth:`_supersedes`."""

    __slots__ = ('_arg', '_from', '_to', '_window', '_cursor', '_cursor_open',
                 '_input_end', '_input_open')

    @property
    def operands(self) -> tuple:
        return (self.arg,)

    def __str__(self) -> str:
        return f'{self._name}{window(self.from_, self.to)} {operand(self.arg)}'

    def __init__(self, arg: StreamExpression, from_: float, to: float):
        super().__init__()
        if not isinstance(arg, StreamExpression):
            raise TypeError(f"Expected a StreamExpression, got {type(arg).__name__}")
        from_ = float(from_)
        to = float(to)
        if from_ < 0 or to < 0:
            raise ValueError(f"'from' ({from_}) and 'to' ({to}) must be non negative.")
        if from_ >= to:
            raise ValueError(f"'from' ({from_}) must be smaller than 'to' ({to}).")
        self._arg = arg
        self._from = from_
        self._to = to
        # Triples (end, right_open, value) of the input segments that may
        # still be the extremum, best first. 'end' is the last
        # output time the segment affects (None for +inf).
        self._window: Deque[Tuple[Optional[float], bool, float]] = deque()
        self._cursor: Optional[float] = 0.0
        # True when the cursor time itself has already been published.
        self._cursor_open = False
        # Where the next input segment must start.
        self._input_end: Optional[float] = 0.0
        self._input_open = False
        arg.add(_Collector(self))

    @property
    def arg(self) -> StreamExpression:
        """The nested expression whose signal is examined."""
        return self._arg

    @property
    def from_(self) -> float:
        """Offset, from ``t``, of the start of the window."""
        return self._from

    @property
    def to(self) -> float:
        """Offset, from ``t``, of the end of the window."""
        return self._to

    @staticmethod
    @abstractmethod
    def _supersedes(value: float, other: float) -> bool:
        """True if ``value``, taken by a later segment, makes the earlier
        ``other`` useless as a candidate extremum."""

    def consume(self, event: Event) -> None:
        """Pass ``event`` to ``arg``; the segments it publishes are
        accumulated and the resulting output published."""
        self._arg.consume(event)

    def _accumulate(self, s: Segment) -> None:
        """Add the input segment ``s`` to the window and publish the part
        of the output it makes known."""
        interval = s.interval
        if s.polynomial.degree != 0:
            raise ValueError(
                f"{type(self).__name__} requires a piecewise-constant signal, got {s!r}."
            )
        if (self._input_end is None or interval.start != self._input_end
                or interval.left_open != self._input_open):
            raise ValueError(
                f"Segments must be contiguous from 0: {interval!r} does not start "
                f"where the previous segment ended."
            )
        self._input_end = interval.end
        self._input_open = not interval.right_open
        value = s.polynomial.coefficients[0]

        # Earlier segments superseded by the new one can no longer be the
        # extremum: the new segment covers every later time they cover.
        while self._window and self._supersedes(value, self._window[-1][2]):
            self._window.pop()
        end = None if interval.end is None else interval.end - self._from
        self._window.append((end, interval.right_open, value))

        # The output is now known up to interval.end - to.
        known = None if interval.end is None else interval.end - self._to
        known_open = interval.right_open
        while _before(self._window[0][0], self._window[0][1], known, known_open):
            front_end, front_open, front_value = self._window.popleft()
            self._publish_until(front_end, front_open, front_value)
        self._publish_until(known, known_open, self._window[0][2])

    def _publish_until(self, end: Optional[float], right_open: bool, value: float) -> None:
        """Publish ``value`` from the cursor up to ``end`` (None for +inf)
        and move the cursor there. Nothing is published if the interval
        would be empty."""
        if self._cursor is None:
            return
        if end is not None and (end < self._cursor or (
                end == self._cursor and (self._cursor_open or right_open))):
            return
        interval = Interval(self._cursor, end, left_open=self._cursor_open,
                            right_open=right_open)
        self.publish(Segment(interval, Polynomial([value])))
        self._cursor = end
        self._cursor_open = not right_open


class MaxWindowExpression(WindowExtremumExpression):
    """A StreamExpression publishing, for each time ``t``, the maximum of
    the signal of ``arg`` over ``[t + from, t + to]``."""

    __slots__ = ()

    _name = 'max'

    @staticmethod
    def _supersedes(value: float, other: float) -> bool:
        """A later value at least as large as ``other`` supersedes it."""
        return value >= other


class MinWindowExpression(WindowExtremumExpression):
    """A StreamExpression publishing, for each time ``t``, the minimum of
    the signal of ``arg`` over ``[t + from, t + to]``."""

    __slots__ = ()

    _name = 'min'

    @staticmethod
    def _supersedes(value: float, other: float) -> bool:
        """A later value at least as small as ``other`` supersedes it."""
        return value <= other
