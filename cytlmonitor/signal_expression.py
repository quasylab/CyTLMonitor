"""
cytlmonitor.signal_expression
================================
Utility functions for building Signals from other cytlmonitor objects.

:class:`SignalExpression` has no state and no instances are meant to be
created: it is just a namespace of related static methods, grouped
together because they all produce a :class:`~cytlmonitor.signal.Signal`.
"""

from __future__ import annotations

from typing import Callable, Optional, Tuple

from cytlmonitor.event_sequence import EventSequence
from cytlmonitor.interval import Interval
from cytlmonitor.measure import Measure
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal import Signal


def _intersect(a: Interval, b: Interval) -> Interval:
    """Return the overlapping sub-interval of two intersecting intervals ``a``
    and ``b`` (the counterpart to :meth:`Interval.join`, which returns
    their union instead)."""
    if a.start > b.start:
        new_start, new_left_open = a.start, a.left_open
    elif b.start > a.start:
        new_start, new_left_open = b.start, b.left_open
    else:
        new_start, new_left_open = a.start, a.left_open or b.left_open

    if a.end is None:
        new_end, new_right_open = b.end, b.right_open
    elif b.end is None:
        new_end, new_right_open = a.end, a.right_open
    elif a.end < b.end:
        new_end, new_right_open = a.end, a.right_open
    elif b.end < a.end:
        new_end, new_right_open = b.end, b.right_open
    else:
        new_end, new_right_open = a.end, a.right_open or b.right_open

    return Interval(new_start, new_end, left_open=new_left_open, right_open=new_right_open)


def _next(segments: Tuple[Segment, ...], index: int) -> Tuple[Optional[Segment], int]:
    """Return ``(segments[index], index + 1)``, or ``(None, index)`` if
    ``index`` is out of range."""
    if index < len(segments):
        return segments[index], index + 1
    return None, index


def _shrink_left(
    interval: Interval, poly: Polynomial, segments: Tuple[Segment, ...], index: int
) -> Tuple[Optional[Segment], int]:
    """``interval``'s own start point has just been consumed on its own
    (because the other side didn't include it). Return the new (current
    segment, next index) pair: the rest of ``interval`` with its start now
    excluded, or -- if ``interval`` was itself just that point -- the next
    real segment."""
    if interval.end == interval.start:
        return _next(segments, index)
    remainder = Interval(interval.start, interval.end, left_open=True, right_open=interval.right_open)
    return Segment(remainder, poly), index


def _advance(
    interval: Interval, poly: Polynomial, overlap: Interval, segments: Tuple[Segment, ...], index: int
) -> Tuple[Optional[Segment], int]:
    """Return the new (current segment, next index) pair for one side of
    :meth:`SignalExpression.apply` after ``overlap`` has been consumed
    from ``interval``."""
    end = overlap.end
    if interval.end == end:
        if interval.right_open == overlap.right_open:
            return _next(segments, index)
        # interval is closed exactly where overlap (forced open by the
        # other side) ends: the single point {end} is still unconsumed.
        return Segment(Interval.point(end), poly), index
    _, remainder = interval.split(end, open_on_left_side=overlap.right_open)
    return Segment(remainder, poly), index


class SignalExpression:
    """A namespace of utility static methods for building Signals."""

    @staticmethod
    def eval_measure(measure: Measure, sequence: EventSequence) -> Signal:
        """Evaluate ``measure`` at each event of ``sequence``.

        Given events ``(t0, p0), ..., (tn, pn)``, returns the Signal

            [0,t0) -> 0, [t0,t0] -> m(e0),
            (t0,t1) -> 0, [t1,t1] -> m(e1),
            ...,
            (t(n-1),tn) -> 0, [tn,tn] -> m(en)

        i.e. zero everywhere except at the exact time of each event, where
        it takes the value of ``measure`` evaluated on that event. The
        leading ``[0,t0)`` segment is omitted when ``t0`` is 0.

        Raises a ``ValueError`` if ``sequence`` is empty.
        """
        if not isinstance(measure, Measure):
            raise TypeError(f"Expected a Measure, got {type(measure).__name__}")
        if not isinstance(sequence, EventSequence):
            raise TypeError(f"Expected an EventSequence, got {type(sequence).__name__}")
        if sequence.length() == 0:
            raise ValueError("eval_measure requires a non-empty EventSequence.")

        signal = Signal()
        previous_time = 0.0
        for i in range(sequence.length()):
            event = sequence[i]
            t = event.get_time()
            if t > previous_time:
                gap = Interval(previous_time, t, left_open=(i > 0), right_open=True)
                signal.add(Segment(gap, Polynomial.ZERO))
            value = measure.evaluate(event)
            signal.add(Segment(Interval.point(t), Polynomial([value])))
            previous_time = t

        return signal

    @staticmethod
    def apply(
        f: Callable[[Polynomial, Polynomial], Polynomial],
        signal1: Signal,
        signal2: Signal,
    ) -> Signal:
        """Return the Signal obtained by applying ``f`` to ``signal1`` and
        ``signal2``'s aligned segments.

        The two signals' segments are walked in lockstep: at each step,
        ``f`` is applied to the polynomials of the pair of segments
        currently overlapping, over their overlapping sub-interval, and
        whichever segment extends further is carried forward (split, if
        needed) to be paired with the next segment of the other signal.
        Once one signal is exhausted, the remaining segments of the other
        are paired with ``Polynomial.ZERO``.

        Raises a ``ValueError`` if the two signals' segments are not
        aligned, i.e. if at any step the current segment of one signal
        does not start where the current segment of the other does.
        """
        if not callable(f):
            raise TypeError(f"Expected a callable, got {type(f).__name__}")
        if not isinstance(signal1, Signal):
            raise TypeError(f"Expected a Signal, got {type(signal1).__name__}")
        if not isinstance(signal2, Signal):
            raise TypeError(f"Expected a Signal, got {type(signal2).__name__}")

        segments1 = tuple(signal1)
        segments2 = tuple(signal2)
        current1, index1 = _next(segments1, 0)
        current2, index2 = _next(segments2, 0)

        result = Signal()

        while current1 is not None and current2 is not None:
            interval1, poly1 = current1.interval, current1.polynomial
            interval2, poly2 = current2.interval, current2.polynomial

            if interval1.start != interval2.start:
                raise ValueError(
                    f"Signals are not aligned: {interval1!r} and {interval2!r} "
                    f"do not start at the same point."
                )

            # One interval may be closed exactly where the other is open at
            # their shared start: that single point belongs to only one of
            # the two, and must be emitted on its own before the bulk
            # overlap (which will exclude it, since it's excluded by the
            # open side).
            if interval1.left_open != interval2.left_open:
                start = interval1.start
                if interval1.left_open:
                    result.add(Segment(Interval.point(start), f(Polynomial.ZERO, poly2)))
                    current2, index2 = _shrink_left(interval2, poly2, segments2, index2)
                else:
                    result.add(Segment(Interval.point(start), f(poly1, Polynomial.ZERO)))
                    current1, index1 = _shrink_left(interval1, poly1, segments1, index1)
                continue

            if not interval1.intersect(interval2):
                raise ValueError(
                    f"Signals are not aligned: {interval1!r} and {interval2!r} do not overlap."
                )

            overlap = _intersect(interval1, interval2)
            result.add(Segment(overlap, f(poly1, poly2)))

            current1, index1 = _advance(interval1, poly1, overlap, segments1, index1)
            current2, index2 = _advance(interval2, poly2, overlap, segments2, index2)

        while current1 is not None:
            result.add(Segment(current1.interval, f(current1.polynomial, Polynomial.ZERO)))
            current1, index1 = _next(segments1, index1)

        while current2 is not None:
            result.add(Segment(current2.interval, f(Polynomial.ZERO, current2.polynomial)))
            current2, index2 = _next(segments2, index2)

        return result
