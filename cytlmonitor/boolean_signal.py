"""
cytlmonitor.boolean_signal
=============================
Representation of a boolean signal as a sequence of intervals.

A :class:`BooleanSignal` holds :class:`~cytlmonitor.interval.Interval`
instances ordered by time. If ``i1`` precedes ``i2`` in the sequence then:

  * ``i1.end`` is not ``None`` (only the last interval may be right
    unbounded);
  * ``i1.end <= i2.start``;
  * if ``i1`` is closed on the right *and* ``i2`` is closed on the left,
    then ``i1.end < i2.start`` (two closed endpoints can't touch, since that
    would make both intervals contain the same point).

Intervals can only be appended at the end of the sequence, provided they
satisfy the above with respect to the interval currently at the end. If the
new interval is immediately adjacent to the last one (see
:meth:`~cytlmonitor.interval.Interval.just_before`), the two are merged into
a single interval instead of being kept as separate elements.

A signal also has a ``horizon``: the time up to which it is known, never
smaller than the end of its last interval. It is 0 for a new signal,
grows automatically when an interval ending after it is added, and can be
moved with :meth:`BooleanSignal.set_horizon`. ``None`` stands for +inf,
and is the horizon of any signal whose last interval is right unbounded.
"""

from __future__ import annotations

from typing import Iterable, Iterator, List, Optional

from cytlmonitor.interval import Interval


def _max_horizon(a: Optional[float], b: Optional[float]) -> Optional[float]:
    """The greater of two horizons, ``None`` standing for +inf."""
    if a is None or b is None:
        return None
    return max(a, b)


def _ends_first(a: Interval, b: Interval) -> bool:
    """True if ``a`` stops strictly before ``b`` does, ``None`` ends
    standing for +inf."""
    if a.end is None:
        return False
    if b.end is None:
        return True
    if a.end != b.end:
        return a.end < b.end
    return a.right_open and not b.right_open


def _merge_by_start(a: List[Interval], b: List[Interval]) -> Iterator[Interval]:
    """Yield the intervals of the two (already start-sorted) lists ``a`` and
    ``b`` in a single start-sorted sequence, in linear time."""
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i].start <= b[j].start:
            yield a[i]
            i += 1
        else:
            yield b[j]
            j += 1
    while i < len(a):
        yield a[i]
        i += 1
    while j < len(b):
        yield b[j]
        j += 1


class BooleanSignal:
    """A sequence of Intervals ordered and non-overlapping in time."""

    __slots__ = ('_intervals', '_horizon')

    def __init__(self, intervals: Optional[Iterable[Interval]] = None):
        self._intervals: List[Interval] = []
        self._horizon: Optional[float] = 0.0
        if intervals is not None:
            for interval in intervals:
                self.add(interval)

    @property
    def horizon(self) -> Optional[float]:
        """The time up to which this signal is known (None for +inf)."""
        return self._horizon

    def set_horizon(self, t: Optional[float]) -> None:
        """Set ``horizon`` to ``t`` (``None`` for +inf).

        Raises a ``ValueError`` if ``t`` is negative or smaller than the
        end of the last interval (which includes any finite ``t`` when the
        last interval is right unbounded).
        """
        if t is not None:
            t = float(t)
            if t < 0:
                raise ValueError(f"horizon must be non-negative, got {t}.")
            if self._intervals:
                last = self._intervals[-1]
                if last.end is None or t < last.end:
                    raise ValueError(
                        f"horizon ({t}) cannot be smaller than the end of the "
                        f"last interval {last!r}."
                    )
        self._horizon = t

    def add(self, interval: Interval) -> None:
        """Append ``interval`` at the end of the sequence.

        If the last interval currently in the sequence is
        :meth:`~cytlmonitor.interval.Interval.just_before` ``interval``
        (i.e. they abut with no gap and no overlap), it is replaced by the
        :meth:`~cytlmonitor.interval.Interval.join` of the two instead of
        appending ``interval`` as a separate element. ``horizon`` becomes
        the greater of its current value and ``interval.end``.

        Raises a ``ValueError`` if ``interval`` does not satisfy the
        ordering constraint with respect to the last interval currently in
        the sequence (see the module docstring).
        """
        if not isinstance(interval, Interval):
            raise TypeError(f"Expected an Interval, got {type(interval).__name__}")
        if self._intervals:
            last = self._intervals[-1]
            if last.end is None:
                raise ValueError(
                    "Cannot append an interval after a right-unbounded interval."
                )
            if interval.start < last.end:
                raise ValueError(
                    f"Interval {interval!r} overlaps the last interval {last!r} "
                    f"in the sequence."
                )
            if interval.start == last.end and not last.right_open and not interval.left_open:
                raise ValueError(
                    f"Interval {interval!r} and the last interval {last!r} "
                    f"both include the shared point {last.end}."
                )
            if last.just_before(interval):
                self._intervals[-1] = last.join(interval)
            else:
                self._intervals.append(interval)
        else:
            self._intervals.append(interval)
        self._horizon = _max_horizon(self._horizon, interval.end)

    def complement(self) -> 'BooleanSignal':
        """Return the signal representing the "false" periods of this one,
        up to its horizon.

        Given intervals ``I_1, ..., I_n``, the result holds (each omitted
        whenever it would be empty):

          * ``I_1.complement(0.0)``, the gap (if any) before the first
            interval;
          * ``I_(i+1).complement(I_i.end, not I_i.right_open)`` for each
            pair of consecutive intervals, the gap (if any) between them;
          * the interval from ``I_n.end`` to this signal's ``horizon``,
            open on the right, the trailing gap (if any) after the last
            interval.

        A signal with no intervals has complement ``[0, horizon)``. The
        result has the same horizon as this signal.
        """
        result = BooleanSignal()
        n = self.length()

        if n == 0:
            if self.horizon is None or self.horizon > 0.0:
                result.add(Interval(0.0, self.horizon))
            result.set_horizon(self.horizon)
            return result

        first = self._intervals[0]
        gap = first.complement(0.0)
        if gap is not None:
            result.add(gap)

        for i in range(n - 1):
            current = self._intervals[i]
            following = self._intervals[i + 1]
            gap = following.complement(current.end, not current.right_open)
            if gap is not None:
                result.add(gap)

        last = self._intervals[-1]
        if last.end is not None and (self.horizon is None or self.horizon > last.end):
            result.add(Interval(last.end, self.horizon, left_open=not last.right_open))

        result.set_horizon(self.horizon)
        return result

    def union(self, s: 'BooleanSignal') -> 'BooleanSignal':
        """Return the union of this signal's intervals with ``s``'s.

        Every interval from either signal that intersects or abuts another
        (see :meth:`~cytlmonitor.interval.Interval.intersect` and
        :meth:`~cytlmonitor.interval.Interval.just_before`) is merged with
        it via :meth:`~cytlmonitor.interval.Interval.join`; the rest are
        kept unchanged. The result's ``horizon`` is the greater of the two
        signals' horizons.
        """
        if not isinstance(s, BooleanSignal):
            raise TypeError(f"Expected a BooleanSignal, got {type(s).__name__}")

        def mergeable(a: Interval, b: Interval) -> bool:
            return a.intersect(b) or a.just_before(b) or b.just_before(a)

        result = BooleanSignal()
        pending: Optional[Interval] = None
        for interval in _merge_by_start(self._intervals, s._intervals):
            if pending is None:
                pending = interval
            elif mergeable(pending, interval):
                pending = pending.join(interval)
            else:
                result.add(pending)
                pending = interval
        if pending is not None:
            result.add(pending)

        result.set_horizon(_max_horizon(self.horizon, s.horizon))
        return result

    def intersection(self, s: 'BooleanSignal') -> 'BooleanSignal':
        """Return the intersection of this signal's intervals with ``s``'s.

        The two sequences are walked together: every pair of intersecting
        intervals contributes their common part, and whichever of the two
        ends first is then left behind. The result's ``horizon`` is the
        greater of the two signals' horizons.
        """
        if not isinstance(s, BooleanSignal):
            raise TypeError(f"Expected a BooleanSignal, got {type(s).__name__}")

        result = BooleanSignal()
        a, b = self._intervals, s._intervals
        i = j = 0
        while i < len(a) and j < len(b):
            common = a[i].intersection(b[j])
            if common is not None:
                result.add(common)
            if _ends_first(a[i], b[j]):
                i += 1
            else:
                j += 1

        result.set_horizon(_max_horizon(self.horizon, s.horizon))
        return result

    def shift(self, t: float) -> 'BooleanSignal':
        """Return a new signal built by applying
        :meth:`~cytlmonitor.interval.Interval.shift` with ``t`` to every
        interval in this signal (forward if ``t`` is positive, back if
        ``t`` is negative), discarding whichever ones return ``None``.
        The result's ``horizon`` is this signal's shifted by ``t``, and 0
        if that would be negative.
        """
        result = BooleanSignal()
        for interval in self._intervals:
            shifted = interval.shift(t)
            if shifted is not None:
                result.add(shifted)
        if self.horizon is None:
            result.set_horizon(None)
        else:
            result.set_horizon(max(0.0, self.horizon + float(t)))
        return result

    def backward(self, i: Interval) -> 'BooleanSignal':
        """Return a new signal built by applying
        :meth:`~cytlmonitor.interval.Interval.backward` with ``i`` to every
        interval in this signal, discarding whichever ones return ``None``
        and joining together any results that overlap, touch, or abut one
        another. The result's ``horizon`` is the same as this signal's, or
        the end of its last interval if that is greater.
        """
        if not isinstance(i, Interval):
            raise TypeError(f"Expected an Interval, got {type(i).__name__}")

        def mergeable(a: Interval, b: Interval) -> bool:
            return a.intersect(b) or a.just_before(b) or b.just_before(a)

        result = BooleanSignal()
        pending: Optional[Interval] = None
        for interval in self._intervals:
            transformed = interval.backward(i)
            if transformed is None:
                continue
            if pending is None:
                pending = transformed
            elif mergeable(pending, transformed):
                pending = pending.join(transformed)
            else:
                result.add(pending)
                pending = transformed
        if pending is not None:
            result.add(pending)

        result.set_horizon(_max_horizon(self.horizon, result.horizon))
        return result

    def length(self) -> int:
        """The number of intervals in the sequence."""
        return len(self._intervals)

    def __len__(self) -> int:
        return self.length()

    def __getitem__(self, i: int) -> Interval:
        return self._intervals[i]

    def __iter__(self) -> Iterator[Interval]:
        return iter(self._intervals)

    def __repr__(self) -> str:
        return f"BooleanSignal({self._intervals!r})"
