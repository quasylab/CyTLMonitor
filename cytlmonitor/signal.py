"""
cytlmonitor.signal
=====================
Representation of a piecewise-polynomial signal.

A :class:`Signal` holds :class:`~cytlmonitor.segment.Segment` instances
ordered by their interval's start: if ``s1`` precedes ``s2`` in the signal,
then ``s1``'s interval ends at or before ``s2``'s interval starts, and the
two intervals do not both contain the shared boundary point. The first
segment's interval always starts at 0 and is left-closed. Segments can
only be appended at the end. Temporal gaps between segments are allowed; no
interpolation, extrapolation, or automatic gap filling is performed.
"""

from __future__ import annotations

from typing import Iterable, Iterator, List, Optional

from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment


class Signal:
    """A piecewise-polynomial signal: Segments ordered by interval start."""

    __slots__ = ('_segments',)

    def __init__(self, segments: Optional[Iterable[Segment]] = None):
        self._segments: List[Segment] = []
        if segments is not None:
            for segment in segments:
                self.add(segment)

    def add(self, segment: Segment) -> None:
        """Append ``segment`` at the end of the signal.

        Raises a ``TypeError`` if ``segment`` is not a ``Segment``. Raises a
        ``ValueError`` if ``segment`` is the first one and its interval does
        not start at 0 or is left-open, if the previous segment is
        right-unbounded (nothing
        can follow it), or if ``segment``'s interval starts before the
        previous segment's interval ends, or starts exactly where it ends
        while both intervals include that shared boundary point.
        """
        if not isinstance(segment, Segment):
            raise TypeError(f"Expected a Segment, got {type(segment).__name__}")
        if not self._segments:
            first = segment.interval
            if first.start != 0.0 or first.left_open:
                raise ValueError(
                    f"The first segment must start at 0 and be left-closed, got {first!r}."
                )
        else:
            previous = self._segments[-1].interval
            if previous.is_right_unbounded:
                raise ValueError(
                    "Cannot add a segment after a right-unbounded segment."
                )
            new_interval = segment.interval
            if new_interval.start < previous.end:
                raise ValueError(
                    f"Segment starting at {new_interval.start} overlaps the "
                    f"previous segment, which ends at {previous.end}."
                )
            if (new_interval.start == previous.end
                    and not previous.right_open and not new_interval.left_open):
                raise ValueError(
                    f"Segment starting at {new_interval.start} overlaps the "
                    f"previous segment at the shared boundary {previous.end}: "
                    "both intervals include that point."
                )
        self._segments.append(segment)

    def length(self) -> int:
        """The number of segments in the signal."""
        return len(self._segments)

    def __len__(self) -> int:
        return self.length()

    def __getitem__(self, index: int) -> Segment:
        return self._segments[index]

    def __iter__(self) -> Iterator[Segment]:
        return iter(self._segments)

    def contains(self, time: float) -> bool:
        """True if some segment of this signal contains ``time``."""
        return any(segment.contains(time) for segment in self._segments)

    __contains__ = contains

    def get_segment_at(self, time: float) -> Segment:
        """Return the unique segment containing ``time``.

        Raises a ``ValueError`` if no segment contains ``time``, including
        when the signal is empty or ``time`` falls in a temporal gap.
        """
        for segment in self._segments:
            if segment.contains(time):
                return segment
        raise ValueError(f"No segment of this signal contains time {time}.")

    def value_at(self, time: float) -> float:
        """Evaluate the signal at the absolute timestamp ``time``."""
        return self.get_segment_at(time).value_at(time)

    def shift(self, t: float) -> 'Signal':
        """Return a new signal made of this signal's segments, each shifted by
        ``t`` (see :meth:`~cytlmonitor.segment.Segment.shift`): forward if
        ``t`` is positive, back if ``t`` is negative. Segments whose
        ``shift`` returns ``None`` are discarded.

        To keep the result starting at 0, a 0-valued segment is put in
        front of the shifted ones, covering the time from 0 up to where
        they start: ``[0, t)`` when ``t`` is positive. When ``t`` is
        negative this only happens if the first remaining segment does not
        already start at ``[0``, e.g. because of a gap in this signal.
        """
        shifted = [s for s in (segment.shift(t) for segment in self._segments) if s is not None]
        result = Signal()
        first = shifted[0].interval if shifted else None
        if first is None and float(t) > 0:
            result.add(Segment(Interval(0.0, t), Polynomial.ZERO))
        elif first is not None and (first.start > 0 or first.left_open):
            result.add(Segment(Interval(0.0, first.start, right_open=not first.left_open),
                               Polynomial.ZERO))
        for segment in shifted:
            result.add(segment)
        return result

    def __eq__(self, other) -> bool:
        if not isinstance(other, Signal):
            return NotImplemented
        return self._segments == other._segments

    def __repr__(self) -> str:
        return f"Signal({self._segments!r})"
