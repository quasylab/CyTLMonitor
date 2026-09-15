"""
cytlmonitor.signal
=====================
Representation of a piecewise-polynomial signal.

A :class:`Signal` holds :class:`~cytlmonitor.segment.Segment` instances
ordered by their interval's start: if ``s1`` precedes ``s2`` in the signal,
then ``s1``'s interval ends at or before ``s2``'s interval starts, and the
two intervals do not both contain the shared boundary point. Segments can
only be appended at the end. Temporal gaps between segments are allowed; no
interpolation, extrapolation, or automatic gap filling is performed.
"""

from __future__ import annotations

from typing import Iterable, Iterator, List, Optional

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
        ``ValueError`` if the previous segment is right-unbounded (nothing
        can follow it), or if ``segment``'s interval starts before the
        previous segment's interval ends, or starts exactly where it ends
        while both intervals include that shared boundary point.
        """
        if not isinstance(segment, Segment):
            raise TypeError(f"Expected a Segment, got {type(segment).__name__}")
        if self._segments:
            previous = self._segments[-1].interval
            if previous.is_right_unbounded:
                raise ValueError(
                    "Cannot add a segment after a right-unbounded segment."
                )
            new_interval = segment.interval
            if new_interval.from_ < previous.to:
                raise ValueError(
                    f"Segment starting at {new_interval.from_} overlaps the "
                    f"previous segment, which ends at {previous.to}."
                )
            if (new_interval.from_ == previous.to
                    and not previous.right_open and not new_interval.left_open):
                raise ValueError(
                    f"Segment starting at {new_interval.from_} overlaps the "
                    f"previous segment at the shared boundary {previous.to}: "
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

    def __eq__(self, other) -> bool:
        if not isinstance(other, Signal):
            return NotImplemented
        return self._segments == other._segments

    def __repr__(self) -> str:
        return f"Signal({self._segments!r})"
