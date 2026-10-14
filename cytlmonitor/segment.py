"""
cytlmonitor.segment
=====================
Representation of one piece of a piecewise-polynomial signal.

A :class:`Segment` couples a temporal :class:`~cytlmonitor.interval.Interval`
with the :class:`~cytlmonitor.polynomial.Polynomial` that describes the
signal's value while time lies within that interval. Both fields are
read-only. A future ``Signal`` will be an ordered list of ``Segment``
objects; ordering, gap/overlap validation, and interpolation between
segments are that class's responsibility, not this one's.
"""

from __future__ import annotations

from typing import Optional

from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial


class Segment:
    """One piece of a piecewise-polynomial signal: an Interval paired with a Polynomial."""

    __slots__ = ('_interval', '_polynomial')

    def __init__(self, interval: Interval, polynomial: Polynomial):
        if not isinstance(interval, Interval):
            raise TypeError(f"Expected an Interval, got {type(interval).__name__}")
        if not isinstance(polynomial, Polynomial):
            raise TypeError(f"Expected a Polynomial, got {type(polynomial).__name__}")
        self._interval = interval
        self._polynomial = polynomial

    @property
    def interval(self) -> Interval:
        """The Interval over which this segment is defined."""
        return self._interval

    @property
    def polynomial(self) -> Polynomial:
        """The Polynomial describing this segment's value."""
        return self._polynomial

    def get_interval(self) -> Interval:
        """Return the Interval over which this segment is defined."""
        return self._interval

    def get_polynomial(self) -> Polynomial:
        """Return the Polynomial describing this segment's value."""
        return self._polynomial

    def contains(self, time: float) -> bool:
        """True if ``time`` belongs to this segment's interval."""
        return self._interval.contains(time)

    __contains__ = contains

    def value_at(self, time: float) -> float:
        """Evaluate the segment's polynomial at the absolute timestamp ``time``."""
        time = float(time)
        if not self._interval.contains(time):
            raise ValueError(
                f"Time {time} is outside the segment's interval {self._interval!r}."
            )
        return self._polynomial.evaluate(time)

    def sup(self) -> float:
        """Return the supremum of this segment's polynomial over its interval."""
        return self._polynomial.sup(self._interval)

    def inf(self) -> float:
        """Return the infimum of this segment's polynomial over its interval."""
        return self._polynomial.inf(self._interval)

    def shift(self, t: float) -> Optional['Segment']:
        """Return a new segment with its interval shifted by ``t``
        (see :meth:`~cytlmonitor.interval.Interval.shift`): forward if
        ``t`` is positive, back if ``t`` is negative. The polynomial is
        shifted along with it (see
        :meth:`~cytlmonitor.polynomial.Polynomial.shift`), so that the new
        segment takes at ``x + t`` the value this one takes at ``x``.

        Returns ``None`` if the interval's ``shift`` returns ``None``.
        """
        shifted = self._interval.shift(t)
        if shifted is None:
            return None
        return Segment(shifted, self._polynomial.shift(t))

    def __eq__(self, other) -> bool:
        if not isinstance(other, Segment):
            return NotImplemented
        return self._interval == other._interval and self._polynomial == other._polynomial

    def __repr__(self) -> str:
        return f"Segment(interval={self._interval!r}, polynomial={self._polynomial!r})"
