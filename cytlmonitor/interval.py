"""
cytlmonitor.interval
=====================
Representation of a temporal interval.

An :class:`Interval` describes a range of float values delimited by a
mandatory starting value (``start``) and an optional ending value (``end``).
Each side of the interval can independently be open or closed:

  * left-open   -> ``start`` is *not* part of the interval
  * right-open  -> ``end`` is *not* part of the interval

By default an interval is left-closed and right-open (e.g. ``[start, end)``).

If ``end`` is ``None`` the interval is right unbounded (it extends to
``+inf``); in that case there is no ending value to include or exclude, so
the interval is always treated as right-open.

An interval is a *point interval* when it is closed on both sides and
``start`` and ``end`` are equal (e.g. ``[5,5]``).

The standard string representation uses ``[``/``(`` for a closed/open left
bound and ``]``/``)`` for a closed/open right bound, e.g. ``[1,5]``,
``(1,5]``, ``[1,5)``, ``(1,5)``. If ``end`` is ``None`` the ``end`` element is
omitted, e.g. ``[1,)``.
"""

from __future__ import annotations

from typing import Optional, Tuple


class Interval:
    """A (possibly right-unbounded) interval of float values."""

    __slots__ = ('start', 'end', 'left_open', 'right_open')

    def __init__(self, start: float, end: Optional[float] = None,
                 left_open: bool = False, right_open: bool = True):
        start = float(start)
        if end is not None:
            end = float(end)
            if end < start:
                raise ValueError(
                    f"Invalid interval: 'end' ({end}) cannot be smaller than 'start' ({start})."
                )
            if end == start and (left_open or right_open):
                raise ValueError(
                    "A degenerate interval (start == end) must be closed on both sides."
                )
        else:
            # Right unbounded: there is no 'end' value to ever include.
            right_open = True

        self.start = start
        self.end = end
        self.left_open = left_open
        self.right_open = right_open

    @classmethod
    def point(cls, value: float) -> 'Interval':
        """Build the point interval ``[value, value]``."""
        return cls(value, value, left_open=False, right_open=False)

    @property
    def is_point(self) -> bool:
        """True if this is a closed interval with start == end."""
        return self.end is not None and self.end == self.start \
            and not self.left_open and not self.right_open

    @property
    def is_right_unbounded(self) -> bool:
        """True if this interval has no ending value (extends to +inf)."""
        return self.end is None

    def contains(self, value: float) -> bool:
        """True if ``value`` belongs to this interval."""
        value = float(value)
        if value < self.start or (value == self.start and self.left_open):
            return False
        if self.end is not None:
            if value > self.end or (value == self.end and self.right_open):
                return False
        return True

    __contains__ = contains

    def complement(self, t: float, open_left: bool = False) -> Optional['Interval']:
        """Return the interval spanning from ``t`` up to ``self.start``.

        This is the "gap" preceding this interval: it touches ``self`` at
        ``self.start`` without overlapping it or leaving a gap there (its
        right bound at ``self.start`` is closed iff ``self`` is left-open).
        Its left bound at ``t`` is open iff ``open_left`` is True.

        Returns ``None`` if ``t`` already belongs to this interval, or if
        ``t == self.start`` while both ``open_left`` and ``self.left_open``
        are True (the computed interval would then be empty).

        Raises a ``ValueError`` if ``t`` is negative, or if ``t`` lies
        after ``self.start`` without being contained in ``self`` (i.e. ``t``
        falls inside or past this interval).
        """
        t = float(t)
        if t < 0:
            raise ValueError(f"t must be non-negative, got {t}.")
        if self.contains(t):
            return None
        if t == self.start and open_left and self.left_open:
            return None
        if t > self.start:
            raise ValueError(f"{t} is after interval {self!r}.")
        return Interval(t, self.start, left_open=open_left, right_open=not self.left_open)

    def shift(self, t: float) -> Optional['Interval']:
        """Return a new interval obtained by moving ``start`` and ``end``
        (if not ``None``) by ``t``: forward if ``t`` is positive, back if
        ``t`` is negative.

        If the shifted ``start`` would be negative, only the positive part
        of the shifted interval (its intersection with ``[0, +inf)``) is
        returned. ``None`` is returned only when the whole shifted interval
        would be negative (including when it ends exactly at 0 but
        excludes that point, i.e. ``self`` is right-open). Neither can
        happen when ``t`` is non-negative.
        """
        t = float(t)
        new_start = self.start + t
        new_end = None if self.end is None else self.end + t

        if new_start >= 0:
            return Interval(new_start, new_end, left_open=self.left_open, right_open=self.right_open)
        if new_end is not None and new_end < 0:
            return None
        if new_end is not None and new_end == 0:
            return None if self.right_open else Interval.point(0.0)
        return Interval(0.0, new_end, left_open=False, right_open=self.right_open)

    def backward(self, i: 'Interval') -> Optional['Interval']:
        """Return the interval ``res`` such that, for every ``t``,
        ``res.contains(t)`` iff there is a ``t'`` with ``i.contains(t')``
        and ``self.contains(t + t')``.

        Returns ``None`` if no such (non-empty) interval exists.
        """
        if not isinstance(i, Interval):
            raise TypeError(f"Expected an Interval, got {type(i).__name__}")

        new_start = 0.0 if i.end is None else self.start - i.end
        new_end = None if self.end is None else self.end - i.start

        if new_end is not None and new_end < 0:
            return None

        # A boundary of the result is open unless the two intervals both
        # include the corresponding pair of endpoints that produced it
        # (self.start pairs with i.end for new_start, self.end pairs with
        # i.start for new_end) -- hence the *opposite*-side pairing below.
        new_left_open = (self.left_open or i.right_open) and (new_start >= 0) and (i.end is not None)
        new_right_open = self.right_open or i.left_open

        new_start = max(0.0, new_start)

        if new_start == new_end and (new_left_open or new_right_open):
            return None

        return Interval(new_start, new_end, left_open=new_left_open, right_open=new_right_open)

    def split(self, t: float, open_on_left_side: bool = True) -> Tuple['Interval', 'Interval']:
        """Split this interval in two at ``t``.

        Returns a pair ``(i_left, i_right)``: ``i_left`` spans from
        ``self.start`` to ``t`` and ``i_right`` spans from ``t`` to
        ``self.end``. The shared boundary at ``t`` is open on ``i_left``'s
        right side iff ``open_on_left_side`` is True, and closed on
        exactly one of the two sides otherwise, so together ``i_left`` and
        ``i_right`` exactly partition ``self`` with no overlap or gap.

        Raises a ``ValueError`` if ``t`` does not belong to this interval.
        """
        t = float(t)
        if not self.contains(t):
            raise ValueError(f"{t} is outside interval {self!r}.")
        i_left = Interval(self.start, t, left_open=self.left_open, right_open=open_on_left_side)
        i_right = Interval(t, self.end, left_open=not open_on_left_side, right_open=self.right_open)
        return i_left, i_right

    def intersect(self, other: 'Interval') -> bool:
        """True if this interval and ``other`` have at least one value in
        common, i.e. their intersection is not empty."""
        if not isinstance(other, Interval):
            raise TypeError(f"Expected an Interval, got {type(other).__name__}")
        return not self.is_before(other) and not other.is_before(self)

    def intersection(self, other: 'Interval') -> Optional['Interval']:
        """Return the values this interval and ``other`` have in common,
        as an interval, or ``None`` if they do not intersect."""
        if not self.intersect(other):
            return None
        if self.start > other.start or (self.start == other.start and self.left_open):
            start, left_open = self.start, self.left_open
        else:
            start, left_open = other.start, other.left_open
        if other.end is None:
            first = self
        elif self.end is None:
            first = other
        elif self.end != other.end:
            first = self if self.end < other.end else other
        else:
            first = self if self.right_open else other
        return Interval(start, first.end, left_open=left_open, right_open=first.right_open)

    def is_before(self, i: 'Interval') -> bool:
        """True if this interval lies entirely before ``i``: either
        ``self.end < i.start``, or ``self.end == i.start`` and at least one
        of the two excludes that shared point. A right-unbounded interval
        is never before another."""
        if not isinstance(i, Interval):
            raise TypeError(f"Expected an Interval, got {type(i).__name__}")
        if self.end is None:
            return False
        if self.end < i.start:
            return True
        if self.end == i.start:
            return self.right_open or i.left_open
        return False

    def just_before(self, other: 'Interval') -> bool:
        """True if this interval ends exactly where ``other`` begins, with
        exactly one of the two including that shared point (i.e. they abut
        without overlap or gap)."""
        if not isinstance(other, Interval):
            raise TypeError(f"Expected an Interval, got {type(other).__name__}")
        return self.end == other.start and self.right_open == (not other.left_open)

    def join(self, other: 'Interval') -> 'Interval':
        """Return the smallest interval containing both this interval and ``other``.

        Raises a ``ValueError`` if the two intervals neither intersect (their
        intersection is non-empty) nor abut (one is immediately before the
        other, see :meth:`just_before`), since their union would then not
        be an interval.
        """
        if not isinstance(other, Interval):
            raise TypeError(f"Expected an Interval, got {type(other).__name__}")
        if not (self.intersect(other) or self.just_before(other) or other.just_before(self)):
            raise ValueError(f"Cannot join disjoint intervals {self!r} and {other!r}.")

        if self.start < other.start:
            new_start, new_left_open = self.start, self.left_open
        elif other.start < self.start:
            new_start, new_left_open = other.start, other.left_open
        else:
            new_start, new_left_open = self.start, self.left_open and other.left_open

        if self.end is None or other.end is None:
            return Interval(new_start, None, left_open=new_left_open)

        if self.end > other.end:
            new_end, new_right_open = self.end, self.right_open
        elif other.end > self.end:
            new_end, new_right_open = other.end, other.right_open
        else:
            new_end, new_right_open = self.end, self.right_open and other.right_open

        return Interval(new_start, new_end, left_open=new_left_open, right_open=new_right_open)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Interval):
            return NotImplemented
        return (self.start == other.start and self.end == other.end
                and self.left_open == other.left_open
                and self.right_open == other.right_open)

    def __hash__(self) -> int:
        return hash((self.start, self.end, self.left_open, self.right_open))

    def __repr__(self) -> str:
        left = '(' if self.left_open else '['
        right = ')' if self.right_open else ']'
        end_str = '' if self.end is None else str(self.end)
        return f"{left}{self.start},{end_str}{right}"

    __str__ = __repr__
