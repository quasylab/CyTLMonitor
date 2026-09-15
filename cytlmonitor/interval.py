"""
cytlmonitor.interval
=====================
Representation of a temporal interval.

An :class:`Interval` describes a range of float values delimited by a
mandatory starting value (``from_``) and an optional ending value (``to``).
Each side of the interval can independently be open or closed:

  * left-open   -> ``from_`` is *not* part of the interval
  * right-open  -> ``to`` is *not* part of the interval

By default an interval is left-closed and right-open (e.g. ``[from_, to)``).

If ``to`` is ``None`` the interval is right unbounded (it extends to
``+inf``); in that case there is no ending value to include or exclude, so
the interval is always treated as right-open.

An interval is a *point interval* when it is closed on both sides and
``from_`` and ``to`` are equal (e.g. ``[5, 5]``).

Note: ``from`` is a Python keyword, so the starting value is stored/passed
as ``from_``.
"""

from __future__ import annotations

from typing import Optional


class Interval:
    """A (possibly right-unbounded) interval of float values."""

    __slots__ = ('from_', 'to', 'left_open', 'right_open')

    def __init__(self, from_: float, to: Optional[float] = None,
                 left_open: bool = False, right_open: bool = True):
        from_ = float(from_)
        if to is not None:
            to = float(to)
            if to < from_:
                raise ValueError(
                    f"Invalid interval: 'to' ({to}) cannot be smaller than 'from' ({from_})."
                )
            if to == from_ and (left_open or right_open):
                raise ValueError(
                    "A degenerate interval (from == to) must be closed on both sides."
                )
        else:
            # Right unbounded: there is no 'to' value to ever include.
            right_open = True

        self.from_ = from_
        self.to = to
        self.left_open = left_open
        self.right_open = right_open

    @classmethod
    def point(cls, value: float) -> 'Interval':
        """Build the point interval ``[value, value]``."""
        return cls(value, value, left_open=False, right_open=False)

    @property
    def is_point(self) -> bool:
        """True if this is a closed interval with from_ == to."""
        return self.to is not None and self.to == self.from_ \
            and not self.left_open and not self.right_open

    @property
    def is_right_unbounded(self) -> bool:
        """True if this interval has no ending value (extends to +inf)."""
        return self.to is None

    def contains(self, value: float) -> bool:
        """True if ``value`` belongs to this interval."""
        value = float(value)
        if value < self.from_ or (value == self.from_ and self.left_open):
            return False
        if self.to is not None:
            if value > self.to or (value == self.to and self.right_open):
                return False
        return True

    __contains__ = contains

    def __eq__(self, other) -> bool:
        if not isinstance(other, Interval):
            return NotImplemented
        return (self.from_ == other.from_ and self.to == other.to
                and self.left_open == other.left_open
                and self.right_open == other.right_open)

    def __hash__(self) -> int:
        return hash((self.from_, self.to, self.left_open, self.right_open))

    def __repr__(self) -> str:
        left = '(' if self.left_open else '['
        if self.to is None:
            return f"{left}{self.from_}, +inf)"
        right = ')' if self.right_open else ']'
        return f"{left}{self.from_}, {self.to}{right}"

    __str__ = __repr__
