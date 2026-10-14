"""
cytlmonitor.min_window_expression
=================================
Stream expression computing a sliding-window minimum over another
expression's signal.

A :class:`MinWindowExpression` wraps a nested
:class:`~cytlmonitor.stream_expression.StreamExpression` ``arg`` and
publishes the signal

    f(t) = min of g(s) over s in [t + from, t + to]

for ``t >= 0``, where ``g`` is the piecewise-constant signal published by
``arg``. See :mod:`cytlmonitor.window_extremum_expression` for how the
signal is computed and when it is published.
"""

from __future__ import annotations

from cytlmonitor.window_extremum_expression import WindowExtremumExpression


class MinWindowExpression(WindowExtremumExpression):
    """A StreamExpression publishing, for each time ``t``, the minimum of
    the signal of ``arg`` over ``[t + from, t + to]``."""

    __slots__ = ()

    @staticmethod
    def _supersedes(value: float, other: float) -> bool:
        """A later value at least as small as ``other`` supersedes it."""
        return value <= other
