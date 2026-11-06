r"""
cytlmonitor.consumers.plot.boolean_signal
=========================================
Boolean signal consumer plotting the signal it receives with Matplotlib.

A :class:`PlotBooleanSignalConsumer` draws the boolean signal it receives
as a piecewise-constant line: at 1 on the
:class:`~cytlmonitor.core.interval.Interval`\ s it consumes, where the signal is
true, and at 0 on the rest of ``[0, horizon)``, where it is known to be
false, with vertical edges where the value changes. The horizon is drawn
as a dashed vertical line; nothing is drawn at 0 after it, where the
signal is not known yet. The signal ``[2,3) (4.5,7.5) [10,26]`` with
horizon 30, for instance, is drawn at 0 on ``[0, 2]``, at 1 on ``[2, 3]``,
at 0 on ``[3, 4.5]``, and so on, up to 0 on ``[26, 30]``.

At each end of an interval the line has two points, at 0 and at 1. A dot
shows the value of the signal at that end: at 1 when the end is closed,
at 0 when it is open. In the example, the dots are at ``(2, 1)``,
``(3, 0)``, ``(4.5, 0)``, ``(7.5, 0)``, ``(10, 1)`` and ``(26, 1)``. An
interval reduced to a single point is drawn as a spike from 0 to 1, with a
dot at 1.

Intervals published one right after the other, as monitors often publish
a long true stretch in pieces, are drawn as a single interval, with no dot
where they meet. The end of an interval is drawn, with its falling edge and
its dot, once the horizon has passed it, since until then the next
interval may continue it. A right-unbounded interval is drawn
``unbounded_extent`` beyond its start or the horizon, whichever is later.

The data is updated at every change. In Matplotlib interactive mode
(``matplotlib.pyplot.ion()``), where the figure is showing, it is
also redrawn, at most every ``refresh_interval`` seconds, so that a
busy stream is not slowed down by drawing; otherwise it is drawn by
``show`` or ``savefig``. :meth:`PlotBooleanSignalConsumer.refresh` redraws it at once.

Matplotlib is imported when a consumer is built, so the rest of
``cytlmonitor`` does not depend on it.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.consumers.plot.style import Redrawer, create_axes
from cytlmonitor.core.interval import Interval


Point = Optional[Tuple[float, float]]


class PlotBooleanSignalConsumer(BooleanSignalConsumer):
    """A BooleanSignalConsumer plotting the received signal as a
    piecewise-constant line, at 1 where it is true and at 0 where it is
    known to be false, with a dot at the value of each end of an interval,
    and the horizon as a vertical line, updating the plot at every
    change."""

    __slots__ = ('_intervals', '_horizon', '_unbounded_extent', '_figure', '_axes',
                 '_line', '_dots', '_horizon_line', '_xs', '_ys', '_dx', '_dy',
                 '_last', '_covered', '_runs', '_x_max', '_redrawer')

    def __init__(self, title: str = 'Boolean signal', axes=None,
                 unbounded_extent: float = 1.0, dark: bool = False,
                 refresh_interval: float = 0.05):
        if unbounded_extent <= 0:
            raise ValueError(f"unbounded_extent must be positive, got {unbounded_extent}.")
        self._intervals: List[Interval] = []
        self._horizon: Optional[float] = None
        self._unbounded_extent = float(unbounded_extent)
        # The line and the dots of the intervals the horizon has passed,
        # and of the false stretches before them.
        self._xs: List[float] = []
        self._ys: List[float] = []
        self._dx: List[float] = []
        self._dy: List[float] = []
        # The last point of the line, and where it ends, at 0.
        self._last: Point = None
        self._covered = 0.0
        # The intervals the horizon has not passed yet, with those
        # continuing one another joined.
        self._runs: List[Interval] = []
        self._x_max: Optional[float] = None

        self._figure, self._axes, theme = create_axes(title, axes, dark)
        self._redrawer = Redrawer(self._figure, refresh_interval)
        axes = self._axes
        axes.set_ylim(-0.15, 1.15)
        axes.update_datalim([(0.0, 0.5)])
        axes.set_yticks([0, 1])
        axes.set_yticklabels(['false', 'true'])

        self._line, = axes.plot([], [], color=theme['series'], linewidth=2,
                                solid_capstyle='round', solid_joinstyle='miter')
        self._dots, = axes.plot([], [], linestyle='none', marker='o', markersize=8,
                                color=theme['series'],
                                markeredgecolor=theme['surface'], markeredgewidth=2)
        self._horizon_line = axes.axvline(0.0, color=theme['muted'], linewidth=1.5,
                                          linestyle=(0, (4, 3)), visible=False)

    @property
    def intervals(self) -> List[Interval]:
        """The intervals consumed so far, in order."""
        return list(self._intervals)

    @property
    def horizon(self) -> Optional[float]:
        """The last horizon received (None if none was received)."""
        return self._horizon

    @property
    def figure(self):
        """The Matplotlib figure the signal is plotted on."""
        return self._figure

    @property
    def axes(self):
        """The Matplotlib axes the signal is plotted on."""
        return self._axes

    def consume(self, i: Interval) -> None:
        """Add ``i`` to the plot, where the signal is 1, and redraw it."""
        if not isinstance(i, Interval):
            raise TypeError(f"Expected an Interval, got {type(i).__name__}")
        self._intervals.append(i)
        runs = self._runs
        if runs and (runs[-1].intersect(i) or runs[-1].just_before(i)):
            runs[-1] = runs[-1].join(i)
        else:
            runs.append(i)
        self.update()

    def set_horizon(self, t: float) -> None:
        """Move the vertical line marking the horizon to ``t``, draw the
        intervals it has passed, and redraw the plot."""
        h = self._horizon = float(t)
        self._horizon_line.set_xdata([h, h])
        self._horizon_line.set_visible(True)
        runs = self._runs
        while runs and runs[0].end is not None and runs[0].end < h:
            self._covered, self._last = self._draw(
                runs.pop(0), self._covered, self._last, self._xs, self._ys, self._dx, self._dy)
        self.update()

    def update(self) -> None:
        """Update the plot with the intervals and the horizon received so
        far, redrawing it if ``refresh_interval`` has passed since the last
        redraw."""
        xs, ys, dx, dy = [], [], [], []
        pen = self._covered if self._horizon is not None else None
        last = self._last
        for run in self._runs:
            pen, last = self._draw(run, pen, last, xs, ys, dx, dy)
        h = self._horizon
        if pen is not None and pen < h:
            # False up to the horizon.
            if last != (pen, 0.0):
                xs.append(pen)
                ys.append(0.0)
            xs.append(h)
            ys.append(0.0)
        self._line.set_data(self._xs + xs, self._ys + ys)
        self._dots.set_data(self._dx + dx, self._dy + dy)
        # The furthest point drawn (NaN, which separates the pieces of the
        # line, is not equal to itself).
        self._grow(max((x for x in xs if x == x), default=0.0))
        if h is not None:
            self._grow(h)
        # Lazy: the time axis is fitted to the data the next time it is
        # drawn.
        self._axes.autoscale(axis='x')
        self._redrawer.request()

    def refresh(self) -> None:
        """Redraw the plot at once."""
        self._redrawer.request(force=True)

    def show(self, block: bool = True) -> None:
        """Show the figure in a window."""
        import matplotlib.pyplot as plt
        self.refresh()
        plt.show(block=block)

    def _draw(self, run: Interval, pen: Optional[float], last: Point,
              xs: List[float], ys: List[float], dx: List[float], dy: List[float]):
        """Append to ``xs``, ``ys`` the line of ``run``, and to ``dx``,
        ``dy`` its dots. The line is at 0 from ``pen`` (None when it is not
        known to be there) and its last point is ``last``. Return where the
        line is at 0 after ``run`` (None if it is not known yet) and its
        last point."""
        h = self._horizon

        def to(x, y):
            nonlocal last
            if last != (x, y):
                xs.append(x)
                ys.append(y)
                last = (x, y)

        start = run.start
        if pen is not None and start <= h:
            # False from pen up to the rising edge; there is no edge where
            # the signal starts true at 0.
            if not (last is None and start == 0.0 and not run.left_open):
                to(pen, 0.0)
                to(start, 0.0)
        elif last is not None:
            # Not known before the interval: keep it apart from the line.
            xs.append(float('nan'))
            ys.append(float('nan'))
            last = None
        to(start, 1.0)
        dx.append(start)
        dy.append(0.0 if run.left_open else 1.0)
        end = run.end
        if end is None:
            to(max(start, h if h is not None else start) + self._unbounded_extent, 1.0)
            return None, last
        to(end, 1.0)
        if h is None or end >= h:
            # The next interval may continue this one.
            return None, last
        to(end, 0.0)
        if not run.is_point:
            dx.append(end)
            dy.append(0.0 if run.right_open else 1.0)
        return end, last

    def _grow(self, x: float) -> None:
        if self._x_max is None or x > self._x_max:
            self._x_max = x
            self._axes.update_datalim([(x, 0.5)])
