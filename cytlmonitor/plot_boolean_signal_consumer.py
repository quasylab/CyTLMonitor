"""
cytlmonitor.plot_boolean_signal_consumer
==========================================
Boolean signal consumer plotting the signal it receives with Matplotlib.

A :class:`PlotBooleanSignalConsumer` draws every
:class:`~cytlmonitor.interval.Interval` it consumes as a constant 1
signal over that interval, the part of ``[0, horizon)`` not covered by any
interval (where the signal is known to be false) as a constant 0 signal,
and the horizon as a vertical line at its position, redrawing the figure
at every change, so that the signal published by an
:class:`~cytlmonitor.event_monitor.EventMonitor` can be watched while the
stream is processed. Where a false stretch meets an interval, a vertical
edge joins 0 and 1; nothing is drawn at 0 after the horizon, where the
signal is not known yet.

Intervals arriving one right after the other, as monitors often publish a
long true stretch in pieces, are drawn as a single line. An interval
reduced to a single point is drawn as a marker, unless it touches the
line already drawn. A right-unbounded interval is drawn
``unbounded_extent`` beyond the furthest point plotted so far.

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

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.interval import Interval
from cytlmonitor.plot_style import Redrawer, create_axes


class PlotBooleanSignalConsumer(BooleanSignalConsumer):
    """A BooleanSignalConsumer plotting the received intervals as a
    constant 1 signal, the known false part as a constant 0 signal, and the
    horizon as a vertical line, updating the plot at every change."""

    __slots__ = ('_intervals', '_horizon', '_unbounded_extent', '_figure', '_axes',
                 '_line', '_false_line', '_points', '_horizon_line', '_xs', '_ys',
                 '_fx', '_fy', '_px', '_x_max', '_pending', '_covered', '_after_true',
                 '_redrawer')

    def __init__(self, title: str = 'Boolean signal', axes=None,
                 unbounded_extent: float = 1.0, dark: bool = False,
                 refresh_interval: float = 0.05):
        if unbounded_extent <= 0:
            raise ValueError(f"unbounded_extent must be positive, got {unbounded_extent}.")
        self._intervals: List[Interval] = []
        self._horizon: Optional[float] = None
        self._unbounded_extent = float(unbounded_extent)
        self._xs: List[float] = []
        self._ys: List[float] = []
        self._px: List[float] = []
        self._x_max: Optional[float] = None
        # Points of the false stretches drawn at 0, with their edges.
        self._fx: List[float] = []
        self._fy: List[float] = []
        # Spans (start, end) of the intervals not yet reached by the
        # horizon; end is None when unbounded.
        self._pending: List[Tuple[float, Optional[float]]] = []
        # The false stretches are drawn up to here.
        self._covered = 0.0
        # True if a true interval ends at ``covered``.
        self._after_true = False

        self._figure, self._axes, theme = create_axes(title, axes, dark)
        self._redrawer = Redrawer(self._figure, refresh_interval)
        axes = self._axes
        axes.set_ylim(-0.15, 1.15)
        axes.update_datalim([(0.0, 0.5)])
        axes.set_yticks([0, 1])
        axes.set_yticklabels(['false', 'true'])

        self._line, = axes.plot([], [], color=theme['series'], linewidth=2,
                                solid_capstyle='round')
        self._false_line, = axes.plot([], [], color=theme['series'], linewidth=2,
                                      solid_capstyle='round', solid_joinstyle='miter')
        self._points, = axes.plot([], [], linestyle='none', marker='o', markersize=8,
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
        """Add ``i`` to the plot, as a constant 1 signal, and redraw it."""
        if not isinstance(i, Interval):
            raise TypeError(f"Expected an Interval, got {type(i).__name__}")
        self._intervals.append(i)
        touches_line = bool(self._xs) and self._xs[-1] == i.start
        if i.is_point:
            if not touches_line:
                self._px.append(i.start)
            self._grow(i.start)
        else:
            end = i.end
            if end is None:
                end = max(i.start, self._x_max if self._x_max is not None else i.start)
                end += self._unbounded_extent
            if self._px and self._px[-1] == i.start:
                # The interval continues a point drawn as a marker.
                self._px.pop()
            if touches_line:
                # Continue the line of the previous interval.
                self._xs[-1] = end
            else:
                if self._xs:
                    # Keep separate intervals apart.
                    self._xs.append(float('nan'))
                    self._ys.append(float('nan'))
                self._xs.extend([i.start, end])
                self._ys.extend([1.0, 1.0])
            self._pending.append((i.start, i.end))
            self._grow(end)
        self.update()

    def set_horizon(self, t: float) -> None:
        """Move the vertical line marking the horizon to ``t`` and redraw
        the plot."""
        self._horizon = float(t)
        self._horizon_line.set_xdata([self._horizon, self._horizon])
        self._horizon_line.set_visible(True)
        self._draw_false_until(self._horizon)
        self._grow(self._horizon)
        self.update()

    def update(self) -> None:
        """Update the plot with the intervals and the horizon received so
        far, redrawing it if ``refresh_interval`` has passed since the last
        redraw."""
        self._line.set_data(self._xs, self._ys)
        self._false_line.set_data(self._fx, self._fy)
        self._points.set_data(self._px, [1.0] * len(self._px))
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

    def _draw_false_until(self, h: float) -> None:
        """Draw at 0 the stretches of ``[covered, h)`` not covered by any
        interval, joined by vertical edges to the intervals they meet."""
        x, after_true = self._covered, self._after_true
        while self._pending and self._pending[0][0] < h:
            start, end = self._pending.pop(0)
            if start > x:
                self._false_stretch(x, start, after_true, True)
            elif start == x and not after_true and self._fx and self._fx[-1] == x \
                    and self._fy[-1] == 0.0:
                # The interval starts where a false stretch drawn before it
                # was published ends: draw the rising edge.
                self._fx.append(x)
                self._fy.append(1.0)
            x = float('inf') if end is None else max(x, end)
            after_true = True
        if x < h:
            self._false_stretch(x, h, after_true, False)
            x, after_true = h, False
        self._covered, self._after_true = x, after_true

    def _false_stretch(self, start: float, end: float, from_true: bool, to_true: bool) -> None:
        if not from_true and self._fx and self._fx[-1] == start and self._fy[-1] == 0.0:
            # Continue the false stretch drawn up to start.
            self._fx[-1] = end
        else:
            self._open_stretch(start, from_true)
            self._fx.append(end)
            self._fy.append(0.0)
        if to_true:
            self._fx.append(end)
            self._fy.append(1.0)

    def _open_stretch(self, start: float, from_true: bool) -> None:
        if self._fx:
            self._fx.append(float('nan'))
            self._fy.append(float('nan'))
        if from_true:
            self._fx.append(start)
            self._fy.append(1.0)
        self._fx.append(start)
        self._fy.append(0.0)

    def _grow(self, x: float) -> None:
        if self._x_max is None or x > self._x_max:
            self._x_max = x
            self._axes.update_datalim([(x, 0.5)])
