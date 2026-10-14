"""
cytlmonitor.plot_signal_consumer
==================================
Signal consumer plotting the signal it receives with Matplotlib.

A :class:`PlotSignalConsumer` draws every
:class:`~cytlmonitor.segment.Segment` it consumes as part of a single line
and redraws the figure at once, so that a signal published by a
:class:`~cytlmonitor.stream_expression.StreamExpression` can be watched
while the stream is processed.

Constant segments are drawn from their two endpoints, the others sampled
at ``samples`` points; a jump between two segments shows as a vertical
step. A segment reduced to a single point is drawn as a marker. A
right-unbounded segment is drawn ``unbounded_extent`` beyond the furthest
point plotted so far.

The data is updated at every segment. In Matplotlib interactive mode
(``matplotlib.pyplot.ion()``), where the figure is showing, it is
also redrawn, at most every ``refresh_interval`` seconds, so that a
busy stream is not slowed down by drawing; otherwise it is drawn by
``show`` or ``savefig``. :meth:`PlotSignalConsumer.refresh` redraws it at once.

Matplotlib is imported when a consumer is built, so the rest of
``cytlmonitor`` does not depend on it.
"""

from __future__ import annotations

from typing import List, Optional

from cytlmonitor.plot_style import Redrawer, create_axes
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer


class PlotSignalConsumer(SignalConsumer):
    """A SignalConsumer plotting the received segments, updating the plot
    every time a new one is consumed."""

    __slots__ = ('_segments', '_samples', '_unbounded_extent', '_figure', '_axes',
                 '_line', '_points', '_xs', '_ys', '_px', '_py', '_x_max', '_redrawer')

    def __init__(self, title: str = 'Signal', axes=None, samples: int = 50,
                 unbounded_extent: float = 1.0, dark: bool = False,
                 refresh_interval: float = 0.05):
        if samples < 2:
            raise ValueError(f"samples must be at least 2, got {samples}.")
        if unbounded_extent <= 0:
            raise ValueError(f"unbounded_extent must be positive, got {unbounded_extent}.")
        self._segments: List[Segment] = []
        self._samples = samples
        self._unbounded_extent = float(unbounded_extent)
        self._xs: List[float] = []
        self._ys: List[float] = []
        self._px: List[float] = []
        self._py: List[float] = []
        self._x_max: Optional[float] = None

        self._figure, self._axes, theme = create_axes(title, axes, dark)
        self._redrawer = Redrawer(self._figure, refresh_interval)
        axes = self._axes

        self._line, = axes.plot([], [], color=theme['series'], linewidth=2,
                                solid_joinstyle='round', solid_capstyle='round')
        self._points, = axes.plot([], [], linestyle='none', marker='o', markersize=8,
                                  color=theme['series'],
                                  markeredgecolor=theme['surface'], markeredgewidth=2)

    @property
    def segments(self) -> List[Segment]:
        """The segments consumed so far, in order."""
        return list(self._segments)

    @property
    def figure(self):
        """The Matplotlib figure the signal is plotted on."""
        return self._figure

    @property
    def axes(self):
        """The Matplotlib axes the signal is plotted on."""
        return self._axes

    def consume(self, s: Segment) -> None:
        """Add ``s`` to the plot and redraw it."""
        if not isinstance(s, Segment):
            raise TypeError(f"Expected a Segment, got {type(s).__name__}")
        self._segments.append(s)
        interval, polynomial = s.interval, s.polynomial

        if interval.is_point:
            x, y = interval.start, polynomial.evaluate(interval.start)
            self._px.append(x)
            self._py.append(y)
            self._axes.update_datalim([(x, y)])
            self._grow(x)
        else:
            start = interval.start
            end = interval.end
            if end is None:
                end = max(start, self._x_max if self._x_max is not None else start)
                end += self._unbounded_extent
            if polynomial.degree == 0:
                xs = [start, end]
            else:
                step = (end - start) / (self._samples - 1)
                xs = [start + k * step for k in range(self._samples)]
            ys = [polynomial.evaluate(x) for x in xs]
            self._xs.extend(xs)
            self._ys.extend(ys)
            self._axes.update_datalim(list(zip(xs, ys)))
            self._grow(end)
        self.update()

    def update(self) -> None:
        """Update the plot with the segments consumed so far, redrawing it
        if ``refresh_interval`` has passed since the last redraw."""
        self._line.set_data(self._xs, self._ys)
        self._points.set_data(self._px, self._py)
        # Lazy: the view is fitted to the data the next time it is drawn.
        self._axes.autoscale()
        self._redrawer.request()

    def refresh(self) -> None:
        """Redraw the plot at once."""
        self._redrawer.request(force=True)

    def show(self, block: bool = True) -> None:
        """Show the figure in a window."""
        import matplotlib.pyplot as plt
        self.refresh()
        plt.show(block=block)

    def _grow(self, x: float) -> None:
        if self._x_max is None or x > self._x_max:
            self._x_max = x
