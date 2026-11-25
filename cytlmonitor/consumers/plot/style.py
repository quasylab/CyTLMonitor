"""
cytlmonitor.consumers.plot.style
================================
Colors and axes styling shared by the consumers plotting signals with
Matplotlib (see :mod:`cytlmonitor.consumers.plot.signal` and
:mod:`cytlmonitor.consumers.plot.boolean_signal`).
"""

from __future__ import annotations

import time
from typing import Callable, Dict, Optional, Sequence, Tuple


# Chart colors, for the light and the dark surface.
THEMES: Dict[bool, Dict[str, str]] = {
    False: {'surface': '#fcfcfb', 'series': '#2a78d6', 'ink': '#0b0b0b',
            'muted': '#898781', 'grid': '#e1e0d9', 'axis': '#c3c2b7'},
    True: {'surface': '#1a1a19', 'series': '#3987e5', 'ink': '#f0efec',
           'muted': '#898781', 'grid': '#2c2c2a', 'axis': '#383835'},
}


def create_axes(title: str, axes, dark: bool):
    """Return the ``(figure, axes, theme)`` to plot on: ``axes`` (or new
    axes, if it is None) styled for the light or the dark surface."""
    import matplotlib.pyplot as plt

    theme = THEMES[bool(dark)]
    if axes is None:
        figure, axes = plt.subplots(figsize=(8, 3.5))
    else:
        figure = axes.figure
    figure.set_facecolor(theme['surface'])
    axes.set_facecolor(theme['surface'])
    axes.set_title(title, loc='left', color=theme['ink'], fontsize=12)
    axes.set_xlabel('time', color=theme['muted'])
    axes.grid(True, color=theme['grid'], linewidth=0.8)
    axes.set_axisbelow(True)
    axes.tick_params(colors=theme['muted'], length=0)
    for side in ('top', 'right'):
        axes.spines[side].set_visible(False)
    for side in ('left', 'bottom'):
        axes.spines[side].set_color(theme['axis'])
    return figure, axes, theme


class Redrawer:
    """Redraws a figure without blocking while Matplotlib is in interactive
    mode (see ``matplotlib.pyplot.ion``), at most once every ``interval``
    seconds of wall-clock time after the previous redraw, so that a busy
    stream does not spend its time drawing. Outside interactive mode no
    window is showing the figure: it is only redrawn when forced, and is
    drawn anyway by ``show`` and ``savefig``."""

    __slots__ = ('_figure', '_interval', '_last')

    def __init__(self, figure, interval: float):
        if interval < 0:
            raise ValueError(f"refresh_interval must be non negative, got {interval}.")
        self._figure = figure
        self._interval = float(interval)
        self._last: Optional[float] = None

    def request(self, force: bool = False) -> None:
        """Redraw the figure, if forced or if ``interval`` seconds have
        passed since the last redraw."""
        if not force:
            import matplotlib
            if not matplotlib.is_interactive():
                return
            if self._last is not None and time.monotonic() - self._last < self._interval:
                return
        canvas = self._figure.canvas
        canvas.draw_idle()
        canvas.flush_events()
        self._last = time.monotonic()


Data = Tuple[Sequence[float], Sequence[float]]

# The LazyLine class, built the first time a line is made, once Matplotlib
# is imported.
_lazy_line_class = None


def lazy_line(axes, fetch: Callable[[], Data], **style):
    """Add to ``axes``, and return, a line whose data is read from
    ``fetch()`` only when it is drawn or asked for, after
    ``line.invalidate()`` has been called.

    Setting the data of a Matplotlib line copies it, so setting it at every
    change of a growing signal would take time quadratic in its length:
    invalidating it is constant time.
    """
    global _lazy_line_class
    if _lazy_line_class is None:
        from matplotlib.lines import Line2D

        class LazyLine(Line2D):
            """A Line2D fetching its data when it is drawn or read."""

            def __init__(self, fetch, **style):
                self._fetch = fetch
                self._data_stale = False
                super().__init__([], [], **style)

            def invalidate(self) -> None:
                """Mark the data as changed: it is fetched again before
                the line is next drawn or read."""
                self._data_stale = True
                self.stale = True

            def _sync(self) -> None:
                if getattr(self, '_data_stale', False):
                    self._data_stale = False
                    Line2D.set_data(self, *self._fetch())

            def draw(self, renderer):
                self._sync()
                super().draw(renderer)

            def get_data(self, orig=True):
                self._sync()
                return super().get_data(orig)

            def get_xdata(self, orig=True):
                self._sync()
                return super().get_xdata(orig)

            def get_ydata(self, orig=True):
                self._sync()
                return super().get_ydata(orig)

            def get_xydata(self):
                self._sync()
                return super().get_xydata()

            def get_path(self):
                self._sync()
                return super().get_path()

        _lazy_line_class = LazyLine
    line = _lazy_line_class(fetch, **style)
    axes.add_line(line)
    return line
