"""
cytlmonitor.plot_style
========================
Colors and axes styling shared by the consumers plotting signals with
Matplotlib (see :mod:`cytlmonitor.plot_signal_consumer` and
:mod:`cytlmonitor.plot_boolean_signal_consumer`).
"""

from __future__ import annotations

import time
from typing import Dict, Optional

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
