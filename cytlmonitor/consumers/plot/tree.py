"""
cytlmonitor.consumers.plot.tree
===============================
Plotting the nodes of a monitor, or of an expression, once it is built.

:func:`plot` attaches a plotting consumer to some nodes of the tree of a
built monitor or expression (see :mod:`cytlmonitor.core.node`), each on its
own axes in a single figure, one above the other and sharing the time axis:
a :class:`~cytlmonitor.consumers.plot.boolean_signal.PlotBooleanSignalConsumer`
for a monitor, a :class:`~cytlmonitor.consumers.plot.signal.PlotSignalConsumer`
for an expression. Each plot is titled with the formula of its node, unless
another title is given.

The nodes are, by default, all the nodes of the tree, in pre-order, or those
down to ``depth`` levels below the root; ``nodes`` selects them explicitly,
as nodes or as paths from the root (see
:meth:`~cytlmonitor.core.node.FormulaNode.node`).

The plots go, by default, in a new figure; ``axes`` places them on given
axes instead, for instance a column of a larger figure, so that two
monitors can be compared side by side.

The consumers only receive what is published after they are attached, so
:func:`plot` is called before the events are fed to the root.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Union

from cytlmonitor.consumers.plot.boolean_signal import PlotBooleanSignalConsumer
from cytlmonitor.consumers.plot.signal import PlotSignalConsumer
from cytlmonitor.core.node import FormulaNode

Selection = Union[FormulaNode, Sequence[int]]
Plotter = Union[PlotSignalConsumer, PlotBooleanSignalConsumer]


def plot(root: FormulaNode, depth: Optional[int] = None,
         nodes: Optional[Iterable[Selection]] = None,
         titles: Optional[Dict[FormulaNode, str]] = None, title: Optional[str] = None,
         axes: Optional[Sequence] = None, dark: bool = False, unbounded_extent: float = 1.0, samples: int = 50,
         refresh_interval: float = 0.05) -> List[Plotter]:
    """Plot some nodes of the tree of ``root``, each on its own axes of a new
    figure, and return the plotting consumers attached to them, in order.

    - ``depth``: plot the nodes down to ``depth`` levels below ``root``
      (0 plots ``root`` alone; None, the default, the whole tree).
    - ``nodes``: plot these nodes instead, each given as a node or as the
      path of operand indexes leading to it from ``root``; ``()`` is
      ``root``.
    - ``titles``: the title of some nodes; the others are titled with their
      formula.
    - ``title``: the title of the new figure.
    - ``axes``: the Matplotlib axes to plot on, one per node, instead of a
      new figure (``title`` is then not allowed).

    The other arguments are passed to the plotting consumers.
    """
    if not isinstance(root, FormulaNode):
        raise TypeError(f"Expected an expression or a monitor, got {type(root).__name__}")
    if nodes is None:
        selected = list(root.nodes(depth))
    elif depth is not None:
        raise ValueError("Give either depth or nodes, not both.")
    else:
        selected = [n if isinstance(n, FormulaNode) else root.node(*n) for n in nodes]
    if not selected:
        raise ValueError("No node to plot.")
    # Imported here so that consumers.plot does not import the monitors and
    # the expressions when it is loaded.
    from cytlmonitor.expressions.base import StreamExpression
    from cytlmonitor.monitors.base import EventMonitor
    for node in selected:
        if not isinstance(node, (StreamExpression, EventMonitor)):
            raise TypeError(f"Expected an expression or a monitor, got {type(node).__name__}")

    if axes is None:
        import matplotlib.pyplot as plt

        rows = len(selected)
        figure, grid = plt.subplots(rows, 1, sharex=True, figsize=(9, 2.2 * rows + 0.6),
                                    squeeze=False)
        if title is not None:
            figure.suptitle(title, x=0.01, ha='left', fontsize=13)
        figure.set_layout_engine('constrained')
        axes = [row[0] for row in grid]
    else:
        axes = list(axes)
        if title is not None:
            raise ValueError("title is the title of a new figure: not allowed with axes.")
        if len(axes) != len(selected):
            raise ValueError(f"Expected {len(selected)} axes, one per node, got {len(axes)}.")

    plotters: List[Plotter] = []
    for node, ax in zip(selected, axes):
        label = titles.get(node, str(node)) if titles else str(node)
        if isinstance(node, EventMonitor):
            plotter = PlotBooleanSignalConsumer(label, axes=ax, dark=dark,
                                                unbounded_extent=unbounded_extent,
                                                refresh_interval=refresh_interval)
        else:
            plotter = PlotSignalConsumer(label, axes=ax, dark=dark, samples=samples,
                                         unbounded_extent=unbounded_extent,
                                         refresh_interval=refresh_interval)
        node.add(plotter)
        plotters.append(plotter)
    # The time axis is shared: label it below the last plot only.
    for plotter in plotters[:-1]:
        plotter.axes.set_xlabel('')
    return plotters
