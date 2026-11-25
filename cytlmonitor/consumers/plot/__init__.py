"""Consumers drawing signals live with matplotlib, and :func:`plot`, which
attaches them to the nodes of a built monitor or expression."""

from cytlmonitor.consumers.plot.boolean_signal import PlotBooleanSignalConsumer
from cytlmonitor.consumers.plot.signal import PlotSignalConsumer
from cytlmonitor.consumers.plot.tree import plot

__all__ = ['PlotSignalConsumer', 'PlotBooleanSignalConsumer', 'plot']
