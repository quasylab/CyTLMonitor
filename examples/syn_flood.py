"""
SYN flood
=========

A SYN flood opens TCP connections without ever completing the handshake:
the target receives many SYN packets that are never followed by an ACK.
The number of half-open connections over the last 10 seconds is

    half_open(t) = (SYNs in [t - 10, t]) - (ACKs in [t - 10, t])

and an alarm is raised wherever it is above 100.

Shows: SumWindowExpression and ShiftExpression (a count over the last
seconds), DifferenceExpression, ConstantExpression as a threshold, and
AtomicGreaterMonitor.

Run with ``python examples/syn_flood.py`` (add ``--plot`` to see the
signals).
"""

import random

from _traffic import (
    AlarmPrinter, arguments, count_last, feed, field, merge, normal_traffic, packet,
    report, show, stacked_axes, steady,
)
from cytlmonitor import (
    AtomicGreaterMonitor, ConstantExpression, DifferenceExpression,
    PlotBooleanSignalConsumer, PlotSignalConsumer,
)

WINDOW = 10.0
THRESHOLD = 100.0


def traffic(seed: int = 1):
    """60 s of normal traffic, with a SYN flood between 25 s and 35 s."""
    rng = random.Random(seed)
    flood = steady(25, 35, 200, lambda t, rng: packet(t, syn=True, dst_port=80), rng)
    return merge(normal_traffic(0, 60, rng), flood)


def half_open_connections():
    return DifferenceExpression(count_last(WINDOW, field('tcp_syn')),
                                count_last(WINDOW, field('tcp_ack')))


def main(plot: bool = False, quiet: bool = False):
    half_open = half_open_connections()
    flood = AtomicGreaterMonitor(half_open, ConstantExpression(THRESHOLD))
    printers = {'SYN flood': AlarmPrinter('SYN flood', quiet)}
    flood.add(printers['SYN flood'])

    if plot:
        top, bottom = stacked_axes('SYN flood', 2)
        half_open.add(PlotSignalConsumer(f'Half-open connections, last {WINDOW:g} s', axes=top))
        top.axhline(THRESHOLD, color='#898781', linewidth=1, linestyle=(0, (4, 3)))
        flood.add(PlotBooleanSignalConsumer(f'More than {THRESHOLD:g} half-open', axes=bottom))

    if not quiet:
        print(f'Half-open connections over the last {WINDOW:g} s above {THRESHOLD:g}:')
    feed([flood], traffic())
    alarms = report(printers)
    if plot:
        show()
    return alarms


if __name__ == '__main__':
    main(plot=arguments(__doc__.split('\n')[1]).plot)
