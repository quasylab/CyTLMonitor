"""
Short spikes and sustained bursts
=================================

The packet rate is the number of packets over the last second. A rate
above 150 packets per second is high, but short spikes are common: an
alarm is wanted only when the rate stays high for 3 seconds in a row. The
traffic has a 1.5 s spike at 15 s and an 8 s burst at 30 s.

Three monitors are fed with the same packets:

- ``high``: the rate is above 150;
- ``sustained``: the rate stays above 150 for the next 3 s (G_[0,3] high),
  which ignores the spike;
- ``burst ahead``: the rate will be above 150 within the next 2 s
  (F_[0,2] high).

``sustained`` and ``burst ahead`` look ahead, so they are known 3 s and
2 s later than ``high``: their horizon lags behind the stream.

Shows: GloballyMonitor, EventuallyMonitor, and feeding several monitors
with the same events (each built from its own expressions).

Run with ``python examples/sustained_rate.py`` (add ``--plot`` to see the
signals).
"""

import random

from _traffic import (
    AlarmPrinter, arguments, count_last, feed, merge, normal_traffic, packet, report,
    show, stacked_axes, steady,
)
from cytlmonitor import (
    AtomicGreaterMonitor, ConstantExpression, EventuallyMonitor, GloballyMonitor,
    Interval, PlotBooleanSignalConsumer, PlotSignalConsumer,
)

RATE_LIMIT = 150.0


def traffic(seed: int = 2):
    """50 s of normal traffic, a 1.5 s spike at 15 s and an 8 s burst at
    30 s, both at 400 packets per second."""
    rng = random.Random(seed)

    def flood(t, rng):
        return packet(t, protocol='UDP', dst_port=53, size=rng.randint(60, 512))

    return merge(normal_traffic(0, 50, rng),
                 steady(15, 16.5, 400, flood, rng),
                 steady(30, 38, 400, flood, rng))


def high_rate(rate=None):
    """The rate over the last second is above the limit."""
    return AtomicGreaterMonitor(rate if rate is not None else count_last(1),
                                ConstantExpression(RATE_LIMIT))


def main(plot: bool = False, quiet: bool = False):
    rate = count_last(1)
    high = high_rate(rate)
    sustained = GloballyMonitor(high_rate(), Interval(0, 3, right_open=False))
    ahead = EventuallyMonitor(high_rate(), Interval(0, 2, right_open=False))

    printers = {name: AlarmPrinter(name, quiet)
                for name in ('high', 'sustained', 'burst ahead')}
    high.add(printers['high'])
    sustained.add(printers['sustained'])
    ahead.add(printers['burst ahead'])

    if plot:
        axes = stacked_axes('Short spikes and sustained bursts', 4)
        rate.add(PlotSignalConsumer('Packets over the last second', axes=axes[0]))
        axes[0].axhline(RATE_LIMIT, color='#898781', linewidth=1, linestyle=(0, (4, 3)))
        high.add(PlotBooleanSignalConsumer(f'Rate above {RATE_LIMIT:g}', axes=axes[1]))
        sustained.add(PlotBooleanSignalConsumer('High for the next 3 s', axes=axes[2]))
        ahead.add(PlotBooleanSignalConsumer('High within the next 2 s', axes=axes[3]))

    if not quiet:
        print(f'Rate above {RATE_LIMIT:g} packets per second:')
    feed([high, sustained, ahead], traffic())
    alarms = report(printers)
    if plot:
        show()
    return alarms


if __name__ == '__main__':
    main(plot=arguments(__doc__.split('\n')[1]).plot)
