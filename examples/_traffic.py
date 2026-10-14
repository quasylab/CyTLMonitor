"""
Helpers shared by the examples: synthetic traffic, windowed counts, and a
consumer printing the alarms raised by a monitor.

The examples feed a monitor with :class:`~cytlmonitor.event.Event`
instances whose payload has the same fields as the packets read by
``cytl_capture.parse_packet`` (``size``, ``protocol``, ``tcp_syn``,
``tcp_ack``, ``dst_port``, ...), so the same monitors can be used on real
traffic.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

# Let the examples run from a checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cytlmonitor import (  # noqa: E402
    BooleanSignalConsumer, Event, Interval, Payload, ShiftExpression,
    StreamExpression, SumWindowExpression,
)


# --------------------------------------------------------------------------
# Synthetic traffic
# --------------------------------------------------------------------------

def packet(time: float, protocol: str = 'TCP', syn: bool = False, ack: bool = False,
           rst: bool = False, dst_port: int = 80, size: int = 60, **extra) -> Event:
    """A packet-like event with the fields of ``cytl_capture.parse_packet``."""
    fields = {
        'size': size, 'protocol': protocol, 'dst_port': dst_port,
        'tcp_syn': int(syn), 'tcp_ack': int(ack), 'tcp_rst': int(rst),
        'tcp_fin': 0, 'tcp_psh': 0, 'tcp_urg': 0,
    }
    fields.update(extra)
    return Event(time, Payload(fields))


def steady(start: float, end: float, rate: float, make: Callable[[float, random.Random], Event],
           rng: random.Random) -> List[Event]:
    """Events from ``make`` at random times in ``[start, end)``, ``rate``
    per second on average."""
    events, t = [], start
    while True:
        t += rng.expovariate(rate)
        if t >= end:
            return events
        events.append(make(t, rng))


def normal_traffic(start: float, end: float, rng: random.Random, rate: float = 20.0) -> List[Event]:
    """Web traffic: each connection is a SYN followed by its ACK."""
    def connection(t, rng):
        return packet(t, syn=True)

    events = []
    for syn in steady(start, end, rate / 2, connection, rng):
        events.append(syn)
        ack_time = syn.time + rng.uniform(0.01, 0.05)
        if ack_time < end:
            events.append(packet(ack_time, ack=True, size=rng.randint(60, 1500)))
    return events


def merge(*streams: Iterable[Event]) -> List[Event]:
    """All the events of ``streams``, ordered by time."""
    return sorted((e for stream in streams for e in stream), key=lambda e: e.time)


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------

def count_last(seconds: float, weight: Callable[[Event], float] = lambda e: 1.0) -> StreamExpression:
    """The sum of ``weight`` over the events of the last ``seconds``.

    :class:`SumWindowExpression` sums over the window ``[t, t + seconds]``
    ahead of ``t``; shifting it forward by ``seconds`` makes it look back,
    over ``[t - seconds, t]``. A new expression is built at every call: an
    expression must not be shared by two monitors, since each would pass
    every event to it.
    """
    return ShiftExpression(SumWindowExpression(weight, 0, seconds), seconds)


def field(name: str) -> Callable[[Event], float]:
    """The weight counting the events whose payload field ``name`` is set."""
    return lambda e: float(e.payload.get(name, 0))


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

class AlarmPrinter(BooleanSignalConsumer):
    """Collects the intervals published by a monitor, merging the adjacent
    ones, and prints each alarm once it is known to be over."""

    def __init__(self, name: str, quiet: bool = False):
        self.name = name
        self.quiet = quiet
        self.alarms: List[Interval] = []
        self._current: Optional[Interval] = None

    def consume(self, i: Interval) -> None:
        current = self._current
        if current is not None and (current.just_before(i) or current.intersect(i)):
            self._current = current.join(i)
        else:
            self._flush()
            self._current = i

    def set_horizon(self, t: float) -> None:
        current = self._current
        # The alarm is over once the horizon is past its end: the next
        # interval cannot start where it ends.
        if current is not None and current.end is not None and current.end < t:
            self._flush()

    def close(self) -> List[Interval]:
        """Report the alarm still open, if any, and return all of them."""
        self._flush()
        return self.alarms

    def _flush(self) -> None:
        if self._current is None:
            return
        i, self._current = self._current, None
        self.alarms.append(i)
        if not self.quiet:
            end = '...' if i.end is None else f'{i.end:7.2f} s'
            length = '' if i.end is None else f'  ({i.end - i.start:.2f} s)'
            print(f'  [{self.name}] alarm from {i.start:7.2f} s to {end}{length}')


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------

def arguments(description: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--plot', action='store_true',
                        help='plot the signals and the alarms with Matplotlib')
    return parser.parse_args()


def feed(monitors, events: Iterable[Event]) -> None:
    """Pass every event to each of ``monitors``, in time order."""
    for e in events:
        for m in monitors:
            m.consume(e)


def stacked_axes(title: str, rows: int):
    """A figure with ``rows`` plots, one above the other, sharing the time
    axis."""
    import matplotlib.pyplot as plt

    figure, axes = plt.subplots(rows, 1, sharex=True, figsize=(9, 2.2 * rows + 0.6),
                                squeeze=False)
    figure.suptitle(title, x=0.01, ha='left', fontsize=13)
    figure.set_layout_engine('constrained')
    return [row[0] for row in axes]


def show() -> None:
    """Show the plots; the time axis, shared by the stacked plots, is only
    labelled below the last one."""
    import matplotlib.pyplot as plt

    for figure in map(plt.figure, plt.get_fignums()):
        for ax in figure.axes[:-1]:
            ax.set_xlabel('')
    plt.show()


def report(printers: Dict[str, AlarmPrinter]) -> Dict[str, List[Interval]]:
    """Close every printer and return the alarms, by name."""
    return {name: p.close() for name, p in printers.items()}
