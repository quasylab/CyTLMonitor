"""
Scalability
===========

Measures how the monitors of the other examples cope with longer and longer
streams. Each monitor is fed with streams of increasing length, and the
time spent in ``consume`` is measured; generating the events is not
counted. A monitor processes each event in constant time on average when
the time grows linearly with the number of events: the time per event then
stays flat, and the fitted exponent ``k`` of ``time ~ n^k`` is close to 1.
With ``--memory``, the peak memory used while monitoring is also measured:
it stays bounded when the monitors only keep what they still need.

The stream repeats a 60 s cycle with all the activity the examples look
for: normal web traffic, a SYN flood, a port scan, an ICMP flood, an SSH
brute force ending with a successful login, and the alerts of a detector
around the flood. A cycle has about 3,100 events; streams are cut at the
requested number of events. Events are generated one cycle at a time, so
the stream is never held in memory as a whole.

Run with ``python examples/scalability.py``; ``--sizes 1000 10000 100000``
picks the stream lengths, ``--memory`` measures the memory as well (slower),
and ``--plot`` plots the results.
"""

import argparse
import math
import random
import time
import tracemalloc
from typing import Callable, Dict, Iterator, List

import port_scan
import quiet_since_attack
import sustained_rate
import syn_flood
import until_since
from _traffic import merge, normal_traffic, packet, steady
from cytlmonitor import (
    AtomicGreaterMonitor, BooleanSignalConsumer, ConstantExpression, Event, GloballyMonitor,
    Interval, OrMonitor, SinceMonitor, UntilMonitor,
)

CYCLE = 60.0
DEFAULT_SIZES = (1_000, 3_000, 10_000, 30_000, 100_000)


# --------------------------------------------------------------------------
# The stream
# --------------------------------------------------------------------------

def cycle(offset: float, rng: random.Random) -> List[Event]:
    """One 60 s cycle of traffic, starting at ``offset``."""
    def at(t):
        return offset + t

    def syn(t, rng):
        return packet(t, syn=True)

    def scan(t, rng):
        return packet(t, syn=True, dst_port=rng.randint(1, 1024))

    def icmp(t, rng):
        return packet(t, protocol='ICMP', size=1000)

    logins = [until_since.login(at(30 + 0.5 * k), 'fail') for k in range(12)]
    logins.append(until_since.login(at(36.2), 'ok'))
    alerts = [quiet_since_attack.alert(at(10), 'start'), quiet_since_attack.alert(at(15), 'stop')]
    return merge(normal_traffic(at(0), at(CYCLE), rng),
                 steady(at(10), at(15), 200, syn, rng),
                 steady(at(20), at(22), 150, scan, rng),
                 steady(at(40), at(42), 300, icmp, rng),
                 logins, alerts)


def stream(n: int, seed: int = 7) -> Iterator[List[Event]]:
    """``n`` events, one cycle at a time."""
    rng = random.Random(seed)
    k = 0
    while n > 0:
        events = cycle(k * CYCLE, rng)[:n]
        n -= len(events)
        k += 1
        yield events


# --------------------------------------------------------------------------
# The monitors, built as in the other examples
# --------------------------------------------------------------------------

def syn_flood_monitor():
    return AtomicGreaterMonitor(syn_flood.half_open_connections(),
                                ConstantExpression(syn_flood.THRESHOLD))


def sustained_rate_monitor():
    return GloballyMonitor(sustained_rate.high_rate(), Interval(0, 3, right_open=False))


def port_scan_monitor():
    from cytlmonitor import AndMonitor
    return OrMonitor(AndMonitor(port_scan.many_syns(), port_scan.few_acks()),
                     port_scan.icmp_flood())


def breach_monitor():
    return UntilMonitor(until_since.brute_force(), until_since.logged_in(),
                        Interval(0, 30, left_open=True, right_open=False))


def all_clear_monitor():
    return SinceMonitor(quiet_since_attack.calm(), quiet_since_attack.AlertMonitor(),
                        Interval(quiet_since_attack.COOL_DOWN))


MONITORS: Dict[str, Callable] = {
    'SYN flood (window sums)': syn_flood_monitor,
    'sustained rate (globally)': sustained_rate_monitor,
    'port scan (and / or)': port_scan_monitor,
    'breach (until)': breach_monitor,
    'all clear (since)': all_clear_monitor,
}


class Counter(BooleanSignalConsumer):
    """Counts what a monitor publishes, so that its output is consumed."""

    def __init__(self):
        self.intervals = 0
        self.horizon = 0.0

    def consume(self, i):
        self.intervals += 1

    def set_horizon(self, t):
        self.horizon = t


# --------------------------------------------------------------------------
# Measuring
# --------------------------------------------------------------------------

def measure(build: Callable, n: int, memory: bool = False) -> Dict[str, float]:
    """Feed a new monitor with ``n`` events and return the time spent in
    ``consume``. If ``memory``, a second monitor is fed with the same events
    to measure the peak memory used while monitoring: tracing allocations
    slows Python down, so it is kept out of the timed run."""
    monitor = build()
    counter = Counter()
    monitor.add(counter)
    elapsed = 0.0
    for events in stream(n):
        start = time.perf_counter()
        for e in events:
            monitor.consume(e)
        elapsed += time.perf_counter() - start
    result = {'events': n, 'seconds': elapsed, 'peak_bytes': 0,
              'intervals': counter.intervals, 'horizon': counter.horizon}
    if memory:
        result['peak_bytes'] = peak_memory(build, n)
    return result


def peak_memory(build: Callable, n: int) -> int:
    """The peak memory, in bytes, allocated while a new monitor processes
    ``n`` events, beyond what is held before each cycle is fed to it."""
    monitor = build()
    monitor.add(Counter())
    peak = 0
    tracemalloc.start()
    try:
        for events in stream(n):
            tracemalloc.reset_peak()
            baseline = tracemalloc.get_traced_memory()[0]
            for e in events:
                monitor.consume(e)
            peak = max(peak, tracemalloc.get_traced_memory()[1] - baseline)
    finally:
        tracemalloc.stop()
    return peak


def growth_exponent(results: List[Dict[str, float]]) -> float:
    """The exponent ``k`` of ``time ~ n^k``, fitted on the larger half of
    the sizes, where fixed costs no longer matter."""
    points = [(math.log(r['events']), math.log(r['seconds'])) for r in results
              if r['seconds'] > 0]
    points = points[len(points) // 2:] if len(points) >= 4 else points
    if len(points) < 2:
        return float('nan')
    mx = sum(x for x, _ in points) / len(points)
    my = sum(y for _, y in points) / len(points)
    sxx = sum((x - mx) ** 2 for x, _ in points)
    sxy = sum((x - mx) * (y - my) for x, y in points)
    return sxy / sxx


def run(sizes=DEFAULT_SIZES, memory: bool = False, quiet: bool = False,
        monitors: Dict[str, Callable] = None) -> Dict[str, List[Dict[str, float]]]:
    monitors = MONITORS if monitors is None else monitors
    results = {}
    for name, build in monitors.items():
        if not quiet:
            print(f'\n{name}')
            header = f'  {"events":>10}  {"time (s)":>9}  {"µs/event":>9}  {"events/s":>10}'
            if memory:
                header += f'  {"peak memory":>12}'
            print(header)
        rows = []
        for n in sizes:
            r = measure(build, n, memory)
            rows.append(r)
            if not quiet:
                line = (f'  {n:>10,}  {r["seconds"]:>9.3f}  {1e6 * r["seconds"] / n:>9.1f}'
                        f'  {n / r["seconds"]:>10,.0f}')
                if memory:
                    line += f'  {r["peak_bytes"] / 1024:>9,.0f} KiB'
                print(line)
        results[name] = rows
        if not quiet:
            print(f'  time grows as n^{growth_exponent(rows):.2f}')
    return results


def plot(results: Dict[str, List[Dict[str, float]]], memory: bool) -> None:
    """Time per event against the number of events, one line per monitor:
    a flat line is linear scaling."""
    import matplotlib.pyplot as plt
    from cytlmonitor.plot_style import THEMES

    theme = THEMES[False]
    # Categorical slots 1-5 of the reference palette, in fixed order. Three
    # of them are below 3:1 contrast on the surface: the legend names every
    # line, and the same results are printed as a table.
    colors = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4']
    rows = 2 if memory else 1
    figure, axes = plt.subplots(rows, 1, figsize=(9, 4 * rows), squeeze=False,
                                layout='constrained')
    figure.set_facecolor(theme['surface'])
    panels = [('Time per event (µs)', lambda r: 1e6 * r['seconds'] / r['events'])]
    if memory:
        panels.append(('Peak memory while monitoring (KiB)', lambda r: r['peak_bytes'] / 1024))
    for k, ((title, value), ax) in enumerate(zip(panels, (row[0] for row in axes))):
        ax.set_facecolor(theme['surface'])
        ax.set_title(title, loc='left', color=theme['ink'], fontsize=12)
        ax.set_xscale('log')
        ax.set_xlabel('events in the stream', color=theme['muted'])
        ax.grid(True, color=theme['grid'], linewidth=0.8)
        ax.set_axisbelow(True)
        ax.tick_params(colors=theme['muted'], length=0)
        for side in ('top', 'right'):
            ax.spines[side].set_visible(False)
        for side in ('left', 'bottom'):
            ax.spines[side].set_color(theme['axis'])
        for (name, rs), color in zip(results.items(), colors):
            xs = [r['events'] for r in rs]
            ys = [value(r) for r in rs]
            ax.plot(xs, ys, color=color, linewidth=2, marker='o', markersize=8,
                    markeredgecolor=theme['surface'], markeredgewidth=2, label=name)
        ax.set_ylim(bottom=0)
        if k == 0:
            ax.legend(frameon=False, labelcolor=theme['ink'], loc='upper left',
                      bbox_to_anchor=(1.0, 1.0))
    plt.show()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Scalability of the monitors')
    parser.add_argument('--sizes', type=int, nargs='+', default=list(DEFAULT_SIZES),
                        help='numbers of events in the streams (default: %(default)s)')
    parser.add_argument('--memory', action='store_true',
                        help='also measure the peak memory (slower)')
    parser.add_argument('--plot', action='store_true', help='plot the results')
    args = parser.parse_args(argv)
    results = run(args.sizes, args.memory)
    if args.plot:
        plot(results, args.memory)
    return results


if __name__ == '__main__':
    main()
