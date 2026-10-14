"""
Port scan, ICMP flood and a combined rule
=========================================

A SYN port scan sends SYN packets to many ports and never completes the
handshakes. Counting over the last 2 seconds:

- ``many SYNs``: more than 100 SYNs;
- ``few ACKs``: fewer than one ACK every four SYNs (4 * ACKs < SYNs);
- ``port scan``: many SYNs and few ACKs;
- ``ICMP flood``: more than 100 ICMP packets;
- ``suspicious``: a port scan or an ICMP flood.

The traffic has a port scan at 20 s, an ICMP flood at 40 s and, at 50 s, a
flash crowd: many SYNs, but each one answered by an ACK, which must not
raise a port scan alarm.

The same port scan rule can be written as the violation of "many SYNs
imply that the ACKs are not few": ``not (many SYNs -> not few ACKs)``.
Both forms are monitored, and give the same alarms.

Shows: AndMonitor, OrMonitor, NotMonitor, ImplyMonitor, AtomicLessMonitor,
ProductExpression, and attaching consumers to monitors nested inside
another.

Run with ``python examples/port_scan.py`` (add ``--plot`` to see the
signals).
"""

import random

from _traffic import (
    AlarmPrinter, arguments, count_last, feed, field, merge, normal_traffic, packet,
    report, show, stacked_axes, steady,
)
from cytlmonitor import (
    AndMonitor, AtomicGreaterMonitor, AtomicLessMonitor, ConstantExpression,
    ImplyMonitor, NotMonitor, OrMonitor, PlotBooleanSignalConsumer, ProductExpression,
)

WINDOW = 2.0


def traffic(seed: int = 3):
    """60 s of normal traffic, a port scan at 20 s, an ICMP flood at 40 s
    and a flash crowd of legitimate connections at 50 s."""
    rng = random.Random(seed)
    scan = steady(20, 24, 150, lambda t, rng: packet(t, syn=True, dst_port=rng.randint(1, 1024)), rng)
    icmp = steady(40, 43, 300, lambda t, rng: packet(t, protocol='ICMP', size=1000), rng)
    crowd = normal_traffic(50, 53, rng, rate=300)
    return merge(normal_traffic(0, 60, rng), scan, icmp, crowd)


def syns():
    return count_last(WINDOW, field('tcp_syn'))


def acks():
    return count_last(WINDOW, field('tcp_ack'))


def many_syns():
    return AtomicGreaterMonitor(syns(), ConstantExpression(100))


def few_acks():
    return AtomicLessMonitor(ProductExpression(ConstantExpression(4), acks()), syns())


def icmp_flood():
    return AtomicGreaterMonitor(count_last(WINDOW, lambda e: float(e.payload.get('protocol') == 'ICMP')),
                                ConstantExpression(100))


def main(plot: bool = False, quiet: bool = False):
    syn_burst, unanswered = many_syns(), few_acks()
    scan = AndMonitor(syn_burst, unanswered)
    icmp = icmp_flood()
    suspicious = OrMonitor(scan, icmp)
    handshakes_answered = NotMonitor(ImplyMonitor(many_syns(), NotMonitor(few_acks())))

    # Consumers can be attached to monitors nested inside ``suspicious``:
    # they receive events through it, once.
    printers = {name: AlarmPrinter(name, quiet) for name in (
        'many SYNs', 'few ACKs', 'port scan', 'ICMP flood', 'suspicious',
        'not (many SYNs -> not few ACKs)')}
    syn_burst.add(printers['many SYNs'])
    unanswered.add(printers['few ACKs'])
    scan.add(printers['port scan'])
    icmp.add(printers['ICMP flood'])
    suspicious.add(printers['suspicious'])
    handshakes_answered.add(printers['not (many SYNs -> not few ACKs)'])

    if plot:
        axes = stacked_axes('Port scan, ICMP flood and a combined rule', 5)
        for monitor, title, ax in ((syn_burst, 'More than 100 SYNs', axes[0]),
                                   (unanswered, 'Fewer than one ACK every four SYNs', axes[1]),
                                   (scan, 'Port scan: many SYNs and few ACKs', axes[2]),
                                   (icmp, 'ICMP flood', axes[3]),
                                   (suspicious, 'Suspicious: port scan or ICMP flood', axes[4])):
            monitor.add(PlotBooleanSignalConsumer(title, axes=ax))

    if not quiet:
        print(f'Counting over the last {WINDOW:g} s:')
    feed([suspicious, handshakes_answered], traffic())
    alarms = report(printers)
    if plot:
        show()
    return alarms


if __name__ == '__main__':
    main(plot=arguments(__doc__.split('\n')[1]).plot)
