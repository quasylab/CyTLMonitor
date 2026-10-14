"""
Quiet since the attack
======================

An upstream detector watches the traffic and reports attacks with events
of their own: one with ``alert = 'start'`` when an attack begins and one
with ``alert = 'stop'`` when it ends. An attack is therefore active on the
right-open interval ``[start, stop)``, and quiet, its negation, starts
exactly at ``stop``: the two signals take over from each other where an
attack ends. Using since, with quiet as the condition that must hold and
the attack as the event in the past:

- ``attack``: an alert is active;
- ``quiet``: no alert is active;
- ``cooling down``: the last attack ended less than 30 s ago, and it has
  been quiet since (quiet S_(0,30] attack);
- ``all clear``: it has been quiet for at least 30 s since the last attack
  (quiet S_[30,inf) attack).

The detector reports an attack on ``[20, 28)`` and a second one on
``[50, 53)``, before 30 quiet seconds have passed: ``all clear`` only comes
30 s after the second attack. Before the first attack it is quiet, but
there is no attack to be quiet since, so neither property holds.

The attack ``[20, 28)`` does not contain 28, where quiet starts: the
hand-over relies on SinceMonitor accepting the closing end of an interval
of its second argument, 28, as ``t'``, as long as ``t' < t``; quiet is then
required on ``(28, t]``. Since only looks back, both properties are known as
soon as the alerts are.

Shows: a custom EventMonitor, SinceMonitor with a bounded window and with
a window starting after 0, NotMonitor, and handing over between
complementary signals.

Run with ``python examples/quiet_since_attack.py`` (add ``--plot`` to see
the signals).
"""

import random

from _traffic import (
    AlarmPrinter, arguments, count_last, feed, merge, normal_traffic, packet, report,
    show, stacked_axes, steady,
)
from cytlmonitor import (
    Event, EventMonitor, Interval, NotMonitor, Payload, PlotBooleanSignalConsumer,
    PlotSignalConsumer, SinceMonitor,
)

COOL_DOWN = 30.0
ATTACKS = ((20.0, 28.0), (50.0, 53.0))


class AlertMonitor(EventMonitor):
    """True while an alert reported by the detector is active: from an event
    with ``alert = 'start'`` to the next one with ``alert = 'stop'``, that
    is on ``[start, stop)``.

    Like TrueMonitor, it publishes the active stretch piece by piece, up to
    each event, and the horizon at every event; the pieces of an attack
    join into its right-open interval.
    """

    def __init__(self):
        super().__init__()
        self._last = 0.0
        self._active = False

    def consume(self, e: Event) -> None:
        time = e.time
        if time > self._last:
            if self._active:
                self.publish(Interval(self._last, time))
            self._last = time
        alert = e.payload.get('alert')
        if alert == 'start':
            self._active = True
        elif alert == 'stop':
            self._active = False
        self.publish_horizon(time)


def alert(time: float, kind: str) -> Event:
    return Event(time, Payload({'alert': kind}))


def traffic(seed: int = 5):
    """120 s of normal traffic, with floods at 400 packets per second during
    the attacks, and the detector's alerts at their start and end."""
    rng = random.Random(seed)

    def flood(t, rng):
        return packet(t, protocol='UDP', dst_port=53, size=rng.randint(60, 512))

    streams = [normal_traffic(0, 120, rng)]
    for start, stop in ATTACKS:
        streams.append(steady(start, stop, 400, flood, rng))
        streams.append([alert(start, 'start'), alert(stop, 'stop')])
    return merge(*streams)


def packets_per_second():
    """Packets over the last second; the detector's alerts are not packets."""
    return count_last(1, lambda e: float('alert' not in e.payload))


def calm():
    """Quiet: no alert is active."""
    return NotMonitor(AlertMonitor())


def main(plot: bool = False, quiet: bool = False):
    under_attack = AlertMonitor()
    no_attack = calm()
    cooling_down = SinceMonitor(calm(), AlertMonitor(),
                                Interval(0, COOL_DOWN, left_open=True, right_open=False))
    all_clear = SinceMonitor(calm(), AlertMonitor(), Interval(COOL_DOWN))
    monitors = [under_attack, no_attack, cooling_down, all_clear]

    printers = {name: AlarmPrinter(name, quiet)
                for name in ('attack', 'quiet', 'cooling down', 'all clear')}
    under_attack.add(printers['attack'])
    no_attack.add(printers['quiet'])
    cooling_down.add(printers['cooling down'])
    all_clear.add(printers['all clear'])

    if plot:
        axes = stacked_axes('Quiet since the attack', 4)
        rate = packets_per_second()
        rate.add(PlotSignalConsumer('Packets over the last second', axes=axes[0]))
        monitors.append(rate)
        under_attack.add(PlotBooleanSignalConsumer('Attack: an alert is active', axes=axes[1]))
        cooling_down.add(PlotBooleanSignalConsumer(
            f'Cooling down: quiet since an attack less than {COOL_DOWN:g} s ago', axes=axes[2]))
        all_clear.add(PlotBooleanSignalConsumer(
            f'All clear: quiet for at least {COOL_DOWN:g} s since the last attack', axes=axes[3]))

    if not quiet:
        print('Attacks reported by the detector and the quiet after them:')
    feed(monitors, traffic())
    alarms = report(printers)
    if plot:
        show()
    return alarms


if __name__ == '__main__':
    main(plot=arguments(__doc__.split('\n')[1]).plot)
