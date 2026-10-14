"""
SSH brute force: until and since
================================

An attacker tries passwords on an SSH server. Each login attempt is an
event with a ``login`` field (``fail`` or ``ok``); the other packets have
no ``login`` field. Counting over the last seconds:

- ``brute force``: more than 5 failed logins over the last 10 s;
- ``login``: a successful login over the last second;
- ``breach``: the brute force goes on until a successful login, within
  30 s (brute force U_(0,30] login);
- ``still failing after login``: there has been a successful login, and
  failed logins have kept coming (at least one over the last 10 s) ever
  since (failing S_(0,inf) login).

Until requires the brute force on ``[t, t')`` and since requires the
failures on ``(t', t]``, ``t'`` being the time of the login. Both windows
exclude 0: with 0 in the window, ``t' = t`` would be allowed, and the
login alone, even the legitimate one, would make them true.

The traffic has a first attack at 10 s that ends with a successful login
at 19 s, a second attack at 40 s that never gets in, and a legitimate
login at 70 s.

``breach`` looks 30 s ahead, so it is known 30 s later than the others;
``still failing after login`` only looks back, so it is known at once.

Shows: UntilMonitor, SinceMonitor, and events with custom fields.

Run with ``python examples/until_since.py`` (add ``--plot`` to see the
signals).
"""

import random

from _traffic import (
    AlarmPrinter, arguments, count_last, feed, merge, normal_traffic, packet, report,
    show, stacked_axes,
)
from cytlmonitor import (
    AtomicGreaterMonitor, ConstantExpression, Interval, PlotBooleanSignalConsumer,
    SinceMonitor, UntilMonitor,
)


def login(t, outcome):
    return packet(t, ack=True, dst_port=22, size=200, login=outcome)


def traffic(seed: int = 4):
    """110 s of normal traffic, with two password-guessing attacks and a
    legitimate login."""
    rng = random.Random(seed)
    attempts = [login(10 + 0.5 * k, 'fail') for k in range(18)]       # 10 s .. 18.5 s
    attempts.append(login(19.0, 'ok'))                                 # the attacker gets in
    attempts += [login(19.5 + 0.5 * k, 'fail') for k in range(8)]      # and keeps trying
    attempts += [login(40 + 0.5 * k, 'fail') for k in range(30)]       # 40 s .. 54.5 s
    attempts.append(login(70.0, 'ok'))                                 # a legitimate user
    return merge(normal_traffic(0, 110, rng), attempts)


def failures(seconds):
    return count_last(seconds, lambda e: float(e.payload.get('login') == 'fail'))


def successes(seconds):
    return count_last(seconds, lambda e: float(e.payload.get('login') == 'ok'))


def brute_force():
    return AtomicGreaterMonitor(failures(10), ConstantExpression(5))


def logged_in():
    return AtomicGreaterMonitor(successes(1), ConstantExpression(0))


def still_failing():
    return AtomicGreaterMonitor(failures(10), ConstantExpression(0))


def main(plot: bool = False, quiet: bool = False):
    attack, success = brute_force(), logged_in()
    breach = UntilMonitor(attack, success, Interval(0, 30, left_open=True, right_open=False))
    after_login = SinceMonitor(still_failing(), logged_in(), Interval(0, left_open=True))

    printers = {name: AlarmPrinter(name, quiet) for name in (
        'brute force', 'login', 'breach', 'still failing after login')}
    attack.add(printers['brute force'])
    success.add(printers['login'])
    breach.add(printers['breach'])
    after_login.add(printers['still failing after login'])

    if plot:
        axes = stacked_axes('SSH brute force: until and since', 4)
        for monitor, title, ax in (
                (attack, 'Brute force: more than 5 failures over the last 10 s', axes[0]),
                (success, 'Successful login over the last second', axes[1]),
                (breach, 'Breach: brute force until a login, within 30 s', axes[2]),
                (after_login, 'Still failing since a successful login', axes[3])):
            monitor.add(PlotBooleanSignalConsumer(title, axes=ax))

    if not quiet:
        print('Password guessing on SSH:')
    feed([breach, after_login], traffic())
    alarms = report(printers)
    if plot:
        show()
    return alarms


if __name__ == '__main__':
    main(plot=arguments(__doc__.split('\n')[1]).plot)
