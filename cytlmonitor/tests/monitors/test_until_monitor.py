"""Unit tests for cytlmonitor.monitors.temporal.UntilMonitor."""

import random
import unittest

from cytlmonitor.core.boolean_signal import BooleanSignal
from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.events.event import Event
from cytlmonitor.monitors.base import EventMonitor
from cytlmonitor.monitors.temporal import EventuallyMonitor
from cytlmonitor.monitors.constants import FalseMonitor
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.payload import Payload
from cytlmonitor.monitors.constants import TrueMonitor
from cytlmonitor.monitors.temporal import UntilMonitor


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self, log=None):
        self.received = []
        self.horizons = []
        self.log = log

    def consume(self, i):
        self.received.append(i)
        if self.log is not None:
            self.log.append(('interval', i))

    def set_horizon(self, t):
        self.horizons.append(t)
        if self.log is not None:
            self.log.append(('horizon', t))


class Replay(EventMonitor):
    """For each consumed event, publishes the next batch of intervals and
    then the next horizon (if it is not None)."""

    def __init__(self, steps):
        super().__init__()
        self.steps = list(steps)
        self.events = []

    def consume(self, e):
        self.events.append(e)
        if not self.steps:
            return
        intervals, horizon = self.steps.pop(0)
        for i in intervals:
            self.publish(i)
        if horizon is not None:
            self.publish_horizon(horizon)


def tick(t=0):
    return Event(t, Payload({}))


def closed(a, b):
    return Interval(a, b, right_open=False)


def run(steps1, steps2, i_arg):
    m = UntilMonitor(Replay(steps1), Replay(steps2), i_arg)
    c = RecordingConsumer()
    m.add(c)
    for k in range(max(len(steps1), len(steps2))):
        m.consume(tick(k))
    return c


def merged(intervals):
    return list(BooleanSignal(intervals))


def completed(intervals, horizon):
    """``intervals`` with what follows ``horizon`` taken as true."""
    return list(BooleanSignal(intervals).union(BooleanSignal([Interval(horizon)])))


def until(phi, psi, i_arg, t):
    """The definition: arg2 at some t' in t + i_arg, arg1 on [t, t')."""
    expected = i_arg.contains(0) and any(j.contains(t) for j in psi)
    around = [i for i in phi if i.contains(t)]
    if around:
        i = around[0]
        reach = Interval(i.start, i.end, left_open=i.left_open, right_open=False)
        reachable = i_arg.shift(t).intersection(reach)
        expected = expected or (reachable is not None and any(
            reachable.intersect(j) for j in psi))
    return expected


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(UntilMonitor(Replay([]), Replay([]), closed(0, 1)), EventMonitor)

    def test_fields_are_stored(self):
        a, b, i = Replay([]), Replay([]), closed(1, 3)
        m = UntilMonitor(a, b, i)
        self.assertIs(m.arg1, a)
        self.assertIs(m.arg2, b)
        self.assertIs(m.i_arg, i)

    def test_non_monitor_args_raise_type_error(self):
        with self.assertRaises(TypeError):
            UntilMonitor(lambda e: None, Replay([]), closed(0, 1))
        with self.assertRaises(TypeError):
            UntilMonitor(Replay([]), None, closed(0, 1))

    def test_non_interval_i_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            UntilMonitor(Replay([]), Replay([]), (0, 1))

    def test_unbounded_i_arg_raises_value_error(self):
        with self.assertRaises(ValueError):
            UntilMonitor(Replay([]), Replay([]), Interval(1))


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_both_monitors_arg1_first(self):
        order = []

        class Tagged(Replay):
            def __init__(self, name):
                super().__init__([])
                self.name = name

            def consume(self, e):
                order.append(self.name)

        UntilMonitor(Tagged('arg1'), Tagged('arg2'), closed(0, 1)).consume(tick())
        self.assertEqual(order, ['arg1', 'arg2'])

    def test_same_monitor_receives_event_once(self):
        a = Replay([([Interval(0, 5)], 10)])
        m = UntilMonitor(a, a, closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(len(a.events), 1)
        # phi U phi within [0, 1] is phi itself.
        self.assertEqual(merged(c.received), [Interval(0, 5)])

    def test_arg1_holds_until_arg2_becomes_true(self):
        # arg1 on [0, 5), arg2 on [4, 6), within [1, 2]: t' in
        # [t + 1, t + 2], in [4, 6) and at most 5 (arg1 holds on [t, t')),
        # so t in [2, 4].
        # Every window is known below 10 - 2 = 8; on [8, 10) arg1 is false,
        # which decides the signal too.
        c = run([([Interval(0, 5)], 10)], [([Interval(4, 6)], 10)], closed(1, 2))
        self.assertEqual(merged(c.received), [closed(2, 4)])
        self.assertEqual(c.horizons, [10.0])

    def test_arg1_is_not_needed_at_t_prime(self):
        # arg1 on [0, 4), arg2 on [4, 6), within (0, 2]: arg1 stops exactly
        # where arg2 starts, which is enough: t in [2, 4).
        c = run([([Interval(0, 4)], 10)], [([Interval(4, 6)], 10)],
                Interval(0, 2, left_open=True, right_open=False))
        self.assertEqual(merged(c.received), [Interval(2, 4)])

    def test_arg2_alone_when_the_window_contains_zero(self):
        # Within [0, 2], t' = t is allowed: arg2 alone makes it true.
        c = run([([Interval(0, 4)], 10)], [([Interval(4, 6)], 10)], closed(0, 2))
        self.assertEqual(merged(c.received), [Interval(2, 6)])

    def test_a_single_point_gap_breaks_it(self):
        # arg1 on [0, 4), arg2 on (4, 6): at 4 neither holds, and every t'
        # after 4 needs arg1 on (4, t').
        c = run([([Interval(0, 4)], 10)], [([Interval(4, 6, left_open=True)], 10)],
                Interval(0, 2, left_open=True, right_open=False))
        self.assertEqual(c.received, [])

    def test_attack_until_quiet(self):
        # Complementary signals: arg1 on [0, 3), arg2 on [3, 10). Within
        # (0, 5], every t in [0, 3) is followed by arg2 at 3; after 3, arg1
        # no longer holds at t.
        c = run([([Interval(0, 3)], 10)], [([Interval(3, 10)], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(merged(c.received), [Interval(0, 3)])

    def test_a_gap_in_arg1_breaks_the_chain(self):
        # arg1 false on [2, 3): from t < 2, arg2 at 4 is not reached.
        c = run([([Interval(0, 2), Interval(3, 8)], 10)], [([Interval(4, 5)], 10)], closed(0, 3))
        self.assertEqual(merged(c.received), [Interval(3, 5)])

    def test_arg2_at_time_t_with_window_from_zero(self):
        # Within [0, 1]: where arg2 and arg1 both hold, t' = t works.
        c = run([([Interval(0, 8)], 10)], [([Interval(2, 3)], 10)], closed(0, 1))
        self.assertEqual(merged(c.received), [Interval(1, 3)])

    def test_nothing_is_published_while_undecided(self):
        # arg1 is not known yet; arg2 may still turn out true at 0.
        c = run([([], None)], [([Interval(1, 2)], 10)], closed(1, 4))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [])

    def test_decided_part_is_published_before_every_window_is_known(self):
        # arg1 known up to 3 only, but true on [0, 3): t in [0, 2) reaches
        # arg2 on [1, 2). On [2, 6) arg2 is false on all of [t, t + 4].
        c = run([([Interval(0, 5)], 3)], [([Interval(1, 2)], 10)], closed(0, 4))
        self.assertEqual(c.received, [Interval(0, 2)])
        self.assertEqual(c.horizons, [6.0])

    def test_false_arg1_decides_before_arg2_is_known(self):
        # Without 0 in the window, arg1 false at t makes the signal false.
        c = run([([], 5)], [([], None)], closed(1, 3))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [5.0])

    def test_true_arg2_decides_before_the_window_is_known(self):
        # arg2 true at t makes the signal true when 0 is in the window.
        c = run([([], None)], [([Interval(0, 4)], 4)], closed(0, 10))
        self.assertEqual(c.received, [Interval(0, 4)])
        self.assertEqual(c.horizons, [4.0])

    def test_known_part_grows_with_both_horizons(self):
        c = run([([Interval(0, 4)], 4), ([Interval(4, 9)], 9)],
                [([], 4), ([Interval(6, 7)], 9)], closed(0, 1))
        self.assertEqual(c.horizons, [3.0, 8.0])
        self.assertEqual(merged(c.received), [Interval(5, 7)])

    def test_intervals_are_published_before_the_horizon(self):
        log = []
        m = UntilMonitor(Replay([([Interval(0, 5)], 10)]), Replay([([Interval(4, 6)], 10)]),
                         closed(1, 2))
        m.add(RecordingConsumer(log))
        m.consume(tick())
        self.assertEqual(log, [('interval', closed(2, 4)), ('horizon', 10.0)])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)

        def random_steps():
            steps, x, horizon, last = [], 0.0, 0.0, None
            for _ in range(rng.randint(1, 6)):
                batch = []
                for _ in range(rng.randint(0, 2)):
                    start = x + rng.choice([0, 0, 0.5, 1])
                    end = start + rng.choice([0, 0.5, 1, 2, 4])
                    if end == start:
                        if last is not None and not last.right_open and last.end == start:
                            continue
                        interval = Interval.point(start)
                    else:
                        interval = Interval(start, end, left_open=rng.random() < 0.3,
                                            right_open=rng.random() < 0.6)
                    if last is not None and not last.is_before(interval):
                        continue
                    batch.append(interval)
                    last, x = interval, end
                horizon = max(horizon, x) + rng.choice([0, 0, 0.5, 1])
                x = horizon
                steps.append((batch, horizon))
            return steps

        produced = ahead = 0
        for _ in range(300):
            s1, s2 = random_steps(), random_steps()
            a = rng.choice([0, 0.5, 1])
            b = a + rng.choice([0, 0.5, 1, 2])
            if a == b:
                i_arg = Interval.point(a)
            else:
                i_arg = Interval(a, b, left_open=rng.random() < 0.3,
                                 right_open=rng.random() < 0.3)
            c = run(s1, s2, i_arg)
            produced += len(c.received)

            for p, q in zip(c.received, c.received[1:]):
                self.assertTrue(p.is_before(q))
            self.assertEqual(c.horizons, sorted(set(c.horizons)))
            h1, h2 = s1[-1][1], s2[-1][1]
            known = min(h1, h2) - b
            decided = c.horizons[-1] if c.horizons else 0.0
            # Every window is known below min(h1, h2) - b.
            if known > 0:
                self.assertGreaterEqual(decided, known)
            ahead += decided > max(known, 0)

            phi = merged([i for batch, _ in s1 for i in batch])
            psi = merged([i for batch, _ in s2 for i in batch])
            # Below the horizon, the published value is the one of the
            # definition whatever the arguments are after their horizons.
            completions = [(phi, psi), (completed(phi, h1), completed(psi, h2))]
            points = {0.0}
            for i in phi + psi:
                for v in (i.start, i.end):
                    if v is not None:
                        points |= {v, v - a, v - b, v - (a + b) / 2}
            for k in range(41):
                points.add(decided * k / 40)
            for t in points:
                if t < 0 or t >= decided:
                    continue
                published = any(i.contains(t) for i in c.received)
                for f1, f2 in completions:
                    self.assertEqual(published, until(f1, f2, i_arg, t), (t, s1, s2, i_arg))
        self.assertGreater(produced, 100)
        # The horizon often gets past min(h1, h2) - b.
        self.assertGreater(ahead, 100)


class TestWithMonitors(unittest.TestCase):

    def test_true_until_is_eventually(self):
        steps = [([Interval(2, 3)], 4), ([Interval(6, 7)], 9)]
        until = UntilMonitor(TrueMonitor(), Replay(steps), closed(0, 2))
        eventually = EventuallyMonitor(Replay(steps), closed(0, 2))
        results = []
        for m in (until, eventually):
            c = RecordingConsumer()
            m.add(c)
            for t in (4, 9):
                m.consume(tick(t))
            results.append(BooleanSignal(c.received))
        horizon = 7.0
        window = BooleanSignal([Interval(0, horizon)])
        self.assertEqual(list(results[0].intersection(window)),
                         list(results[1].intersection(window)))

    def test_false_until_true_is_true_with_zero_in_the_window(self):
        m = UntilMonitor(FalseMonitor(), TrueMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        # arg2 alone decides: no need to wait for the window to be known.
        self.assertEqual(merged(c.received), [Interval(0, 5)])
        self.assertEqual(c.horizons, [2.0, 5.0])

    def test_false_until_is_false(self):
        m = UntilMonitor(FalseMonitor(), TrueMonitor(), Interval(0, 1, left_open=True,
                                                                 right_open=False))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        # arg1 false decides at once: no need to wait for the window.
        self.assertEqual(c.horizons, [2.0, 5.0])

    def test_until_false_is_false(self):
        m = UntilMonitor(TrueMonitor(), FalseMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [1.0, 4.0])


if __name__ == '__main__':
    unittest.main()
