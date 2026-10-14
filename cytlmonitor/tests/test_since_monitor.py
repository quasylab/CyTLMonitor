"""Unit tests for cytlmonitor.since_monitor.SinceMonitor."""

import random
import unittest

from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.false_monitor import FalseMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
from cytlmonitor.since_monitor import SinceMonitor
from cytlmonitor.true_monitor import TrueMonitor


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
    m = SinceMonitor(Replay(steps1), Replay(steps2), i_arg)
    c = RecordingConsumer()
    m.add(c)
    for k in range(max(len(steps1), len(steps2))):
        m.consume(tick(k))
    return c


def merged(intervals):
    return list(BooleanSignal(intervals))


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(SinceMonitor(Replay([]), Replay([]), closed(0, 1)), EventMonitor)

    def test_fields_are_stored(self):
        a, b, i = Replay([]), Replay([]), closed(1, 3)
        m = SinceMonitor(a, b, i)
        self.assertIs(m.arg1, a)
        self.assertIs(m.arg2, b)
        self.assertIs(m.i_arg, i)

    def test_non_monitor_args_raise_type_error(self):
        with self.assertRaises(TypeError):
            SinceMonitor(lambda e: None, Replay([]), closed(0, 1))
        with self.assertRaises(TypeError):
            SinceMonitor(Replay([]), None, closed(0, 1))

    def test_non_interval_i_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            SinceMonitor(Replay([]), Replay([]), (0, 1))

    def test_unbounded_i_arg_is_allowed(self):
        SinceMonitor(Replay([]), Replay([]), Interval(1))


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_both_monitors_arg1_first(self):
        order = []

        class Tagged(Replay):
            def __init__(self, name):
                super().__init__([])
                self.name = name

            def consume(self, e):
                order.append(self.name)

        SinceMonitor(Tagged('arg1'), Tagged('arg2'), closed(0, 1)).consume(tick())
        self.assertEqual(order, ['arg1', 'arg2'])

    def test_same_monitor_receives_event_once(self):
        a = Replay([([Interval(2, 5)], 10)])
        m = SinceMonitor(a, a, closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(len(a.events), 1)
        # phi S phi within [0, 1] is phi itself.
        self.assertEqual(merged(c.received), [Interval(2, 5)])

    def test_arg1_holds_since_arg2_was_true(self):
        # arg2 on [1, 2), arg1 on [1, 8), within [2, 3]: t' in [t - 3, t - 2]
        # and in [1, 2], 2 being the closing end of arg2, so t in [3, 5].
        c = run([([Interval(1, 8)], 10)], [([Interval(1, 2)], 10)], closed(2, 3))
        self.assertEqual(merged(c.received), [closed(3, 5)])
        self.assertEqual(c.horizons, [10.0])

    def test_no_lag_behind_the_arguments(self):
        c = run([([Interval(0, 4)], 4)], [([Interval(0, 4)], 4)], closed(0, 1))
        self.assertEqual(merged(c.received), [Interval(0, 4)])
        self.assertEqual(c.horizons, [4.0])

    def test_arg1_must_hold_right_after_t_prime(self):
        # arg2 on [0, 2), arg1 on [3, 8), within (0, 5]: arg1 is false on
        # (t', 3) for every t' up to the closing end 2, so never.
        c = run([([Interval(3, 8)], 10)], [([Interval(0, 2)], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(c.received, [])

    def test_arg1_is_not_needed_at_t_prime(self):
        # arg2 on [0, 2], arg1 on (2, 8), within (0, 5]: arg1 starts right
        # after t' = 2, which is enough: t in (2, 7].
        c = run([([Interval(2, 8, left_open=True)], 10)], [([closed(0, 2)], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(merged(c.received), [Interval(2, 7, left_open=True, right_open=False)])

    def test_arg2_alone_when_the_window_contains_zero(self):
        # Within [0, 5], t' = t is allowed: arg2 alone makes it true on
        # [0, 2); after 2, t' = 2 (the closing end) needs t > 2.
        c = run([([Interval(2, 8)], 10)], [([Interval(0, 2)], 10)], closed(0, 5))
        self.assertEqual(merged(c.received),
                         [Interval(0, 2), Interval(2, 7, left_open=True, right_open=False)])

    def test_quiet_since_attack(self):
        # Complementary signals meeting at a point arg2 includes: arg2 on
        # [0, 3], arg1 on (3, 10). Within (0, 5], every t in (3, 8] has
        # t' = 3.
        c = run([([Interval(3, 10, left_open=True)], 10)], [([closed(0, 3)], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(merged(c.received), [Interval(3, 8, left_open=True, right_open=False)])

    def test_t_prime_at_the_open_end_of_arg2(self):
        # arg2 on [0, 3), arg1 on [3, 10): t' = 3, the closing end of
        # arg2, so t in (3, 8].
        c = run([([Interval(3, 10)], 10)], [([Interval(0, 3)], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(merged(c.received), [Interval(3, 8, left_open=True, right_open=False)])

    def test_open_end_of_arg2_survives_the_horizon(self):
        # arg2 on [0, 3) is published and passed by the horizon before
        # arg1 starts at 3: its closing end must not be forgotten.
        c = run([([], 3), ([Interval(3, 10)], 10)], [([Interval(0, 3)], 3), ([], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(merged(c.received), [Interval(3, 8, left_open=True, right_open=False)])

    def test_open_end_of_arg2_needs_t_prime_before_t(self):
        # With t' = t, arg2 must really hold at t: the closing end 3 of
        # [0, 3) does not make the signal true at 3.
        c = run([([], 10)], [([Interval(0, 3)], 10)], closed(0, 5))
        self.assertEqual(merged(c.received), [Interval(0, 3)])

    def test_since_of_itself_is_itself(self):
        c = run([([Interval(2, 5)], 10)], [([Interval(2, 5)], 10)], closed(0, 1))
        self.assertEqual(merged(c.received), [Interval(2, 5)])

    def test_a_gap_after_arg2_breaks_it(self):
        # arg2 on [0, 3), arg1 on (3, 10): arg1 is false at 3, which
        # (t', t] contains for t' < 3, and t' = 3 needs arg1 on (3, t].
        # So t' = 3 works: t in (3, 8].
        c = run([([Interval(3, 10, left_open=True)], 10)], [([Interval(0, 3)], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(merged(c.received), [Interval(3, 8, left_open=True, right_open=False)])
        # A real gap: arg1 from 4 on.
        c = run([([Interval(4, 10)], 10)], [([Interval(0, 3)], 10)],
                Interval(0, 5, left_open=True, right_open=False))
        self.assertEqual(c.received, [])

    def test_a_gap_in_arg1_breaks_the_chain(self):
        # arg1 false on [3, 4): arg2 at 1 is no longer enough after 3.
        c = run([([Interval(0, 3), Interval(4, 9)], 10)], [([Interval(1, 2)], 10)], closed(0, 6))
        self.assertEqual(merged(c.received), [Interval(1, 3)])

    def test_unbounded_window(self):
        # Within [1, inf): true from 1 after arg2, for as long as arg1 holds.
        c = run([([Interval(0, 7)], 10)], [([Interval(2, 3)], 10)], Interval(1))
        self.assertEqual(merged(c.received), [Interval(3, 7)])

    def test_long_stretch_of_arg1_published_in_pieces(self):
        # arg1 holds on [0, 9) but arrives in pieces, while arg2 holds only
        # on [0.5, 1): within [0, 20], everything from 0.5 on is true.
        c = run([([Interval(0, 1)], 1), ([Interval(1, 3)], 3), ([Interval(3, 9)], 9)],
                [([Interval(0.5, 1)], 1), ([], 3), ([], 9)], closed(0, 20))
        self.assertEqual(merged(c.received), [Interval(0.5, 9)])
        self.assertEqual(c.horizons, [1.0, 3.0, 9.0])

    def test_arg2_out_of_reach_is_forgotten(self):
        # Within [0, 1]: arg2 at [0, 1), closing end included, only reaches
        # up to t = 2.
        c = run([([Interval(0, 2)], 2), ([Interval(2, 9)], 9)],
                [([Interval(0, 1)], 2), ([], 9)], closed(0, 1))
        self.assertEqual(merged(c.received), [closed(0, 2)])
        self.assertEqual(c.horizons, [2.0, 9.0])

    def test_nothing_is_published_until_both_horizons_move(self):
        c = run([([Interval(0, 5)], 5)], [([Interval(1, 2)], None)], closed(0, 4))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [])

    def test_intervals_are_published_before_the_horizon(self):
        log = []
        m = SinceMonitor(Replay([([Interval(1, 8)], 10)]), Replay([([Interval(1, 2)], 10)]),
                         closed(2, 3))
        m.add(RecordingConsumer(log))
        m.consume(tick())
        self.assertEqual(log, [('interval', closed(3, 5)), ('horizon', 10.0)])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)

        def random_steps():
            steps, x, horizon, last = [], 0.0, 0.0, None
            for _ in range(rng.randint(1, 8)):
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

        produced = 0
        for _ in range(400):
            s1, s2 = random_steps(), random_steps()
            a = rng.choice([0, 0.5, 1])
            if rng.random() < 0.15:
                i_arg = Interval(a, None, left_open=rng.random() < 0.3)
                b = None
            else:
                b = a + rng.choice([0, 0.5, 1, 3])
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
            known = min(s1[-1][1], s2[-1][1])
            if known > 0:
                self.assertEqual(c.horizons[-1], known)

            phi = merged([i for batch, _ in s1 for i in batch])
            psi = merged([i for batch, _ in s2 for i in batch])
            points = {0.0}
            for i in phi + psi:
                for v in (i.start, i.end):
                    points |= {v, v + a}
                    if b is not None:
                        points |= {v + b, v + (a + b) / 2}
            for k in range(41):
                points.add(known * k / 40)
            for t in points:
                if t < 0 or t >= known:
                    continue
                if b is None:
                    back = Interval(-1e9, t - a, right_open=i_arg.left_open)
                else:
                    back = Interval(t - b, t - a, left_open=i_arg.right_open,
                                    right_open=i_arg.left_open)
                # arg2 at some t' with t - t' in i_arg, or t' < t at the
                # open end of an interval of arg2; arg1 on (t', t].
                expected = i_arg.contains(0) and any(j.contains(t) for j in psi)
                around = [i for i in phi if i.contains(t)]
                if around:
                    i = around[0]
                    reach = Interval(i.start, i.end, left_open=False, right_open=i.right_open)
                    reachable = back.intersection(reach)
                    if reachable is not None:
                        expected = expected or any(reachable.intersect(j) for j in psi) or any(
                            j.end is not None and j.right_open and j.end < t
                            and reachable.contains(j.end) for j in psi)
                self.assertEqual(any(i.contains(t) for i in c.received), expected,
                                 (t, s1, s2, i_arg))
        self.assertGreater(produced, 100)


class TestBuffers(unittest.TestCase):

    def test_buffers_stay_bounded_on_a_long_stream(self):
        class Blink(EventMonitor):
            """True on [t, t + 0.5) after every event at time t."""

            def consume(self, e):
                self.publish(Interval(e.time, e.time + 0.5))
                self.publish_horizon(e.time + 1)

        m = SinceMonitor(TrueMonitor(), Blink(), closed(0, 2))
        c = RecordingConsumer()
        m.add(c)
        for t in range(500):
            m.consume(tick(t))
        self.assertLessEqual(len(m._left.intervals), 2)
        self.assertLessEqual(len(m._right.intervals), 4)
        self.assertEqual(merged(c.received), [Interval(0, 499)])


class TestWithMonitors(unittest.TestCase):

    def test_true_since_true_is_true(self):
        m = SinceMonitor(TrueMonitor(), TrueMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(merged(c.received), [Interval(0, 5)])
        self.assertEqual(c.horizons, [2.0, 5.0])

    def test_since_false_is_false(self):
        m = SinceMonitor(TrueMonitor(), FalseMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [2.0, 5.0])

    def test_false_since_true_is_true_with_zero_in_the_window(self):
        m = SinceMonitor(FalseMonitor(), TrueMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(merged(c.received), [Interval(0, 5)])

    def test_false_since_is_false(self):
        m = SinceMonitor(FalseMonitor(), TrueMonitor(), Interval(0, 1, left_open=True,
                                                                 right_open=False))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [2.0, 5.0])


if __name__ == '__main__':
    unittest.main()
