"""Unit tests for cytlmonitor.globally_monitor.GloballyMonitor."""

import random
import unittest

from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.false_monitor import FalseMonitor
from cytlmonitor.globally_monitor import GloballyMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
from cytlmonitor.true_monitor import TrueMonitor


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.received = []
        self.horizons = []

    def consume(self, i):
        self.received.append(i)

    def set_horizon(self, t):
        self.horizons.append(t)


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


def run(steps, i_arg):
    m = GloballyMonitor(Replay(steps), i_arg)
    c = RecordingConsumer()
    m.add(c)
    for k in range(len(steps)):
        m.consume(tick(k))
    return c


def merged(intervals):
    return list(BooleanSignal(intervals))


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(GloballyMonitor(Replay([]), closed(0, 1)), EventMonitor)

    def test_fields_are_stored(self):
        a, i = Replay([]), closed(1, 3)
        m = GloballyMonitor(a, i)
        self.assertIs(m.arg, a)
        self.assertIs(m.i_arg, i)

    def test_non_monitor_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            GloballyMonitor(lambda e: None, closed(0, 1))

    def test_non_interval_i_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            GloballyMonitor(Replay([]), (0, 1))


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_arg(self):
        a = Replay([])
        m = GloballyMonitor(a, closed(0, 1))
        e = tick(1)
        m.consume(e)
        self.assertEqual(a.events, [e])

    def test_true_where_the_whole_window_is_true(self):
        # arg true on [0, 6), known up to 10: within [1, 2], true for
        # t in [0, 4); false after, where the window reaches past 6. It is
        # known to be false up to 9, where the window still meets [6, 10).
        c = run([([Interval(0, 6)], 10)], closed(1, 2))
        self.assertEqual(merged(c.received), [Interval(0, 4)])
        self.assertEqual(c.horizons, [9.0])

    def test_a_short_gap_makes_it_false_around_it(self):
        # arg false on [3, 4) only: within [0, 1], [t, t + 1] avoids it for
        # t < 2 and for t >= 4.
        c = run([([Interval(0, 3), Interval(4, 10)], 10)], closed(0, 1))
        self.assertEqual(merged(c.received), [Interval(0, 2), Interval(4, 9)])

    def test_open_window_ends(self):
        # Within (0, 1): the window of t = 2 is (2, 3), missing the gap
        # [3, 4) by its open end; from t = 4 the window lies in [4, 10).
        c = run([([Interval(0, 3), Interval(4, 10)], 10)], Interval(0, 1, left_open=True))
        self.assertEqual(merged(c.received), [closed(0, 2), Interval(4, 9)])

    def test_point_window_is_a_shift(self):
        # Within [2, 2], i.e. exactly 2 time units ahead.
        c = run([([Interval(3, 5)], 10)], Interval.point(2))
        self.assertEqual(merged(c.received), [Interval(1, 3)])

    def test_nothing_true_is_published_before_the_window_is_known(self):
        c = run([([Interval(0, 3)], 3)], closed(0, 5))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [])

    def test_known_part_grows_with_the_horizon_of_arg(self):
        c = run([([Interval(0, 4)], 4), ([Interval(4, 8)], 8)], closed(0, 1))
        self.assertEqual(merged(c.received), [Interval(0, 7)])
        self.assertEqual(c.horizons, [3.0, 7.0])

    def test_published_intervals_are_ordered(self):
        c = run([([Interval(0, 3), Interval(4, 6)], 6), ([Interval(7, 12)], 12)], closed(0, 1))
        for a, b in zip(c.received, c.received[1:]):
            self.assertTrue(a.is_before(b))
        self.assertEqual(c.horizons, sorted(set(c.horizons)))

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)
        for _ in range(300):
            steps, x, horizon, last = [], 0.0, 0.0, None
            for _ in range(rng.randint(1, 6)):
                batch = []
                for _ in range(rng.randint(0, 2)):
                    start = x + rng.choice([0, 0, 0.5, 1])
                    end = start + rng.choice([0.5, 1, 2, 4])
                    interval = Interval(start, end, left_open=rng.random() < 0.3,
                                        right_open=rng.random() < 0.6)
                    if last is not None and not last.is_before(interval):
                        continue
                    batch.append(interval)
                    last, x = interval, end
                horizon = max(horizon, x) + rng.choice([0, 0, 0.5])
                x = horizon
                steps.append((batch, horizon))
            a = rng.choice([0, 0.5, 1])
            b = a + rng.choice([0, 0.5, 1, 2])
            if a == b:
                i_arg = Interval.point(a)
            else:
                i_arg = Interval(a, b, left_open=rng.random() < 0.3,
                                 right_open=rng.random() < 0.3)
            c = run(steps, i_arg)

            for p, q in zip(c.received, c.received[1:]):
                self.assertTrue(p.is_before(q))
            self.assertEqual(c.horizons, sorted(set(c.horizons)))
            known = c.horizons[-1] if c.horizons else 0.0
            arg = merged([i for batch, _ in steps for i in batch])

            points = {0.0}
            for i in arg:
                for v in (i.start, i.end):
                    points |= {v - a, v - b, v - (a + b) / 2}
            for k in range(41):
                points.add(known * k / 40)
            for t in points:
                if t < 0 or t >= known:
                    continue
                window = i_arg.shift(t)
                expected = any(i.intersection(window) == window for i in arg)
                self.assertEqual(any(i.contains(t) for i in c.received), expected,
                                 (t, steps, i_arg))


class TestWithMonitors(unittest.TestCase):

    def test_globally_true_is_true_up_to_the_window_end(self):
        m = GloballyMonitor(TrueMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3, 6):
            m.consume(tick(t))
        self.assertEqual(merged(c.received), [Interval(0, 5)])
        self.assertEqual(c.horizons, [2.0, 5.0])

    def test_globally_false_is_false_and_known_at_once(self):
        m = GloballyMonitor(FalseMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3, 6):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [1.0, 3.0, 6.0])


if __name__ == '__main__':
    unittest.main()
