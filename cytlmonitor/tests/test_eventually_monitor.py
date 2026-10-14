"""Unit tests for cytlmonitor.eventually_monitor.EventuallyMonitor."""

import random
import unittest

from cytlmonitor.eventually_monitor import EventuallyMonitor
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.false_monitor import FalseMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
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


def run(intervals, i_arg):
    m = EventuallyMonitor(Replay([(intervals, None)]), i_arg)
    c = RecordingConsumer()
    m.add(c)
    m.consume(tick())
    return c


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(EventuallyMonitor(Replay([]), closed(0, 1)), EventMonitor)

    def test_fields_are_stored(self):
        a, i = Replay([]), closed(1, 3)
        m = EventuallyMonitor(a, i)
        self.assertIs(m.arg, a)
        self.assertIs(m.i_arg, i)
        self.assertEqual(m.last, 0.0)

    def test_non_monitor_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            EventuallyMonitor(lambda e: None, closed(0, 1))

    def test_non_interval_i_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            EventuallyMonitor(Replay([]), (0, 1))


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_arg(self):
        a = Replay([])
        m = EventuallyMonitor(a, closed(0, 1))
        e = tick(1)
        m.consume(e)
        self.assertEqual(a.events, [e])

    def test_interval_is_moved_back_by_the_window(self):
        # [5, 6) is reached within [1, 3] from t in [2, 5).
        c = run([Interval(5, 6)], closed(1, 3))
        self.assertEqual(c.received, [Interval(2, 5)])
        self.assertEqual(c.horizons, [5.0])

    def test_last_is_moved_to_the_end(self):
        m = EventuallyMonitor(Replay([([Interval(5, 6)], None)]), closed(1, 3))
        m.consume(tick())
        self.assertEqual(m.last, 5.0)

    def test_overlapping_results_start_from_last(self):
        # [7, 8) gives [4, 7), overlapping [2, 5): only [5, 7) is new.
        c = run([Interval(5, 6), Interval(7, 8)], closed(1, 3))
        self.assertEqual(c.received, [Interval(2, 5), Interval(5, 7)])
        self.assertEqual(c.horizons, [5.0, 7.0])

    def test_continuation_starts_open_after_a_closed_end(self):
        # [5, 6] gives [2, 5]; [6.5, 8) gives [3.5, 7): new part (5, 7).
        c = run([closed(5, 6), Interval(6.5, 8)], closed(1, 3))
        self.assertEqual(c.received, [closed(2, 5), Interval(5, 7, left_open=True)])

    def test_separate_results_keep_their_own_start(self):
        c = run([Interval(5, 6), Interval(20, 21)], closed(1, 3))
        self.assertEqual(c.received, [Interval(2, 5), Interval(17, 20)])
        self.assertEqual(c.horizons, [5.0, 20.0])

    def test_published_intervals_are_ordered(self):
        c = run([Interval(5, 6), Interval(7, 8), closed(9, 9.5), Interval(20, 21)], closed(1, 3))
        for a, b in zip(c.received, c.received[1:]):
            self.assertTrue(a.is_before(b))

    def test_open_window_bounds(self):
        # Within (1, 3): [5, 6) is reached from t in (2, 5).
        c = run([Interval(5, 6)], Interval(1, 3, left_open=True))
        self.assertEqual(c.received, [Interval(2, 5, left_open=True)])

    def test_result_clipped_at_zero(self):
        # [1, 4) within [0, 2] is reached from t in [-1, 4): clipped to [0, 4).
        c = run([Interval(1, 4)], closed(0, 2))
        self.assertEqual(c.received, [Interval(0, 4)])

    def test_result_entirely_before_zero_is_skipped(self):
        c = run([Interval(0, 1), Interval(5, 6)], closed(2, 3))
        self.assertEqual(c.received, [Interval(2, 4)])
        self.assertEqual(c.horizons, [4.0])

    def test_result_not_beyond_last_publishes_nothing(self):
        # Within (1, 3]: [5, 6) gives [2, 5) and the point 6 gives [3, 5),
        # which adds nothing beyond last = 5.
        c = run([Interval(5, 6), Interval.point(6)], Interval(1, 3, left_open=True, right_open=False))
        self.assertEqual(c.received, [Interval(2, 5)])
        self.assertEqual(c.horizons, [5.0])

    def test_closed_end_adds_the_point_at_last(self):
        # Within [1, 3]: [5, 6) gives [2, 5) and the point 6 gives [3, 5],
        # which adds only the point 5.
        c = run([Interval(5, 6), Interval.point(6)], closed(1, 3))
        self.assertEqual(c.received, [Interval(2, 5), Interval.point(5)])
        self.assertEqual(c.horizons, [5.0])

    def test_point_window_shifts_back(self):
        # Within [2, 2], i.e. exactly 2 time units ahead.
        c = run([Interval(5, 6)], Interval.point(2))
        self.assertEqual(c.received, [Interval(3, 4)])

    def test_unbounded_interval_publishes_no_horizon(self):
        c = run([Interval(5, 6), Interval(10)], closed(1, 3))
        self.assertEqual(c.received, [Interval(2, 5), Interval(7)])
        self.assertEqual(c.horizons, [5.0])

    def test_nothing_after_an_unbounded_result(self):
        m = EventuallyMonitor(Replay([([Interval(10)], None)]), closed(1, 3))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        m._receive(Interval(20, 21))
        self.assertEqual(c.received, [Interval(7)])
        self.assertIsNone(m.last)

    def test_horizon_of_arg_moves_the_horizon_back_by_the_window_end(self):
        m = EventuallyMonitor(Replay([([], 10)]), closed(1, 3))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [7.0])

    def test_horizon_of_arg_too_small_publishes_nothing(self):
        m = EventuallyMonitor(Replay([([], 2), ([], 3)]), closed(1, 3))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick(0))
        m.consume(tick(1))
        self.assertEqual(c.horizons, [])

    def test_horizon_of_arg_not_beyond_last_publishes_nothing(self):
        # [5, 6) gives [2, 5) and horizon 5; arg's horizon 7 gives only 4.
        m = EventuallyMonitor(Replay([([Interval(5, 6)], 7), ([], 9)]), closed(1, 3))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick(0))
        self.assertEqual(c.horizons, [5.0])
        m.consume(tick(1))
        self.assertEqual(c.horizons, [5.0, 6.0])

    def test_unbounded_window_ignores_the_horizons_of_arg(self):
        m = EventuallyMonitor(Replay([([], 10)]), Interval(1))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(c.horizons, [])

    def test_interval_is_published_before_its_horizon(self):
        log = []
        m = EventuallyMonitor(Replay([([Interval(5, 6)], None)]), closed(1, 3))
        m.add(RecordingConsumer(log))
        m.consume(tick())
        self.assertEqual(log, [('interval', Interval(2, 5)), ('horizon', 5.0)])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)
        for _ in range(500):
            intervals, x = [], 0.0
            for _ in range(rng.randint(1, 6)):
                start = x + rng.choice([0, 0.5, 1, 2, 4])
                end = start + rng.choice([0, 0.5, 1, 2])
                if end == start:
                    interval = Interval.point(start)
                else:
                    interval = Interval(start, end, left_open=rng.random() < 0.5,
                                        right_open=rng.random() < 0.6)
                if intervals and not intervals[-1].is_before(interval):
                    continue
                intervals.append(interval)
                x = end
            a = rng.choice([0, 0.5, 1, 2])
            b = a + rng.choice([0, 0.5, 1, 3])
            if a == b:
                i_arg = Interval.point(a)
            else:
                i_arg = Interval(a, b, left_open=rng.random() < 0.5,
                                 right_open=rng.random() < 0.5)
            c = run(intervals, i_arg)

            for p, q in zip(c.received, c.received[1:]):
                self.assertTrue(p.is_before(q))
            self.assertEqual(c.horizons, sorted(set(c.horizons)))
            known = c.horizons[-1] if c.horizons else 0.0

            images = [i.backward(i_arg) for i in intervals]
            points = {0.0, known}
            for i in images:
                if i is not None:
                    points |= {i.start, i.end, (i.start + i.end) / 2}
            for k in range(41):
                points.add(known * k / 40)
            for t in points:
                if t > known or t < 0:
                    continue
                expected = any(i is not None and i.contains(t) for i in images)
                self.assertEqual(any(i.contains(t) for i in c.received), expected,
                                 (t, intervals, i_arg))


class TestWithMonitors(unittest.TestCase):

    def test_eventually_true(self):
        # TrueMonitor publishes [0, 1) and [1, 3): within [0, 1] it is
        # reached from [0, 1) and then up to 3.
        m = EventuallyMonitor(TrueMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval(0, 1), Interval(1, 3)])
        self.assertEqual(c.horizons, [1.0, 3.0])

    def test_eventually_false_publishes_only_horizons(self):
        m = EventuallyMonitor(FalseMonitor(), closed(0, 1))
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3, 6):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [2.0, 5.0])


if __name__ == '__main__':
    unittest.main()
