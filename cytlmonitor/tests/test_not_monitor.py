"""Unit tests for cytlmonitor.not_monitor.NotMonitor."""

import random
import unittest

from cytlmonitor.and_monitor import AndMonitor
from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.false_monitor import FalseMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.not_monitor import NotMonitor
from cytlmonitor.or_monitor import OrMonitor
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


def run(steps):
    m = NotMonitor(Replay(steps))
    c = RecordingConsumer()
    m.add(c)
    for k in range(len(steps)):
        m.consume(tick(k))
    return c


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(NotMonitor(Replay([])), EventMonitor)

    def test_m_is_stored(self):
        a = Replay([])
        self.assertIs(NotMonitor(a).m, a)

    def test_non_monitor_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            NotMonitor(lambda e: None)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_m(self):
        a = Replay([])
        m = NotMonitor(a)
        e = tick(1)
        m.consume(e)
        self.assertEqual(a.events, [e])

    def test_gaps_are_published_up_to_the_horizon(self):
        c = run([([Interval(1, 3), Interval(5, 6)], 8)])
        self.assertEqual(c.received, [Interval(0, 1), Interval(3, 5), Interval(6, 8)])
        self.assertEqual(c.horizons, [8.0])

    def test_false_signal_gives_the_whole_known_part(self):
        c = run([([], 4)])
        self.assertEqual(c.received, [Interval(0, 4)])

    def test_true_signal_gives_nothing(self):
        c = run([([Interval(0, 4)], 4)])
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [4.0])

    def test_closed_ends_become_open_and_vice_versa(self):
        c = run([([Interval(1, 3, left_open=True, right_open=False)], 5)])
        self.assertEqual(c.received, [Interval(0, 1, right_open=False),
                                      Interval(3, 5, left_open=True)])

    def test_point_interval_leaves_a_gap_on_each_side(self):
        c = run([([Interval.point(2)], 4)])
        self.assertEqual(c.received, [Interval(0, 2), Interval(2, 4, left_open=True)])

    def test_nothing_is_published_until_the_horizon_moves(self):
        c = run([([Interval(1, 3)], None)])
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [])

    def test_known_part_grows_step_by_step(self):
        c = run([([Interval(1, 3)], 3), ([], 6), ([Interval(6, 7)], 7)])
        self.assertEqual(c.received, [Interval(0, 1), Interval(3, 6)])
        self.assertEqual(c.horizons, [3.0, 6.0, 7.0])

    def test_interval_beyond_the_horizon_is_negated_once_known(self):
        c = run([([Interval(2, 10)], 4), ([], 12)])
        self.assertEqual(c.received, [Interval(0, 2), Interval(10, 12)])
        self.assertEqual(c.horizons, [4.0, 12.0])

    def test_closed_point_at_the_horizon_waits_for_the_next_horizon(self):
        # m is true at 2, which is not in [0, 2): its negation over [2, 4)
        # must exclude 2.
        c = run([([Interval(0, 2, right_open=False)], 2), ([], 4)])
        self.assertEqual(c.received, [Interval(2, 4, left_open=True)])

    def test_horizon_is_not_republished_when_it_does_not_grow(self):
        c = run([([], 3), ([], 3)])
        self.assertEqual(c.horizons, [3.0])

    def test_intervals_are_published_before_the_horizon(self):
        log = []
        m = NotMonitor(Replay([([Interval(1, 2)], 3)]))
        m.add(RecordingConsumer(log))
        m.consume(tick())
        self.assertEqual(log, [('interval', Interval(0, 1)), ('interval', Interval(2, 3)),
                               ('horizon', 3.0)])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)
        for _ in range(300):
            steps, x, horizon, last = [], 0.0, 0.0, None
            for _ in range(rng.randint(1, 6)):
                batch = []
                for _ in range(rng.randint(0, 2)):
                    start = x + rng.choice([0, 0.5, 1])
                    end = start + rng.choice([0, 0.5, 1, 2])
                    left_open = rng.random() < 0.5
                    if end == start:
                        if left_open:
                            continue
                        interval = Interval.point(start)
                    else:
                        interval = Interval(start, end, left_open=left_open,
                                            right_open=rng.random() < 0.6)
                    if last is not None and not last.is_before(interval):
                        continue
                    batch.append(interval)
                    last, x = interval, end
                horizon = max(horizon, x) + rng.choice([0, 0, 0.5])
                x = horizon
                steps.append((batch, horizon))
            c = run(steps)
            sig = BooleanSignal([i for batch, _ in steps for i in batch])
            known = steps[-1][1]

            for a, b in zip(c.received, c.received[1:]):
                self.assertTrue(a.is_before(b))
            points = {0.0, known}
            for i in sig:
                points |= {i.start, i.end, (i.start + i.end) / 2}
            for k in range(9):
                points.add(known * k / 8)
            for t in points:
                negated = any(i.contains(t) for i in c.received)
                if t < known:
                    self.assertEqual(negated, not any(i.contains(t) for i in sig), (t, steps))
                else:
                    self.assertFalse(negated)


class TestWithMonitors(unittest.TestCase):

    def test_not_true_is_false(self):
        m = NotMonitor(TrueMonitor())
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [1.0, 3.0])

    def test_not_false_is_true(self):
        m = NotMonitor(FalseMonitor())
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval(0, 1), Interval(1, 3)])
        self.assertEqual(c.horizons, [1.0, 3.0])

    def test_double_negation(self):
        m = NotMonitor(NotMonitor(TrueMonitor()))
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval(0, 2), Interval(2, 5)])

    def test_de_morgan(self):
        # not (a and b) == (not a) or (not b), with a = true, b = false.
        left = NotMonitor(AndMonitor(TrueMonitor(), FalseMonitor()))
        right = OrMonitor(NotMonitor(TrueMonitor()), NotMonitor(FalseMonitor()))
        received = []
        for m in (left, right):
            c = RecordingConsumer()
            m.add(c)
            for t in (1, 4):
                m.consume(tick(t))
            received.append((c.received, c.horizons))
        self.assertEqual(received[0], received[1])


if __name__ == '__main__':
    unittest.main()
