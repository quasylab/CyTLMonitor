"""Unit tests for cytlmonitor.or_monitor.OrMonitor."""

import random
import unittest

from cytlmonitor.and_monitor import AndMonitor
from cytlmonitor.binary_monitor import BinaryMonitor
from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.false_monitor import FalseMonitor
from cytlmonitor.interval import Interval
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


def run(steps1, steps2):
    m = OrMonitor(Replay(steps1), Replay(steps2))
    c = RecordingConsumer()
    m.add(c)
    for k in range(max(len(steps1), len(steps2))):
        m.consume(tick(k))
    return c


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(OrMonitor(Replay([]), Replay([])), EventMonitor)

    def test_base_class_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            BinaryMonitor(Replay([]), Replay([]))

    def test_fields_are_stored(self):
        a, b = Replay([]), Replay([])
        m = OrMonitor(a, b)
        self.assertIs(m.m1, a)
        self.assertIs(m.m2, b)

    def test_non_monitor_args_raise_type_error(self):
        with self.assertRaises(TypeError):
            OrMonitor(lambda e: None, Replay([]))
        with self.assertRaises(TypeError):
            OrMonitor(Replay([]), None)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_both_monitors(self):
        a, b = Replay([]), Replay([])
        m = OrMonitor(a, b)
        e = tick(1)
        m.consume(e)
        self.assertEqual(a.events, [e])
        self.assertEqual(b.events, [e])

    def test_same_monitor_receives_event_once(self):
        a = Replay([([Interval(0, 2)], 3)])
        m = OrMonitor(a, a)
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(len(a.events), 1)
        self.assertEqual(c.received, [Interval(0, 2)])
        self.assertEqual(c.horizons, [3.0])

    def test_union_is_published_up_to_the_smaller_horizon(self):
        c = run([([Interval(0, 2), Interval(6, 8)], 8)], [([Interval(3, 4)], 7)])
        self.assertEqual(c.received, [Interval(0, 2), Interval(3, 4), Interval(6, 7)])
        self.assertEqual(c.horizons, [7.0])

    def test_overlapping_intervals_are_merged(self):
        c = run([([Interval(0, 3)], 6)], [([Interval(2, 5)], 6)])
        self.assertEqual(c.received, [Interval(0, 5)])

    def test_adjacent_intervals_are_merged(self):
        c = run([([Interval(0, 2, right_open=False)], 6)],
                [([Interval(2, 5, left_open=True)], 6)])
        self.assertEqual(c.received, [Interval(0, 5)])

    def test_nothing_is_published_until_both_horizons_move(self):
        c = run([([Interval(0, 4)], 4)], [([], None)])
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [])

    def test_interval_split_across_horizons(self):
        c = run([([Interval(0, 10)], 10), ([], None)],
                [([], 4), ([], 10)])
        self.assertEqual(c.received, [Interval(0, 4), Interval(4, 10)])
        self.assertEqual(c.horizons, [4.0, 10.0])

    def test_both_false_publishes_only_horizons(self):
        c = run([([], 5)], [([], 5)])
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [5.0])

    def test_closed_point_at_the_horizon_waits_for_the_next_horizon(self):
        c = run([([Interval(0, 2, right_open=False)], 2), ([], 4)],
                [([], 2), ([], 4)])
        self.assertEqual(c.received, [Interval(0, 2), Interval.point(2)])
        self.assertEqual(c.horizons, [2.0, 4.0])

    def test_horizon_is_not_republished_when_it_does_not_grow(self):
        c = run([([], 3), ([], 3)], [([], 3), ([], 3)])
        self.assertEqual(c.horizons, [3.0])

    def test_intervals_are_published_before_the_horizon(self):
        log = []
        m = OrMonitor(Replay([([Interval(0, 1)], 5)]), Replay([([Interval(3, 4)], 5)]))
        m.add(RecordingConsumer(log))
        m.consume(tick())
        self.assertEqual(log, [('interval', Interval(0, 1)), ('interval', Interval(3, 4)),
                               ('horizon', 5.0)])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)

        def random_steps():
            steps, x, horizon = [], 0.0, 0.0
            for _ in range(rng.randint(1, 6)):
                batch = []
                for _ in range(rng.randint(0, 2)):
                    start = x + rng.choice([0, 0.5, 1])
                    end = start + rng.choice([0, 0.5, 1, 2])
                    left_open = rng.random() < 0.5 and start > horizon
                    if end == start:
                        if left_open:
                            continue
                        interval = Interval.point(start)
                    else:
                        interval = Interval(start, end, left_open=left_open,
                                            right_open=rng.random() < 0.6)
                    if start < horizon or (batch and not batch[-1].is_before(interval)):
                        continue
                    if not batch and steps and not _last(steps).is_before(interval):
                        continue
                    batch.append(interval)
                    x = end
                horizon = max([horizon, x] + [i.end for i in batch]) + rng.choice([0, 0, 0.5])
                x = max(x, horizon)
                steps.append((batch, horizon))
            return steps

        def _last(steps):
            for batch, _ in reversed(steps):
                if batch:
                    return batch[-1]
            return Interval(-1, -1, right_open=False)

        for _ in range(300):
            s1, s2 = random_steps(), random_steps()
            c = run(s1, s2)
            sig1 = BooleanSignal([i for batch, _ in s1 for i in batch])
            sig2 = BooleanSignal([i for batch, _ in s2 for i in batch])
            known = min(s1[-1][1], s2[-1][1])

            for a, b in zip(c.received, c.received[1:]):
                self.assertTrue(a.is_before(b))
            self.assertEqual(c.horizons, sorted(set(c.horizons)))
            if known > 0:
                self.assertEqual(c.horizons[-1], known)

            points = {0.0, known}
            for i in list(sig1) + list(sig2):
                points.add(i.start)
                if i.end is not None:
                    points |= {i.end, (i.start + i.end) / 2}
            for t in points:
                if t < known:
                    expected = (any(i.contains(t) for i in sig1)
                                or any(i.contains(t) for i in sig2))
                    self.assertEqual(any(i.contains(t) for i in c.received), expected, (t, s1, s2))
                elif c.received:
                    self.assertFalse(any(i.contains(t) for i in c.received))



class TestWithMonitors(unittest.TestCase):

    def test_true_or_false_is_true(self):
        m = OrMonitor(TrueMonitor(), FalseMonitor())
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval(0, 1), Interval(1, 3)])
        self.assertEqual(c.horizons, [1.0, 3.0])

    def test_false_or_false_is_false(self):
        m = OrMonitor(FalseMonitor(), FalseMonitor())
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3):
            m.consume(tick(t))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [1.0, 3.0])

    def test_or_of_and(self):
        m = OrMonitor(AndMonitor(TrueMonitor(), FalseMonitor()), TrueMonitor())
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval(0, 2), Interval(2, 5)])
        self.assertEqual(c.horizons, [2.0, 5.0])


if __name__ == '__main__':
    unittest.main()
