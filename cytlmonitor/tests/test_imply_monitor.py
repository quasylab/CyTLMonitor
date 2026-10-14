"""Unit tests for cytlmonitor.imply_monitor.ImplyMonitor."""

import random
import unittest

from cytlmonitor.and_monitor import AndMonitor
from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.false_monitor import FalseMonitor
from cytlmonitor.imply_monitor import ImplyMonitor
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


def run(steps1, steps2):
    m = ImplyMonitor(Replay(steps1), Replay(steps2))
    c = RecordingConsumer()
    m.add(c)
    for k in range(max(len(steps1), len(steps2))):
        m.consume(tick(k))
    return c


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(ImplyMonitor(Replay([]), Replay([])), EventMonitor)

    def test_fields_are_stored(self):
        a, b = Replay([]), Replay([])
        m = ImplyMonitor(a, b)
        self.assertIs(m.m1, a)
        self.assertIs(m.m2, b)

    def test_non_monitor_args_raise_type_error(self):
        with self.assertRaises(TypeError):
            ImplyMonitor(lambda e: None, Replay([]))
        with self.assertRaises(TypeError):
            ImplyMonitor(Replay([]), None)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_both_monitors(self):
        a, b = Replay([]), Replay([])
        m = ImplyMonitor(a, b)
        e = tick(1)
        m.consume(e)
        self.assertEqual(a.events, [e])
        self.assertEqual(b.events, [e])

    def test_true_where_m1_is_false_or_m2_is_true(self):
        # m1 true on [2, 6), m2 true on [4, 5): false only on [2, 4) and [5, 6).
        c = run([([Interval(2, 6)], 8)], [([Interval(4, 5)], 8)])
        self.assertEqual(c.received, [Interval(0, 2), Interval(4, 5), Interval(6, 8)])
        self.assertEqual(c.horizons, [8.0])

    def test_argument_order_matters(self):
        c = run([([Interval(4, 5)], 8)], [([Interval(2, 6)], 8)])
        self.assertEqual(c.received, [Interval(0, 8)])

    def test_m1_false_everywhere_gives_true(self):
        c = run([([], 5)], [([], 5)])
        self.assertEqual(c.received, [Interval(0, 5)])

    def test_m1_true_everywhere_gives_m2(self):
        c = run([([Interval(0, 5)], 5)], [([Interval(1, 2)], 5)])
        self.assertEqual(c.received, [Interval(1, 2)])

    def test_same_monitor_gives_true(self):
        a = Replay([([Interval(1, 3)], 4)])
        m = ImplyMonitor(a, a)
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(len(a.events), 1)
        self.assertEqual(c.received, [Interval(0, 4)])

    def test_closed_and_open_ends(self):
        # m1 true on [1, 3]: false on [0, 1) and (3, 5).
        c = run([([Interval(1, 3, right_open=False)], 5)], [([], 5)])
        self.assertEqual(c.received, [Interval(0, 1), Interval(3, 5, left_open=True)])

    def test_nothing_is_published_until_both_horizons_move(self):
        c = run([([], 4)], [([], None)])
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [])

    def test_known_part_grows_step_by_step(self):
        c = run([([Interval(1, 10)], 10), ([], None)],
                [([], 3), ([Interval(3, 6)], 6)])
        self.assertEqual(c.received, [Interval(0, 1), Interval(3, 6)])
        self.assertEqual(c.horizons, [3.0, 6.0])

    def test_closed_point_at_the_horizon_waits_for_the_next_horizon(self):
        # m1 true on [0, 2]: the implication is false at 2, which is not in
        # [0, 2), so the next stretch starts open at 2.
        c = run([([Interval(0, 2, right_open=False)], 2), ([], 4)],
                [([], 2), ([], 4)])
        self.assertEqual(c.received, [Interval(2, 4, left_open=True)])

    def test_horizon_is_not_republished_when_it_does_not_grow(self):
        c = run([([], 3), ([], 3)], [([], 3), ([], 3)])
        self.assertEqual(c.horizons, [3.0])

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
                    expected = (not any(i.contains(t) for i in sig1)
                                or any(i.contains(t) for i in sig2))
                    self.assertEqual(any(i.contains(t) for i in c.received), expected, (t, s1, s2))
                else:
                    self.assertFalse(any(i.contains(t) for i in c.received))




class TestWithMonitors(unittest.TestCase):

    def test_truth_table(self):
        for m1, m2, expected in ((TrueMonitor, TrueMonitor, True),
                                 (TrueMonitor, FalseMonitor, False),
                                 (FalseMonitor, TrueMonitor, True),
                                 (FalseMonitor, FalseMonitor, True)):
            with self.subTest(m1=m1.__name__, m2=m2.__name__):
                m = ImplyMonitor(m1(), m2())
                c = RecordingConsumer()
                m.add(c)
                for t in (1, 3):
                    m.consume(tick(t))
                self.assertEqual(c.received, [Interval(0, 1), Interval(1, 3)] if expected else [])
                self.assertEqual(c.horizons, [1.0, 3.0])

    def test_matches_not_m1_or_m2(self):
        steps1 = [([Interval(1, 4)], 4), ([Interval(5, 9)], 9)]
        steps2 = [([Interval(2, 3)], 3), ([Interval(6, 7)], 9)]
        imply = ImplyMonitor(Replay(steps1), Replay(steps2))
        explicit = OrMonitor(NotMonitor(Replay(steps1)), Replay(steps2))
        results = []
        for m in (imply, explicit):
            c = RecordingConsumer()
            m.add(c)
            for k in range(2):
                m.consume(tick(k))
            results.append((BooleanSignal(c.received).horizon, list(BooleanSignal(c.received))))
        self.assertEqual(results[0], results[1])


if __name__ == '__main__':
    unittest.main()
