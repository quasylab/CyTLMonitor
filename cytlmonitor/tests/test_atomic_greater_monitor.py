"""Unit tests for cytlmonitor.atomic_greater_monitor.AtomicGreaterMonitor."""

import random
import unittest

from cytlmonitor.atomic_geq_monitor import AtomicGeqMonitor
from cytlmonitor.atomic_greater_monitor import AtomicGreaterMonitor
from cytlmonitor.atomic_less_monitor import AtomicLessMonitor
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.not_monitor import NotMonitor
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.sum_window_expression import SumWindowExpression


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


class Replay(StreamExpression):
    """For each consumed event, publishes the next batch of segments."""

    def __init__(self, batches):
        super().__init__()
        self.batches = [list(b) for b in batches]
        self.events = []

    def consume(self, event):
        self.events.append(event)
        for s in (self.batches.pop(0) if self.batches else []):
            self.publish(s)


def segment(interval, *coefficients):
    return Segment(interval, Polynomial(coefficients))


def tick(t=0):
    return Event(t, Payload({}))


def run(batches1, batches2):
    m = AtomicGreaterMonitor(Replay(batches1), Replay(batches2))
    c = RecordingConsumer()
    m.add(c)
    for k in range(max(len(batches1), len(batches2))):
        m.consume(tick(k))
    return c


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(AtomicGreaterMonitor(Replay([]), Replay([])), EventMonitor)

    def test_fields_are_stored(self):
        a, b = Replay([]), Replay([])
        m = AtomicGreaterMonitor(a, b)
        self.assertIs(m.arg1, a)
        self.assertIs(m.arg2, b)

    def test_non_expression_args_raise_type_error(self):
        with self.assertRaises(TypeError):
            AtomicGreaterMonitor(lambda e: 1.0, Replay([]))
        with self.assertRaises(TypeError):
            AtomicGreaterMonitor(Replay([]), None)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_both_args(self):
        a, b = Replay([]), Replay([])
        m = AtomicGreaterMonitor(a, b)
        e = tick(1)
        m.consume(e)
        self.assertEqual(a.events, [e])
        self.assertEqual(b.events, [e])

    def test_event_is_passed_to_arg1_first(self):
        order = []

        class Tagged(Replay):
            def __init__(self, name):
                super().__init__([])
                self.name = name

            def consume(self, event):
                order.append(self.name)

        AtomicGreaterMonitor(Tagged('arg1'), Tagged('arg2')).consume(tick())
        self.assertEqual(order, ['arg1', 'arg2'])

    def test_same_arg_receives_event_once_and_is_always_false(self):
        a = Replay([[segment(Interval(0, 2), 0, 1)]])
        m = AtomicGreaterMonitor(a, a)
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(len(a.events), 1)
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [2.0])

    def test_constants(self):
        c = run([[segment(Interval(0, 2), 1), segment(Interval(2, 4), 5)]],
                [[segment(Interval(0, 4), 3)]])
        self.assertEqual(c.received, [Interval(2, 4)])
        self.assertEqual(c.horizons, [2.0, 4.0])

    def test_equal_values_count_as_false(self):
        c = run([[segment(Interval(0, 3), 2)]], [[segment(Interval(0, 3), 2)]])
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [3.0])

    def test_argument_order_matters(self):
        c = run([[segment(Interval(0, 4), 3)]],
                [[segment(Interval(0, 2), 1), segment(Interval(2, 4), 5)]])
        self.assertEqual(c.received, [Interval(0, 2)])

    def test_linear_crossing_excludes_the_root(self):
        # t > 2 on [0, 4): true on (2, 4).
        c = run([[segment(Interval(0, 4), 0, 1)]], [[segment(Interval(0, 4), 2)]])
        self.assertEqual(c.received, [Interval(2, 4, left_open=True)])
        self.assertEqual(c.horizons, [4.0])

    def test_quadratic_comparison(self):
        # t^2 > 4t - 3, i.e. (t - 1)(t - 3) > 0: true on [0, 1) and (3, 5).
        c = run([[segment(Interval(0, 5), 0, 0, 1)]], [[segment(Interval(0, 5), -3, 4)]])
        self.assertEqual(c.received, [Interval(0, 1), Interval(3, 5, left_open=True)])

    def test_tangent_point_is_excluded(self):
        # t^2 > 2t - 1, i.e. (t - 1)^2 > 0: true everywhere except t = 1.
        c = run([[segment(Interval(0, 3), 0, 0, 1)]], [[segment(Interval(0, 3), -1, 2)]])
        self.assertEqual(c.received, [Interval(0, 1), Interval(1, 3, left_open=True)])

    def test_greater_is_less_with_swapped_arguments(self):
        a = [[segment(Interval(0, 4), 0, 1)]]
        b = [[segment(Interval(0, 1), 2), segment(Interval(1, 4), 3)]]
        results = []
        for m in (AtomicGreaterMonitor(Replay(a), Replay(b)),
                  AtomicLessMonitor(Replay(b), Replay(a))):
            c = RecordingConsumer()
            m.add(c)
            m.consume(tick())
            results.append((c.received, c.horizons))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0][0], [Interval(3, 4, left_open=True)])

    def test_greater_and_geq_differ_only_where_the_signals_are_equal(self):
        a = [[segment(Interval(0, 4), 0, 1)]]
        b = [[segment(Interval(0, 4), 2)]]
        results = []
        for cls in (AtomicGreaterMonitor, AtomicGeqMonitor):
            m = cls(Replay(a), Replay(b))
            c = RecordingConsumer()
            m.add(c)
            m.consume(tick())
            results.append(c.received)
        self.assertEqual(results[0], [Interval(2, 4, left_open=True)])
        self.assertEqual(results[1], [Interval(2, 4)])

    def test_horizon_is_not_republished_when_it_does_not_grow(self):
        c = run([[segment(Interval(0, 2), 1), segment(Interval.point(2), 1),
                  segment(Interval(2, 4, left_open=True), 1)]],
                [[segment(Interval(0, 4), 0)]])
        self.assertEqual(c.horizons, [2.0, 4.0])

    def test_unbounded_segment_publishes_no_horizon(self):
        c = run([[segment(Interval(0, 2), 5), segment(Interval(2), 0)]],
                [[segment(Interval(0), 1)]])
        self.assertEqual(c.received, [Interval(0, 2)])
        self.assertEqual(c.horizons, [2.0])

    def test_degree_above_two_raises_value_error(self):
        with self.assertRaises(ValueError):
            run([[segment(Interval(0, 2), 0, 0, 0, 1)]], [[segment(Interval(0, 2), 0)]])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)

        def random_signal(length):
            segments, x, left_open = [], 0.0, False
            while x < length:
                if not left_open and rng.random() < 0.2:
                    interval = Interval.point(x)
                    left_open = True
                else:
                    end = min(length, x + rng.choice([0.5, 1, 1.5, 2]))
                    right_open = end < length and rng.random() < 0.6
                    interval = Interval(x, end, left_open=left_open, right_open=right_open)
                    x, left_open = end, not right_open
                coefficients = [rng.randint(-3, 3) for _ in range(rng.randint(1, 3))]
                segments.append(Segment(interval, Polynomial(coefficients)))
            return segments

        def random_batches(segments, n):
            cuts = sorted(rng.randint(0, len(segments)) for _ in range(n - 1))
            bounds = [0] + cuts + [len(segments)]
            return [segments[bounds[i]:bounds[i + 1]] for i in range(n)]

        def at(signal, t):
            return next(s.value_at(t) for s in signal if s.contains(t))

        for _ in range(300):
            g1, g2 = random_signal(6), random_signal(6)
            n = rng.randint(1, 5)
            c = run(random_batches(g1, n), random_batches(g2, n))

            for a, b in zip(c.received, c.received[1:]):
                self.assertTrue(a.is_before(b))
            self.assertEqual(c.horizons, sorted(set(c.horizons)))
            self.assertEqual(c.horizons[-1], 6.0)
            for i in c.received:
                self.assertLessEqual(i.end, 6.0)

            points = {0.0, 6.0}
            for s in g1 + g2:
                i = s.interval
                points |= {i.start, i.end, (i.start + i.end) / 2}
            for k in range(25):
                points.add(6 * k / 24)
            for t in points:
                v1, v2 = at(g1, t), at(g2, t)
                if abs(v1 - v2) < 1e-9:
                    continue
                self.assertEqual(any(i.contains(t) for i in c.received), v1 > v2, (t, g1, g2))




class TestComposition(unittest.TestCase):

    def test_more_than_one_event_in_window(self):
        # count > 1 over [t, t + 1], with events at 1 and 2: true only at
        # t = 1, where both events are in the window.
        count = SumWindowExpression(lambda e: 1.0, 0, 1)
        one = Replay([[segment(Interval(0), 1)]])
        m = AtomicGreaterMonitor(count, one)
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval.point(1)])
        self.assertEqual(c.horizons, [1.0, 2.0, 4.0])

    def test_not_greater_is_leq(self):
        # not (x > 3) where x is 1 then 5: true where x <= 3.
        m = NotMonitor(AtomicGreaterMonitor(
            Replay([[segment(Interval(0, 2), 1), segment(Interval(2, 4), 5)]]),
            Replay([[segment(Interval(0, 4), 3)]])))
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(c.received, [Interval(0, 2)])
        self.assertEqual(c.horizons, [2.0, 4.0])


if __name__ == '__main__':
    unittest.main()
