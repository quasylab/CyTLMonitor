"""Unit tests for cytlmonitor.atomic_leq_monitor.AtomicLeqMonitor."""

import random
import unittest

from cytlmonitor.and_monitor import AndMonitor
from cytlmonitor.atomic_leq_monitor import AtomicLeqMonitor
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
    m = AtomicLeqMonitor(Replay(batches1), Replay(batches2))
    c = RecordingConsumer()
    m.add(c)
    for k in range(max(len(batches1), len(batches2))):
        m.consume(tick(k))
    return c


class TestConstruction(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(AtomicLeqMonitor(Replay([]), Replay([])), EventMonitor)

    def test_fields_are_stored(self):
        a, b = Replay([]), Replay([])
        m = AtomicLeqMonitor(a, b)
        self.assertIs(m.arg1, a)
        self.assertIs(m.arg2, b)

    def test_non_expression_args_raise_type_error(self):
        with self.assertRaises(TypeError):
            AtomicLeqMonitor(lambda e: 1.0, Replay([]))
        with self.assertRaises(TypeError):
            AtomicLeqMonitor(Replay([]), None)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_both_args(self):
        a, b = Replay([]), Replay([])
        m = AtomicLeqMonitor(a, b)
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

        AtomicLeqMonitor(Tagged('arg1'), Tagged('arg2')).consume(tick())
        self.assertEqual(order, ['arg1', 'arg2'])

    def test_same_arg_receives_event_once_and_is_always_true(self):
        a = Replay([[segment(Interval(0, 2), 0, 1)]])
        m = AtomicLeqMonitor(a, a)
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick())
        self.assertEqual(len(a.events), 1)
        self.assertEqual(c.received, [Interval(0, 2)])
        self.assertEqual(c.horizons, [2.0])

    def test_constants(self):
        c = run([[segment(Interval(0, 2), 1), segment(Interval(2, 4), 5)]],
                [[segment(Interval(0, 4), 3)]])
        self.assertEqual(c.received, [Interval(0, 2)])
        self.assertEqual(c.horizons, [2.0, 4.0])

    def test_equal_values_count_as_true(self):
        c = run([[segment(Interval(0, 3), 2)]], [[segment(Interval(0, 3), 2)]])
        self.assertEqual(c.received, [Interval(0, 3)])

    def test_argument_order_matters(self):
        c = run([[segment(Interval(0, 4), 3)]],
                [[segment(Interval(0, 2), 1), segment(Interval(2, 4), 5)]])
        self.assertEqual(c.received, [Interval(2, 4)])

    def test_linear_crossing_is_split_at_the_root(self):
        # t <= 2 on [0, 4): true on [0, 2], including the crossing point.
        c = run([[segment(Interval(0, 4), 0, 1)]], [[segment(Interval(0, 4), 2)]])
        self.assertEqual(c.received, [Interval(0, 2, right_open=False)])
        self.assertEqual(c.horizons, [4.0])

    def test_quadratic_comparison(self):
        # t^2 <= 4t - 3, i.e. (t - 1)(t - 3) <= 0: true on [1, 3].
        c = run([[segment(Interval(0, 5), 0, 0, 1)]], [[segment(Interval(0, 5), -3, 4)]])
        self.assertEqual(c.received, [Interval(1, 3, right_open=False)])

    def test_tangent_point_is_true(self):
        # t^2 <= 2t - 1, i.e. (t - 1)^2 <= 0: true only at t = 1.
        c = run([[segment(Interval(0, 3), 0, 0, 1)]], [[segment(Interval(0, 3), -1, 2)]])
        self.assertEqual(c.received, [Interval.point(1)])

    def test_waits_for_the_slower_argument(self):
        a = Replay([[segment(Interval(0, 4), 1)], []])
        b = Replay([[segment(Interval(0, 1), 0)], [segment(Interval(1, 4), 2)]])
        m = AtomicLeqMonitor(a, b)
        c = RecordingConsumer()
        m.add(c)
        m.consume(tick(0))
        self.assertEqual(c.received, [])
        self.assertEqual(c.horizons, [1.0])
        m.consume(tick(1))
        self.assertEqual(c.received, [Interval(1, 4)])
        self.assertEqual(c.horizons, [1.0, 4.0])

    def test_intervals_are_published_before_their_horizon(self):
        log = []
        m = AtomicLeqMonitor(Replay([[segment(Interval(0, 2), 0)]]),
                             Replay([[segment(Interval(0, 2), 1)]]))
        m.add(RecordingConsumer(log))
        m.consume(tick())
        self.assertEqual(log, [('interval', Interval(0, 2)), ('horizon', 2.0)])

    def test_unbounded_segment_publishes_no_horizon(self):
        c = run([[segment(Interval(0, 2), 0), segment(Interval(2), 5)]],
                [[segment(Interval(0), 1)]])
        self.assertEqual(c.received, [Interval(0, 2)])
        self.assertEqual(c.horizons, [2.0])

    def test_horizon_is_not_republished_when_it_does_not_grow(self):
        # The point segment [2, 2] ends where [0, 2) does.
        c = run([[segment(Interval(0, 2), 0), segment(Interval.point(2), 0),
                  segment(Interval(2, 4, left_open=True), 0)]],
                [[segment(Interval(0, 4), 1)]])
        self.assertEqual(c.horizons, [2.0, 4.0])
        self.assertEqual(c.received, [Interval(0, 2), Interval.point(2),
                                      Interval(2, 4, left_open=True)])

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
                self.assertEqual(any(i.contains(t) for i in c.received), v1 <= v2, (t, g1, g2))


class TestComposition(unittest.TestCase):

    def test_count_in_window_at_most_one(self):
        # At most one event in [t, t + 1]: with events at 1 and 2 the count
        # is 2 only at t = 1 (it is 1 on (1, 2], where the event at 2 is
        # still in the window, and 0 after).
        count = SumWindowExpression(lambda e: 1.0, 0, 1)
        one = Replay([[segment(Interval(0), 1)]])
        m = AtomicLeqMonitor(count, one)
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval(0, 1),
                                      Interval(1, 2, left_open=True, right_open=False),
                                      Interval(2, 4, left_open=True)])
        self.assertEqual(c.horizons, [1.0, 2.0, 4.0])

    def test_combined_with_boolean_monitors(self):
        # not (constant 3 <= constant 1) and true.
        m = AndMonitor(NotMonitor(AtomicLeqMonitor(
            Replay([[segment(Interval(0, 2), 3)], [segment(Interval(2, 5), 3)]]),
            Replay([[segment(Interval(0, 2), 1)], [segment(Interval(2, 5), 1)]]))),
            TrueMonitor())
        c = RecordingConsumer()
        m.add(c)
        for t in (2, 5):
            m.consume(tick(t))
        self.assertEqual(c.received, [Interval(0, 2), Interval(2, 5)])
        self.assertEqual(c.horizons, [2.0, 5.0])


if __name__ == '__main__':
    unittest.main()
