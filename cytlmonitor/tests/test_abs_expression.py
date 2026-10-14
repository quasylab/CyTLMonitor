"""Unit tests for cytlmonitor.abs_expression.AbsExpression."""

import random
import unittest

from cytlmonitor.abs_expression import AbsExpression
from cytlmonitor.difference_expression import DifferenceExpression
from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.sum_window_expression import SumWindowExpression
from cytlmonitor.unary_expression import UnaryExpression


class RecordingConsumer(SignalConsumer):

    def __init__(self):
        self.received = []

    def consume(self, s):
        self.received.append(s)


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


def run(batches):
    x = AbsExpression(Replay(batches))
    c = RecordingConsumer()
    x.add(c)
    for i in range(len(batches)):
        x.consume(tick(i))
    return c.received


def as_tuples(segments):
    return [(s.interval, s.polynomial) for s in segments]


class TestConstruction(unittest.TestCase):

    def test_is_a_stream_expression(self):
        self.assertIsInstance(AbsExpression(Replay([])), StreamExpression)

    def test_base_class_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            UnaryExpression(Replay([]))

    def test_arg_is_stored(self):
        a = Replay([])
        self.assertIs(AbsExpression(a).arg, a)

    def test_non_expression_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            AbsExpression(lambda e: 1.0)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_arg(self):
        a = Replay([])
        x = AbsExpression(a)
        e = tick(1)
        x.consume(e)
        self.assertEqual(a.events, [e])

    def test_positive_constant_is_unchanged(self):
        segments = run([[segment(Interval(0, 2), 3)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([3]))])

    def test_negative_constant_is_negated(self):
        segments = run([[segment(Interval(0, 2), -3)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([3]))])

    def test_zero_stays_zero(self):
        segments = run([[segment(Interval(0, 2), 0)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial.ZERO)])

    def test_linear_segment_is_split_at_its_root(self):
        # t - 2 on [0, 4): 2 - t on [0, 2), t - 2 on [2, 4).
        segments = run([[segment(Interval(0, 4), -2, 1)]])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 2), Polynomial([2, -1])),
            (Interval(2, 4), Polynomial([-2, 1])),
        ])

    def test_quadratic_segment_is_split_at_both_roots(self):
        # (t - 1)(t - 3) is negative on (1, 3).
        segments = run([[segment(Interval(0, 4), 3, -4, 1)]])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1, right_open=False), Polynomial([3, -4, 1])),
            (Interval(1, 3, left_open=True), Polynomial([-3, 4, -1])),
            (Interval(3, 4), Polynomial([3, -4, 1])),
        ])

    def test_quadratic_without_roots_is_unchanged(self):
        segments = run([[segment(Interval(0, 4), 1, 0, 1)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 4), Polynomial([1, 0, 1]))])

    def test_root_outside_segment_does_not_split(self):
        segments = run([[segment(Interval(0, 2), -5, 1)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([5, -1]))])

    def test_point_segment(self):
        segments = run([[segment(Interval.point(2), -7)]])
        self.assertEqual(as_tuples(segments), [(Interval.point(2), Polynomial([7]))])

    def test_unbounded_segment(self):
        segments = run([[segment(Interval(0), 1, -1)]])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1, right_open=False), Polynomial([1, -1])),
            (Interval(1, None, left_open=True), Polynomial([-1, 1])),
        ])

    def test_each_segment_is_published_at_once(self):
        a = Replay([[segment(Interval(0, 1), -1)], [segment(Interval(1, 2), 2)]])
        x = AbsExpression(a)
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick(0))
        self.assertEqual(as_tuples(c.received), [(Interval(0, 1), Polynomial([1]))])
        x.consume(tick(1))
        self.assertEqual(as_tuples(c.received)[1:], [(Interval(1, 2), Polynomial([2]))])

    def test_degree_above_two_raises_value_error(self):
        with self.assertRaises(ValueError):
            run([[segment(Interval(0, 2), 0, 0, 0, 1)]])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)
        for _ in range(300):
            inputs, x, left_open = [], 0.0, False
            for _ in range(rng.randint(1, 6)):
                if not left_open and rng.random() < 0.2:
                    interval = Interval.point(x)
                    left_open = True
                else:
                    end = x + rng.choice([0.5, 1, 2, 4])
                    right_open = rng.random() < 0.6
                    interval = Interval(x, end, left_open=left_open, right_open=right_open)
                    x, left_open = end, not right_open
                coefficients = [rng.randint(-4, 4) for _ in range(rng.randint(1, 3))]
                inputs.append(Segment(interval, Polynomial(coefficients)))
            segments = run([inputs])

            cursor, cursor_open = 0.0, False
            for s in segments:
                self.assertEqual(s.interval.start, cursor)
                self.assertEqual(s.interval.left_open, cursor_open)
                cursor, cursor_open = s.interval.end, not s.interval.right_open
            self.assertEqual(cursor, inputs[-1].interval.end)

            for g in inputs:
                i = g.interval
                for k in range(9):
                    t = i.start + (i.end - i.start) * k / 8
                    if g.contains(t):
                        out = next(s for s in segments if s.contains(t))
                        self.assertGreaterEqual(out.value_at(t), -1e-9)
                        self.assertAlmostEqual(out.value_at(t), abs(g.value_at(t)))


class TestComposition(unittest.TestCase):

    def test_absolute_difference(self):
        g1 = [segment(Interval(0, 2), 5), segment(Interval(2, 4), 1)]
        g2 = [segment(Interval(0, 4), 3)]
        x = AbsExpression(DifferenceExpression(Replay([g1]), Replay([g2])))
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick())
        self.assertEqual(as_tuples(c.received), [
            (Interval(0, 2), Polynomial([2])),
            (Interval(2, 4), Polynomial([2])),
        ])

    def test_abs_of_a_window_sum(self):
        x = AbsExpression(SumWindowExpression(lambda e: e['v'], 0, 1))
        c = RecordingConsumer()
        x.add(c)
        for t, v in ((1, -4), (5, 0)):
            x.consume(Event(t, Payload({'v': v})))
        values = [(s.interval, s.polynomial.evaluate(0)) for s in c.received]
        self.assertEqual(values, [
            (Interval(0, 1, right_open=False), 4.0),
            (Interval(1, 4, left_open=True), 0.0),
        ])


if __name__ == '__main__':
    unittest.main()
