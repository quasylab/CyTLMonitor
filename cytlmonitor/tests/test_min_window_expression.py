"""Unit tests for cytlmonitor.min_window_expression.MinWindowExpression."""

import random
import unittest

from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.min_window_expression import MinWindowExpression
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.sum_window_expression import SumWindowExpression
from cytlmonitor.window_extremum_expression import WindowExtremumExpression


class RecordingConsumer(SignalConsumer):

    def __init__(self):
        self.received = []

    def consume(self, s):
        self.received.append(s)


class Replay(StreamExpression):
    """Publishes the given segments, one for each consumed event."""

    def __init__(self, segments):
        super().__init__()
        self.segments = list(segments)
        self.events = []

    def consume(self, event):
        self.events.append(event)
        self.publish(self.segments.pop(0))


def constant(interval, value):
    return Segment(interval, Polynomial([value]))


def run(from_, to, segments):
    x = MinWindowExpression(Replay(segments), from_, to)
    c = RecordingConsumer()
    x.add(c)
    for i in range(len(segments)):
        x.consume(Event(i, Payload({})))
    return c.received


def as_tuples(segments):
    """Return (interval, value) pairs, merging adjacent segments with the
    same value: the expression publishes as soon as it can, so a constant
    stretch of the output may arrive split in several segments."""
    result = []
    for s in segments:
        value = s.polynomial.evaluate(0)
        if result and result[-1][1] == value:
            result[-1] = (result[-1][0].join(s.interval), value)
        else:
            result.append((s.interval, value))
    return result


class TestConstruction(unittest.TestCase):

    def test_is_a_stream_expression(self):
        self.assertIsInstance(MinWindowExpression(Replay([]), 0, 1), StreamExpression)

    def test_base_class_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            WindowExtremumExpression(Replay([]), 0, 1)

    def test_fields_are_stored(self):
        arg = Replay([])
        x = MinWindowExpression(arg, 1, 3)
        self.assertIs(x.arg, arg)
        self.assertEqual(x.from_, 1.0)
        self.assertEqual(x.to, 3.0)

    def test_non_expression_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            MinWindowExpression(lambda e: 1.0, 0, 1)

    def test_invalid_bounds_raise_value_error(self):
        for from_, to in ((-1, 1), (0, -1), (1, 1), (2, 1)):
            with self.subTest(from_=from_, to=to):
                with self.assertRaises(ValueError):
                    MinWindowExpression(Replay([]), from_, to)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_arg(self):
        arg = Replay([constant(Interval(0, 1), 1)])
        x = MinWindowExpression(arg, 0, 1)
        e = Event(0, Payload({}))
        x.consume(e)
        self.assertEqual(arg.events, [e])

    def test_constant_input(self):
        segments = run(0, 1, [constant(Interval(0, 4), 5)])
        self.assertEqual(as_tuples(segments), [(Interval(0, 3), 5.0)])

    def test_min_of_two_segments(self):
        # g = 5 on [0, 2), 1 on [2, 6): f(t) = 1 as soon as t + 1 >= 2.
        segments = run(0, 1, [constant(Interval(0, 2), 5), constant(Interval(2, 6), 1)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 5.0),
            (Interval(1, 5), 1.0),
        ])

    def test_dip_extends_backwards_and_forwards(self):
        # g = 7 on [0, 3), 0 on [3, 4), 7 on [4, 10): f(t) = 0 for t in [1, 4).
        segments = run(0, 2, [
            constant(Interval(0, 3), 7),
            constant(Interval(3, 4), 0),
            constant(Interval(4, 10), 7),
        ])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 7.0),
            (Interval(1, 4), 0.0),
            (Interval(4, 8), 7.0),
        ])

    def test_point_dip(self):
        segments = run(0, 1, [
            constant(Interval(0, 2), 9),
            constant(Interval.point(2), 0),
            constant(Interval(2, 5, left_open=True), 9),
        ])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 9.0),
            (Interval(1, 2, right_open=False), 0.0),
            (Interval(2, 4, left_open=True), 9.0),
        ])

    def test_unbounded_segment_publishes_up_to_infinity(self):
        segments = run(0, 1, [constant(Interval(0, 2), 1), constant(Interval(2), 3)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 2), 1.0),
            (Interval(2), 3.0),
        ])

    def test_non_constant_segment_raises_value_error(self):
        with self.assertRaises(ValueError):
            run(0, 1, [Segment(Interval(0, 2), Polynomial([0, 1]))])

    def test_gap_between_segments_raises_value_error(self):
        with self.assertRaises(ValueError):
            run(0, 1, [constant(Interval(0, 1), 1), constant(Interval(2, 3), 1)])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(1)
        for _ in range(300):
            from_ = rng.choice([0, 0.5, 1, 2])
            to = from_ + rng.choice([0.5, 1, 2.5])
            inputs, x, left_open = [], 0.0, False
            for _ in range(rng.randint(1, 8)):
                if not left_open and rng.random() < 0.25:
                    interval = Interval.point(x)
                    left_open = True
                else:
                    end = x + rng.choice([0.5, 1, 1.5, 3])
                    right_open = rng.random() < 0.6
                    interval = Interval(x, end, left_open=left_open, right_open=right_open)
                    x, left_open = end, not right_open
                inputs.append(constant(interval, rng.randint(0, 5)))
            segments = run(from_, to, inputs)

            cursor, cursor_open = 0.0, False
            for s in segments:
                self.assertEqual(s.interval.start, cursor)
                self.assertEqual(s.interval.left_open, cursor_open)
                cursor, cursor_open = s.interval.end, not s.interval.right_open
            self.assertEqual(cursor, max(0.0, inputs[-1].interval.end - to))

            for s in segments:
                i = s.interval
                for t in (i.start, i.end, (i.start + i.end) / 2):
                    if s.contains(t):
                        window = Interval(t + from_, t + to, right_open=False)
                        expected = min(g.polynomial.evaluate(0) for g in inputs
                                       if g.interval.intersect(window))
                        self.assertEqual(s.value_at(t), expected)


class TestWithSumWindowExpression(unittest.TestCase):

    def test_min_of_a_window_sum(self):
        # The sum over [t, t + 1] is 1 on [0, 1), 2 at t = 1, 1 on (1, 2],
        # 0 on (2, 4): its min over [t, t + 1] is 1 on [0, 1], 0 on (1, 3).
        inner = SumWindowExpression(lambda e: 1.0, 0, 1)
        x = MinWindowExpression(inner, 0, 1)
        c = RecordingConsumer()
        x.add(c)
        for t in (1, 2, 5):
            x.consume(Event(t, Payload({})))
        self.assertEqual(as_tuples(c.received), [
            (Interval(0, 1, right_open=False), 1.0),
            (Interval(1, 3, left_open=True), 0.0),
        ])


if __name__ == '__main__':
    unittest.main()
