"""Unit tests for cytlmonitor.max_window_expression.MaxWindowExpression."""

import random
import unittest

from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.max_window_expression import MaxWindowExpression
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.sum_window_expression import SumWindowExpression


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
    x = MaxWindowExpression(Replay(segments), from_, to)
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
        self.assertIsInstance(MaxWindowExpression(Replay([]), 0, 1), StreamExpression)

    def test_fields_are_stored(self):
        arg = Replay([])
        x = MaxWindowExpression(arg, 1, 3)
        self.assertIs(x.arg, arg)
        self.assertEqual(x.from_, 1.0)
        self.assertEqual(x.to, 3.0)

    def test_non_expression_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            MaxWindowExpression(lambda e: 1.0, 0, 1)

    def test_negative_from_raises_value_error(self):
        with self.assertRaises(ValueError):
            MaxWindowExpression(Replay([]), -1, 1)

    def test_negative_to_raises_value_error(self):
        with self.assertRaises(ValueError):
            MaxWindowExpression(Replay([]), 0, -1)

    def test_from_equal_to_to_raises_value_error(self):
        with self.assertRaises(ValueError):
            MaxWindowExpression(Replay([]), 1, 1)

    def test_from_greater_than_to_raises_value_error(self):
        with self.assertRaises(ValueError):
            MaxWindowExpression(Replay([]), 2, 1)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_arg(self):
        arg = Replay([constant(Interval(0, 1), 1)])
        x = MaxWindowExpression(arg, 0, 1)
        e = Event(0, Payload({}))
        x.consume(e)
        self.assertEqual(arg.events, [e])

    def test_nothing_is_published_until_window_is_covered(self):
        self.assertEqual(run(0, 2, [constant(Interval(0, 1), 5)]), [])

    def test_constant_input(self):
        segments = run(0, 1, [constant(Interval(0, 4), 5)])
        self.assertEqual(as_tuples(segments), [(Interval(0, 3), 5.0)])

    def test_max_of_two_segments(self):
        # g = 1 on [0, 2), 5 on [2, 6): f(t) = 5 as soon as t + 1 >= 2.
        segments = run(0, 1, [constant(Interval(0, 2), 1), constant(Interval(2, 6), 5)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 1.0),
            (Interval(1, 5), 5.0),
        ])

    def test_peak_extends_backwards_and_forwards(self):
        # g = 0 on [0, 3), 7 on [3, 4), 0 on [4, 10): f(t) = 7 for t in [1, 4).
        segments = run(0, 2, [
            constant(Interval(0, 3), 0),
            constant(Interval(3, 4), 7),
            constant(Interval(4, 10), 0),
        ])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 0.0),
            (Interval(1, 4), 7.0),
            (Interval(4, 8), 0.0),
        ])

    def test_from_shifts_the_window(self):
        # Window [t + 1, t + 2] meets [3, 4) for t in [1, 3).
        segments = run(1, 2, [
            constant(Interval(0, 3), 0),
            constant(Interval(3, 4), 7),
            constant(Interval(4, 10), 0),
        ])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 0.0),
            (Interval(1, 3), 7.0),
            (Interval(3, 8), 0.0),
        ])

    def test_point_peak(self):
        segments = run(0, 1, [
            constant(Interval(0, 2), 0),
            constant(Interval.point(2), 9),
            constant(Interval(2, 5, left_open=True), 0),
        ])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 0.0),
            (Interval(1, 2, right_open=False), 9.0),
            (Interval(2, 4, left_open=True), 0.0),
        ])

    def test_unbounded_segment_publishes_up_to_infinity(self):
        segments = run(0, 1, [constant(Interval(0, 2), 3), constant(Interval(2), 1)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 2), 3.0),
            (Interval(2), 1.0),
        ])

    def test_non_constant_segment_raises_value_error(self):
        with self.assertRaises(ValueError):
            run(0, 1, [Segment(Interval(0, 2), Polynomial([0, 1]))])

    def test_segment_not_starting_at_zero_raises_value_error(self):
        with self.assertRaises(ValueError):
            run(0, 1, [constant(Interval(1, 2), 1)])

    def test_gap_between_segments_raises_value_error(self):
        with self.assertRaises(ValueError):
            run(0, 1, [constant(Interval(0, 1), 1), constant(Interval(2, 3), 1)])

    def test_overlapping_endpoint_raises_value_error(self):
        with self.assertRaises(ValueError):
            run(0, 1, [constant(Interval(0, 1, right_open=False), 1),
                       constant(Interval(1, 3), 1)])

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)
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
                        expected = max(g.polynomial.evaluate(0) for g in inputs
                                       if g.interval.intersect(window))
                        self.assertEqual(s.value_at(t), expected)


class TestWithSumWindowExpression(unittest.TestCase):

    def test_max_of_a_window_sum(self):
        # The sum over [t, t + 1] is 1 on [0, 1], 2 at t = 1 (events at 1
        # and 2 both in [1, 2]), 1 on (1, 2], 0 on (2, 4).
        inner = SumWindowExpression(lambda e: 1.0, 0, 1)
        x = MaxWindowExpression(inner, 0, 1)
        c = RecordingConsumer()
        x.add(c)
        for t in (1, 2, 5):
            x.consume(Event(t, Payload({})))
        self.assertEqual(as_tuples(c.received), [
            (Interval(0, 1, right_open=False), 2.0),
            (Interval(1, 2, left_open=True, right_open=False), 1.0),
            (Interval(2, 3, left_open=True), 0.0),
        ])


if __name__ == '__main__':
    unittest.main()
