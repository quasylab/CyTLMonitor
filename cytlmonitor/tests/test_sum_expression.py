"""Unit tests for cytlmonitor.sum_expression.SumExpression."""

import random
import unittest

from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.sum_expression import SumExpression
from cytlmonitor.sum_window_expression import SumWindowExpression


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


def constant(interval, value):
    return Segment(interval, Polynomial([value]))


def tick(t=0):
    return Event(t, Payload({}))


def run(batches1, batches2):
    x = SumExpression(Replay(batches1), Replay(batches2))
    c = RecordingConsumer()
    x.add(c)
    for i in range(max(len(batches1), len(batches2))):
        x.consume(tick(i))
    return c.received


def as_tuples(segments):
    return [(s.interval, s.polynomial) for s in segments]


class TestConstruction(unittest.TestCase):

    def test_is_a_stream_expression(self):
        self.assertIsInstance(SumExpression(Replay([]), Replay([])), StreamExpression)

    def test_fields_are_stored(self):
        a, b = Replay([]), Replay([])
        x = SumExpression(a, b)
        self.assertIs(x.arg1, a)
        self.assertIs(x.arg2, b)

    def test_non_expression_args_raise_type_error(self):
        with self.assertRaises(TypeError):
            SumExpression(lambda e: 1.0, Replay([]))
        with self.assertRaises(TypeError):
            SumExpression(Replay([]), None)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_both_args(self):
        a, b = Replay([]), Replay([])
        x = SumExpression(a, b)
        e = tick(1)
        x.consume(e)
        self.assertEqual(a.events, [e])
        self.assertEqual(b.events, [e])

    def test_same_arg_receives_event_once_and_is_doubled(self):
        a = Replay([[constant(Interval(0, 2), 3)]])
        x = SumExpression(a, a)
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick())
        self.assertEqual(len(a.events), 1)
        self.assertEqual(as_tuples(c.received), [(Interval(0, 2), Polynomial([6]))])

    def test_nothing_is_published_until_both_sides_cover(self):
        self.assertEqual(run([[constant(Interval(0, 2), 1)]], [[]]), [])

    def test_identical_boundaries(self):
        segments = run([[constant(Interval(0, 2), 1)]], [[constant(Interval(0, 2), 4)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([5]))])

    def test_different_boundaries_are_aligned(self):
        segments = run(
            [[constant(Interval(0, 3), 1), constant(Interval(3, 5), 2)]],
            [[constant(Interval(0, 1), 10), constant(Interval(1, 5), 20)]],
        )
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), Polynomial([11])),
            (Interval(1, 3), Polynomial([21])),
            (Interval(3, 5), Polynomial([22])),
        ])

    def test_waits_for_the_slower_side(self):
        a = Replay([[constant(Interval(0, 4), 1)], []])
        b = Replay([[constant(Interval(0, 1), 10)], [constant(Interval(1, 4), 20)]])
        x = SumExpression(a, b)
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick(0))
        self.assertEqual(as_tuples(c.received), [(Interval(0, 1), Polynomial([11]))])
        x.consume(tick(1))
        self.assertEqual(as_tuples(c.received)[1:], [(Interval(1, 4), Polynomial([21]))])

    def test_same_end_with_different_closure_leaves_a_point(self):
        segments = run(
            [[constant(Interval(0, 2, right_open=False), 1),
              constant(Interval(2, 4, left_open=True), 2)]],
            [[constant(Interval(0, 2), 10), constant(Interval(2, 4), 20)]],
        )
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 2), Polynomial([11])),
            (Interval.point(2), Polynomial([21])),
            (Interval(2, 4, left_open=True), Polynomial([22])),
        ])

    def test_polynomials_are_added(self):
        segments = run(
            [[Segment(Interval(0, 2), Polynomial([1, 2]))]],
            [[Segment(Interval(0, 2), Polynomial([0, 1, 3]))]],
        )
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([1, 3, 3]))])

    def test_unbounded_segments(self):
        segments = run(
            [[constant(Interval(0), 1)]],
            [[constant(Interval(0, 2), 10), constant(Interval(2), 20)]],
        )
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 2), Polynomial([11])),
            (Interval(2), Polynomial([21])),
        ])

    def test_segment_not_starting_at_zero_raises_value_error(self):
        with self.assertRaises(ValueError):
            run([[constant(Interval(1, 2), 1)]], [[]])

    def test_gap_between_segments_raises_value_error(self):
        with self.assertRaises(ValueError):
            run([[constant(Interval(0, 1), 1), constant(Interval(2, 3), 1)]], [[]])

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

        for _ in range(300):
            g1, g2 = random_signal(6), random_signal(6)
            n = rng.randint(1, 5)
            segments = run(random_batches(g1, n), random_batches(g2, n))

            cursor, cursor_open = 0.0, False
            for s in segments:
                self.assertEqual(s.interval.start, cursor)
                self.assertEqual(s.interval.left_open, cursor_open)
                cursor, cursor_open = s.interval.end, not s.interval.right_open
            self.assertEqual(cursor, 6.0)

            def at(signal, t):
                return next(s.value_at(t) for s in signal if s.contains(t))

            for s in segments:
                i = s.interval
                for t in (i.start, i.end, (i.start + i.end) / 2):
                    if s.contains(t):
                        self.assertAlmostEqual(s.value_at(t), at(g1, t) + at(g2, t))


class TestWithSumWindowExpression(unittest.TestCase):

    def test_sum_of_two_window_sums(self):
        # w1 counts events in [t, t + 1], w2 events in [t + 1, t + 2].
        w1 = SumWindowExpression(lambda e: 1.0, 0, 1)
        w2 = SumWindowExpression(lambda e: 1.0, 1, 2)
        x = SumExpression(w1, w2)
        c = RecordingConsumer()
        x.add(c)
        for t in (2, 6):
            x.consume(tick(t))
        # w1 is 1 on [1, 2], w2 is 1 on [0, 1]; w2 is only known up to 4.
        values = [(s.interval, s.polynomial.evaluate(0)) for s in c.received]
        self.assertEqual(values, [
            (Interval(0, 1), 1.0),
            (Interval.point(1), 2.0),
            (Interval(1, 2, left_open=True, right_open=False), 1.0),
            (Interval(2, 4, left_open=True), 0.0),
        ])


if __name__ == '__main__':
    unittest.main()
