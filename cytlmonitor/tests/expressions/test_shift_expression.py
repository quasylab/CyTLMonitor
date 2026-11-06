"""Unit tests for cytlmonitor.expressions.shift.ShiftExpression."""

import random
import unittest

from cytlmonitor.expressions.arithmetic import DifferenceExpression
from cytlmonitor.events.event import Event
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.payload import Payload
from cytlmonitor.core.polynomial import Polynomial
from cytlmonitor.core.segment import Segment
from cytlmonitor.expressions.shift import ShiftExpression
from cytlmonitor.consumers.signal_consumer import SignalConsumer
from cytlmonitor.expressions.base import StreamExpression
from cytlmonitor.expressions.window import SumWindowExpression


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


def run(t, batches):
    x = ShiftExpression(Replay(batches), t)
    c = RecordingConsumer()
    x.add(c)
    for i in range(len(batches)):
        x.consume(tick(i))
    return c.received


def as_tuples(segments):
    return [(s.interval, s.polynomial) for s in segments]


class TestConstruction(unittest.TestCase):

    def test_is_a_stream_expression(self):
        self.assertIsInstance(ShiftExpression(Replay([]), 1), StreamExpression)

    def test_fields_are_stored(self):
        a = Replay([])
        x = ShiftExpression(a, 2)
        self.assertIs(x.arg, a)
        self.assertEqual(x.t, 2.0)

    def test_non_expression_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            ShiftExpression(lambda e: 1.0, 1)


class TestPositiveShift(unittest.TestCase):

    def test_event_is_passed_to_arg(self):
        a = Replay([])
        x = ShiftExpression(a, 1)
        e = tick(1)
        x.consume(e)
        self.assertEqual(a.events, [e])

    def test_nothing_is_published_before_arg_publishes(self):
        self.assertEqual(run(1, [[]]), [])

    def test_zero_segment_precedes_the_first_segment(self):
        segments = run(2, [[segment(Interval(0, 3), 5)]])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 2), Polynomial.ZERO),
            (Interval(2, 5), Polynomial([5])),
        ])

    def test_zero_segment_is_published_only_once(self):
        a = Replay([[segment(Interval(0, 1), 1)], [segment(Interval(1, 2), 2)]])
        x = ShiftExpression(a, 3)
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick(0))
        self.assertEqual(as_tuples(c.received), [
            (Interval(0, 3), Polynomial.ZERO),
            (Interval(3, 4), Polynomial([1])),
        ])
        x.consume(tick(1))
        self.assertEqual(as_tuples(c.received)[2:], [(Interval(4, 5), Polynomial([2]))])

    def test_zero_segment_includes_shift_when_first_segment_is_left_open(self):
        segments = run(2, [[segment(Interval(0, 3, left_open=True), 5)]])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 2, right_open=False), Polynomial.ZERO),
            (Interval(2, 5, left_open=True), Polynomial([5])),
        ])

    def test_polynomial_is_shifted_with_its_segment(self):
        # g(x) = x on [0, 2): shifted by 1, f(x) = x - 1 on [1, 3).
        segments = run(1, [[segment(Interval(0, 2), 0, 1)]])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), Polynomial.ZERO),
            (Interval(1, 3), Polynomial([-1, 1])),
        ])

    def test_unbounded_segment(self):
        segments = run(1, [[segment(Interval(0), 4)]])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), Polynomial.ZERO),
            (Interval(1), Polynomial([4])),
        ])


class TestZeroShift(unittest.TestCase):

    def test_segments_are_unchanged_and_no_zero_segment_is_added(self):
        inputs = [segment(Interval(0, 2), 0, 1), segment(Interval(2, 5), 3)]
        self.assertEqual(as_tuples(run(0, [inputs])), as_tuples(inputs))


class TestNegativeShift(unittest.TestCase):

    def test_no_zero_segment_is_added(self):
        segments = run(-1, [[segment(Interval(0, 3), 5)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([5]))])

    def test_segments_before_zero_are_dropped(self):
        segments = run(-3, [[segment(Interval(0, 2), 1), segment(Interval(2, 5), 2)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([2]))])

    def test_segment_ending_open_at_zero_is_dropped(self):
        segments = run(-2, [[segment(Interval(0, 2), 1), segment(Interval(2, 5), 2)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 3), Polynomial([2]))])

    def test_segment_ending_closed_at_zero_leaves_a_point(self):
        segments = run(-2, [[segment(Interval(0, 2, right_open=False), 1),
                             segment(Interval(2, 5, left_open=True), 2)]])
        self.assertEqual(as_tuples(segments), [
            (Interval.point(0), Polynomial([1])),
            (Interval(0, 3, left_open=True), Polynomial([2])),
        ])

    def test_polynomial_is_shifted_back(self):
        # g(x) = x on [0, 4): shifted by -1, f(x) = x + 1 on [0, 3).
        segments = run(-1, [[segment(Interval(0, 4), 0, 1)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 3), Polynomial([1, 1]))])


class TestDefinition(unittest.TestCase):

    def test_matches_definition_on_random_signals(self):
        rng = random.Random(0)
        for _ in range(300):
            inputs, x, left_open = [], 0.0, False
            for _ in range(rng.randint(1, 6)):
                if not left_open and rng.random() < 0.2:
                    interval = Interval.point(x)
                    left_open = True
                else:
                    end = x + rng.choice([0.5, 1, 2])
                    right_open = rng.random() < 0.6
                    interval = Interval(x, end, left_open=left_open, right_open=right_open)
                    x, left_open = end, not right_open
                coefficients = [rng.randint(-3, 3) for _ in range(rng.randint(1, 3))]
                inputs.append(Segment(interval, Polynomial(coefficients)))
            t = rng.choice([-3, -1.5, -0.5, 0, 0.5, 1, 2.5])
            segments = run(t, [inputs])

            last = inputs[-1].interval
            if last.end + t < 0 or (last.end + t == 0 and last.right_open):
                self.assertEqual(segments, [])
                continue

            cursor, cursor_open = 0.0, False
            for s in segments:
                self.assertEqual(s.interval.start, cursor)
                self.assertEqual(s.interval.left_open, cursor_open)
                cursor, cursor_open = s.interval.end, not s.interval.right_open
            self.assertEqual(cursor, last.end + t)

            for s in segments:
                i = s.interval
                for x in (i.start, i.end, (i.start + i.end) / 2):
                    if s.contains(x):
                        source = [g for g in inputs if g.contains(x - t)]
                        expected = source[0].value_at(x - t) if source else 0.0
                        self.assertAlmostEqual(s.value_at(x), expected)


class TestComposition(unittest.TestCase):

    def test_change_over_one_time_unit(self):
        # g(x) - g(x - 1) with g = 1 on [0, 2), 4 on [2, 5).
        g = [segment(Interval(0, 2), 1), segment(Interval(2, 5), 4)]
        x = DifferenceExpression(Replay([g]), ShiftExpression(Replay([g]), 1))
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick())
        values = [(s.interval, s.polynomial.evaluate(0)) for s in c.received]
        self.assertEqual(values, [
            (Interval(0, 1), 1.0),
            (Interval(1, 2), 0.0),
            (Interval(2, 3), 3.0),
            (Interval(3, 5), 0.0),
        ])

    def test_shifted_window_sum(self):
        x = ShiftExpression(SumWindowExpression(lambda e: e['v'], 0, 1), 2)
        c = RecordingConsumer()
        x.add(c)
        for t, v in ((1, 4), (5, 0)):
            x.consume(Event(t, Payload({'v': v})))
        values = [(s.interval, s.polynomial.evaluate(0)) for s in c.received]
        self.assertEqual(values, [
            (Interval(0, 2), 0.0),
            (Interval(2, 3, right_open=False), 4.0),
            (Interval(3, 6, left_open=True), 0.0),
        ])



def assert_contiguous(test, segments):
    """The segments start at 0 and each continues where the previous ends,
    with exactly one of the two containing the shared point."""
    test.assertEqual(segments[0].interval.start, 0.0)
    test.assertFalse(segments[0].interval.left_open)
    for a, b in zip(segments, segments[1:]):
        test.assertEqual(a.interval.end, b.interval.start, (a, b))
        test.assertNotEqual(a.interval.right_open, b.interval.left_open, (a, b))


class TestRounding(unittest.TestCase):
    """Shifting adds ``t`` to both ends of each interval, and rounding can
    make a very short interval empty."""

    sliver = Interval(0.3, 0.30000000000000004, left_open=True)

    def test_interval_emptied_by_rounding_is_dropped(self):
        out = run(10, [[segment(Interval(0, 0.3, right_open=False), 1),
                        segment(self.sliver, 2),
                        segment(Interval(0.30000000000000004, 1), 3)]])
        self.assertEqual(as_tuples(out), [
            (Interval(0, 10), Polynomial([0])),
            (Interval(10, 10.3, right_open=False), Polynomial([1]).shift(10)),
            (Interval(10.3, 11, left_open=True), Polynomial([3]).shift(10)),
        ])

    def test_neighbours_of_a_dropped_interval_do_not_overlap(self):
        # Without the sliver, [.., 10.3] and [10.3, ..) would both hold 10.3.
        out = run(10, [[segment(Interval(0, 0.3, right_open=False), 1)],
                       [segment(self.sliver, 2)],
                       [segment(Interval(0.30000000000000004, 1), 3)]])
        assert_contiguous(self, out)

    def test_point_emptied_by_its_open_neighbour_is_kept_once(self):
        # [0, 0.3) then the sliver [0.3, 0.30000000000000004) then the rest:
        # the point 10.3 belongs to the segment after the dropped one.
        out = run(10, [[segment(Interval(0, 0.3), 1),
                        segment(Interval(0.3, 0.30000000000000004), 2),
                        segment(Interval(0.30000000000000004, 1), 3)]])
        assert_contiguous(self, out)
        self.assertEqual(out[-1].interval, Interval(10.3, 11))

    def test_window_sum_over_tenths_of_a_second(self):
        # Events every 0.1 s make the window sum publish very short
        # segments; shifting them by 10 used to raise a ValueError.
        x = ShiftExpression(SumWindowExpression(lambda e: 1.0, 0, 10), 10)
        c = RecordingConsumer()
        x.add(c)
        for k in range(3000):
            x.consume(tick(k / 10))
        assert_contiguous(self, c.received)
        self.assertGreater(c.received[-1].interval.end, 299)
        # With an event every 0.1 s, a 10 s window holds 100 or 101.
        for s in c.received:
            if s.interval.start >= 10:
                self.assertIn(s.polynomial.coefficients[0], (100.0, 101.0), s)


if __name__ == '__main__':
    unittest.main()
