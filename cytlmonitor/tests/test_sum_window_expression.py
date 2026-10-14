"""Unit tests for cytlmonitor.sum_window_expression.SumWindowExpression."""

import random
import unittest

from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.measure import Measure
from cytlmonitor.payload import Payload
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.sum_window_expression import SumWindowExpression


class RecordingConsumer(SignalConsumer):

    def __init__(self):
        self.received = []

    def consume(self, s):
        self.received.append(s)


def value(e):
    return e['v']


def event(t, v=1):
    return Event(t, Payload({'v': v}))


def run(from_, to, events, w=value):
    x = SumWindowExpression(w, from_, to)
    c = RecordingConsumer()
    x.add(c)
    for e in events:
        x.consume(e)
    return c.received


def as_tuples(segments):
    return [(s.interval, s.polynomial.evaluate(0)) for s in segments]


class TestConstruction(unittest.TestCase):

    def test_is_a_stream_expression(self):
        self.assertIsInstance(SumWindowExpression(value, 0, 1), StreamExpression)

    def test_fields_are_stored(self):
        x = SumWindowExpression(value, 1, 3)
        self.assertIs(x.w, value)
        self.assertEqual(x.from_, 1.0)
        self.assertEqual(x.to, 3.0)

    def test_accepts_a_measure(self):
        segments = run(0, 1, [event(0.5, 4), event(3)], w=Measure(value))
        self.assertEqual(segments[0].value_at(0), 4.0)

    def test_non_callable_raises_type_error(self):
        with self.assertRaises(TypeError):
            SumWindowExpression(42, 0, 1)

    def test_negative_from_raises_value_error(self):
        with self.assertRaises(ValueError):
            SumWindowExpression(value, -1, 1)

    def test_negative_to_raises_value_error(self):
        with self.assertRaises(ValueError):
            SumWindowExpression(value, 0, -1)

    def test_from_equal_to_to_raises_value_error(self):
        with self.assertRaises(ValueError):
            SumWindowExpression(value, 1, 1)

    def test_from_greater_than_to_raises_value_error(self):
        with self.assertRaises(ValueError):
            SumWindowExpression(value, 2, 1)


class TestConsume(unittest.TestCase):

    def test_no_events_publishes_nothing(self):
        self.assertEqual(run(0, 1, []), [])

    def test_non_event_raises_type_error(self):
        with self.assertRaises(TypeError):
            SumWindowExpression(value, 0, 1).consume(1.0)

    def test_out_of_order_event_raises_value_error(self):
        x = SumWindowExpression(value, 0, 1)
        x.consume(event(2))
        with self.assertRaises(ValueError):
            x.consume(event(1))

    def test_signal_is_published_up_to_last_time_minus_to(self):
        segments = run(0, 1, [event(5)])
        self.assertEqual(as_tuples(segments), [(Interval(0, 4), 0.0)])

    def test_single_event_window(self):
        # Event at 3 counts for t in [3 - 2, 3 - 1] = [1, 2].
        segments = run(1, 2, [event(3, 10), event(10)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 0.0),
            (Interval(1, 2, right_open=False), 10.0),
            (Interval(2, 8, left_open=True), 0.0),
        ])

    def test_overlapping_events_are_summed(self):
        segments = run(0, 2, [event(2, 1), event(3, 10), event(10)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 1.0),
            (Interval(1, 2, right_open=False), 11.0),
            (Interval(2, 3, left_open=True, right_open=False), 10.0),
            (Interval(3, 8, left_open=True), 0.0),
        ])

    def test_events_with_the_same_time_enter_and_leave_together(self):
        segments = run(1, 2, [event(3, 1), event(3, 2), event(10)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1), 0.0),
            (Interval(1, 2, right_open=False), 3.0),
            (Interval(2, 8, left_open=True), 0.0),
        ])

    def test_event_already_in_window_at_time_zero(self):
        # Event at 1 counts for t in [-1, 1]: from 0 it is already there.
        segments = run(0, 2, [event(1, 5), event(10)])
        self.assertEqual(as_tuples(segments), [
            (Interval(0, 1, right_open=False), 5.0),
            (Interval(1, 8, left_open=True), 0.0),
        ])

    def test_event_leaving_at_time_zero_gives_a_point_segment(self):
        segments = run(1, 2, [event(1, 5), event(10)])
        self.assertEqual(as_tuples(segments), [
            (Interval.point(0), 5.0),
            (Interval(0, 8, left_open=True), 0.0),
        ])

    def test_event_before_from_is_ignored(self):
        segments = run(1, 2, [event(0.5, 5), event(10)])
        self.assertEqual(as_tuples(segments), [(Interval(0, 8), 0.0)])

    def test_matches_definition_on_random_streams(self):
        rng = random.Random(0)
        for _ in range(200):
            from_ = rng.choice([0, 0.5, 1, 2])
            to = from_ + rng.choice([0.5, 1, 3])
            times = sorted(rng.choice([0, 0.5, 1, 1.5, 2, 3, 4, 5, 7])
                           for _ in range(rng.randint(0, 8)))
            events = [event(t, rng.randint(1, 5)) for t in times]
            segments = run(from_, to, events)

            cursor, left_open = 0.0, False
            for s in segments:
                self.assertEqual(s.interval.start, cursor)
                self.assertEqual(s.interval.left_open, left_open)
                cursor, left_open = s.interval.end, not s.interval.right_open
            if events:
                self.assertEqual(cursor, max(0.0, events[-1].time - to))

            for s in segments:
                i = s.interval
                for t in (i.start, i.end, (i.start + i.end) / 2):
                    if s.contains(t):
                        expected = sum(e['v'] for e in events
                                       if t + from_ <= e.time <= t + to)
                        self.assertEqual(s.value_at(t), expected)


if __name__ == '__main__':
    unittest.main()
