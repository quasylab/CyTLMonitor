"""Unit tests for cytlmonitor.negation_expression.NegationExpression."""

import unittest

from cytlmonitor.difference_expression import DifferenceExpression
from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.negation_expression import NegationExpression
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


def run(batches):
    x = NegationExpression(Replay(batches))
    c = RecordingConsumer()
    x.add(c)
    for i in range(len(batches)):
        x.consume(tick(i))
    return c.received


def as_tuples(segments):
    return [(s.interval, s.polynomial) for s in segments]


class TestConstruction(unittest.TestCase):

    def test_is_a_stream_expression(self):
        self.assertIsInstance(NegationExpression(Replay([])), StreamExpression)

    def test_arg_is_stored(self):
        a = Replay([])
        self.assertIs(NegationExpression(a).arg, a)

    def test_non_expression_arg_raises_type_error(self):
        with self.assertRaises(TypeError):
            NegationExpression(lambda e: 1.0)


class TestConsume(unittest.TestCase):

    def test_event_is_passed_to_arg(self):
        a = Replay([])
        x = NegationExpression(a)
        e = tick(1)
        x.consume(e)
        self.assertEqual(a.events, [e])

    def test_constant_is_negated(self):
        segments = run([[constant(Interval(0, 2), 3)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([-3]))])

    def test_zero_stays_zero(self):
        segments = run([[constant(Interval(0, 2), 0)]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial.ZERO)])

    def test_polynomial_is_negated(self):
        segments = run([[Segment(Interval(0, 2), Polynomial([1, -2, 3]))]])
        self.assertEqual(as_tuples(segments), [(Interval(0, 2), Polynomial([-1, 2, -3]))])

    def test_each_segment_is_published_at_once_with_its_interval(self):
        a = Replay([[constant(Interval(0, 1), 1)],
                    [constant(Interval.point(1), 2),
                     constant(Interval(1, None, left_open=True), 3)]])
        x = NegationExpression(a)
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick(0))
        self.assertEqual(as_tuples(c.received), [(Interval(0, 1), Polynomial([-1]))])
        x.consume(tick(1))
        self.assertEqual(as_tuples(c.received)[1:], [
            (Interval.point(1), Polynomial([-2])),
            (Interval(1, None, left_open=True), Polynomial([-3])),
        ])

    def test_double_negation_gives_the_original_signal(self):
        segments = [constant(Interval(0, 1), 4), Segment(Interval(1, 3), Polynomial([1, 2]))]
        x = NegationExpression(NegationExpression(Replay([segments])))
        c = RecordingConsumer()
        x.add(c)
        x.consume(tick())
        self.assertEqual(as_tuples(c.received), as_tuples(segments))


class TestComposition(unittest.TestCase):

    def test_sum_with_negation_is_a_difference(self):
        g1 = [constant(Interval(0, 2), 5), constant(Interval(2, 4), 1)]
        g2 = [constant(Interval(0, 1), 2), constant(Interval(1, 4), 3)]
        plus = SumExpression(Replay([g1]), NegationExpression(Replay([g2])))
        minus = DifferenceExpression(Replay([g1]), Replay([g2]))
        received = []
        for x in (plus, minus):
            c = RecordingConsumer()
            x.add(c)
            x.consume(tick())
            received.append(as_tuples(c.received))
        self.assertEqual(received[0], received[1])

    def test_negated_window_sum(self):
        x = NegationExpression(SumWindowExpression(lambda e: e['v'], 0, 1))
        c = RecordingConsumer()
        x.add(c)
        for t, v in ((1, 4), (5, 0)):
            x.consume(Event(t, Payload({'v': v})))
        values = [(s.interval, s.polynomial.evaluate(0)) for s in c.received]
        self.assertEqual(values, [
            (Interval(0, 1, right_open=False), -4.0),
            (Interval(1, 4, left_open=True), 0.0),
        ])


if __name__ == '__main__':
    unittest.main()
