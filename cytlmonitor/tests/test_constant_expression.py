"""Unit tests for cytlmonitor.constant_expression.ConstantExpression."""

import unittest

from cytlmonitor.atomic_greater_monitor import AtomicGreaterMonitor
from cytlmonitor.boolean_signal import BooleanSignal
from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.constant_expression import ConstantExpression
from cytlmonitor.event import Event
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression
from cytlmonitor.sum_window_expression import SumWindowExpression


class RecordingConsumer(SignalConsumer):

    def __init__(self):
        self.received = []

    def consume(self, s):
        self.received.append(s)


class RecordingBooleanConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.received = []
        self.horizons = []

    def consume(self, i):
        self.received.append(i)

    def set_horizon(self, t):
        self.horizons.append(t)


def event(t):
    return Event(t, Payload({}))


def run(value, times):
    x = ConstantExpression(value)
    c = RecordingConsumer()
    x.add(c)
    for t in times:
        x.consume(event(t))
    return [(s.interval, s.polynomial) for s in c.received]


class TestConstantExpression(unittest.TestCase):

    def test_is_a_stream_expression(self):
        self.assertIsInstance(ConstantExpression(1), StreamExpression)

    def test_value_is_stored_as_float(self):
        x = ConstantExpression(3)
        self.assertEqual(x.value, 3.0)
        self.assertIsInstance(x.value, float)

    def test_no_events_publishes_nothing(self):
        self.assertEqual(run(5, []), [])

    def test_each_event_publishes_up_to_its_time(self):
        self.assertEqual(run(5, [1, 2.5, 4]), [
            (Interval(0, 1), Polynomial([5])),
            (Interval(1, 2.5), Polynomial([5])),
            (Interval(2.5, 4), Polynomial([5])),
        ])

    def test_events_at_the_same_time_publish_once(self):
        self.assertEqual(run(2, [0, 1, 1, 3]), [
            (Interval(0, 1), Polynomial([2])),
            (Interval(1, 3), Polynomial([2])),
        ])

    def test_out_of_order_event_raises_value_error(self):
        x = ConstantExpression(1)
        x.consume(event(2))
        with self.assertRaises(ValueError):
            x.consume(event(1))

    def test_non_event_raises_type_error(self):
        with self.assertRaises(TypeError):
            ConstantExpression(1).consume(1.0)

    def test_as_a_threshold(self):
        # More than one event in [t, t + 1]: events at 1 and 1.5.
        count = SumWindowExpression(lambda e: 1.0, 0, 1)
        m = AtomicGreaterMonitor(count, ConstantExpression(1))
        c = RecordingBooleanConsumer()
        m.add(c)
        for t in (1, 1.5, 5):
            m.consume(event(t))
        self.assertEqual(list(BooleanSignal(c.received)), [Interval(0.5, 1, right_open=False)])


if __name__ == '__main__':
    unittest.main()
