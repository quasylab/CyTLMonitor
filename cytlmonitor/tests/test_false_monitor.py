"""Unit tests for cytlmonitor.false_monitor.FalseMonitor."""

import unittest

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.false_monitor import FalseMonitor
from cytlmonitor.payload import Payload


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.received = []
        self.horizons = []

    def consume(self, i):
        self.received.append(i)

    def set_horizon(self, t):
        self.horizons.append(t)


def event(t):
    return Event(t, Payload({}))


class TestFalseMonitor(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(FalseMonitor(), EventMonitor)

    def test_last_is_initially_zero(self):
        self.assertEqual(FalseMonitor()._last, 0.0)

    def test_nothing_is_ever_published(self):
        m = FalseMonitor()
        c = RecordingConsumer()
        m.add(c)
        for t in (0, 1, 1, 2.5, 4):
            m.consume(event(t))
        self.assertEqual(c.received, [])

    def test_each_event_sets_the_horizon_of_every_consumer(self):
        m = FalseMonitor()
        a, b = RecordingConsumer(), RecordingConsumer()
        m.add(a)
        m.add(b)
        for t in (0, 1, 1, 2.5, 4):
            m.consume(event(t))
        self.assertEqual(a.horizons, [0.0, 1.0, 1.0, 2.5, 4.0])
        self.assertEqual(b.horizons, a.horizons)

    def test_no_consumers_is_fine(self):
        FalseMonitor().consume(event(1))

    def test_out_of_order_event_does_not_set_the_horizon(self):
        m = FalseMonitor()
        c = RecordingConsumer()
        m.add(c)
        m.consume(event(2))
        with self.assertRaises(ValueError):
            m.consume(event(1))
        self.assertEqual(c.horizons, [2.0])

    def test_consume_updates_last(self):
        m = FalseMonitor()
        m.consume(event(2))
        self.assertEqual(m._last, 2.0)

    def test_out_of_order_event_raises_value_error(self):
        m = FalseMonitor()
        m.consume(event(2))
        with self.assertRaises(ValueError):
            m.consume(event(1))

    def test_non_event_raises_type_error(self):
        with self.assertRaises(TypeError):
            FalseMonitor().consume(1.0)


if __name__ == '__main__':
    unittest.main()
