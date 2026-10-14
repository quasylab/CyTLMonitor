"""Unit tests for cytlmonitor.boolean_signal_consumer.BooleanSignalConsumer."""

import unittest

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.interval import Interval


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.received = []
        self.horizons = []

    def consume(self, i):
        self.received.append(i)

    def set_horizon(self, t):
        self.horizons.append(t)


class TestBooleanSignalConsumer(unittest.TestCase):

    def test_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            BooleanSignalConsumer()

    def test_subclass_without_consume_cannot_be_instantiated(self):
        class Incomplete(BooleanSignalConsumer):
            def set_horizon(self, t):
                pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_subclass_without_set_horizon_cannot_be_instantiated(self):
        class Incomplete(BooleanSignalConsumer):
            def consume(self, i):
                pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_subclass_implementing_set_horizon_receives_horizons(self):
        c = RecordingConsumer()
        c.consume(Interval(0, 1))
        self.assertIsNone(c.set_horizon(1.0))
        c.set_horizon(4.0)
        self.assertEqual(c.horizons, [1.0, 4.0])

    def test_subclass_implementing_consume_receives_intervals(self):
        c = RecordingConsumer()
        i1, i2 = Interval(0, 1), Interval(2, 3)
        self.assertIsNone(c.consume(i1))
        c.consume(i2)
        self.assertEqual(c.received, [i1, i2])
        self.assertTrue(i1.is_before(i2))


if __name__ == '__main__':
    unittest.main()
