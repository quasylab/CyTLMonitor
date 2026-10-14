"""Unit tests for cytlmonitor.signal_consumer.SignalConsumer."""

import unittest

from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer


class RecordingConsumer(SignalConsumer):

    def __init__(self):
        self.received = []

    def consume(self, s):
        self.received.append(s)


class TestSignalConsumer(unittest.TestCase):

    def test_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            SignalConsumer()

    def test_subclass_without_consume_cannot_be_instantiated(self):
        class Incomplete(SignalConsumer):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_subclass_implementing_consume_receives_segments(self):
        c = RecordingConsumer()
        s = Segment(Interval(0, 1), Polynomial([2]))
        self.assertIsNone(c.consume(s))
        self.assertEqual(c.received, [s])


if __name__ == '__main__':
    unittest.main()
