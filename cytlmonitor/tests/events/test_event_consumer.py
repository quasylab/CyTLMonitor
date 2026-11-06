"""Unit tests for cytlmonitor.events.consumer.EventConsumer."""

import unittest

from cytlmonitor.events.event import Event
from cytlmonitor.events.consumer import EventConsumer
from cytlmonitor.events.payload import Payload


class RecordingConsumer(EventConsumer):

    def __init__(self):
        self.received = []

    def consume(self, event):
        self.received.append(event)


class TestEventConsumer(unittest.TestCase):

    def test_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            EventConsumer()

    def test_subclass_without_consume_cannot_be_instantiated(self):
        class Incomplete(EventConsumer):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_subclass_implementing_consume_receives_events(self):
        c = RecordingConsumer()
        e = Event(1.0, Payload({'a': 1}))
        self.assertIsNone(c.consume(e))
        self.assertEqual(c.received, [e])


if __name__ == '__main__':
    unittest.main()
