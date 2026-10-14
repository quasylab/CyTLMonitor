"""Unit tests for cytlmonitor.stream_expression.StreamExpression."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression


class RecordingConsumer(SignalConsumer):

    def __init__(self, log=None, name=None):
        self.received = []
        self.log = log
        self.name = name

    def consume(self, s):
        self.received.append(s)
        if self.log is not None:
            self.log.append(self.name)


class ConstantExpression(StreamExpression):
    """Publishes, for each event, a constant segment holding the event's
    'value' field from the event's time onwards."""

    def consume(self, event):
        self.publish(Segment(Interval(event.time), Polynomial([event['value']])))


def segment(start, end, value):
    return Segment(Interval(start, end), Polynomial([value]))


class TestAbstractness(unittest.TestCase):

    def test_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            StreamExpression()

    def test_subclass_without_consume_cannot_be_instantiated(self):
        class Incomplete(StreamExpression):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_is_an_event_consumer(self):
        self.assertIsInstance(ConstantExpression(), EventConsumer)


class TestAdd(unittest.TestCase):

    def test_add_none_is_ignored(self):
        x = ConstantExpression()
        c = RecordingConsumer()
        x.add(None)
        x.add(c)
        x.publish(segment(0, 1, 5))
        self.assertEqual(len(c.received), 1)

    def test_add_non_consumer_raises_type_error(self):
        with self.assertRaises(TypeError):
            ConstantExpression().add(lambda s: None)

    def test_publish_with_no_consumers_does_nothing(self):
        ConstantExpression().publish(segment(0, 1, 5))


class TestPublish(unittest.TestCase):

    def test_segment_is_sent_to_all_consumers(self):
        x = ConstantExpression()
        a, b = RecordingConsumer(), RecordingConsumer()
        x.add(a)
        x.add(b)
        s = segment(0, 1, 5)
        x.publish(s)
        self.assertEqual(a.received, [s])
        self.assertEqual(b.received, [s])

    def test_published_segment_is_passed_unchanged(self):
        x = ConstantExpression()
        c = RecordingConsumer()
        x.add(c)
        s = segment(0, 1, 5)
        x.publish(s)
        self.assertIs(c.received[0], s)

    def test_none_is_not_published(self):
        x = ConstantExpression()
        c = RecordingConsumer()
        x.add(c)
        x.publish(None)
        self.assertEqual(c.received, [])

    def test_publish_returns_none(self):
        self.assertIsNone(ConstantExpression().publish(segment(0, 1, 5)))

    def test_consumers_are_called_in_insertion_order(self):
        log = []
        x = ConstantExpression()
        for name in ('first', 'second', 'third'):
            x.add(RecordingConsumer(log, name))
        x.publish(segment(0, 1, 5))
        self.assertEqual(log, ['first', 'second', 'third'])

    def test_consume_in_subclass_can_publish(self):
        x = ConstantExpression()
        c = RecordingConsumer()
        x.add(c)
        x.consume(Event(2.0, Payload({'value': 7})))
        self.assertEqual(len(c.received), 1)
        self.assertEqual(c.received[0].interval, Interval(2.0))
        self.assertEqual(c.received[0].value_at(3.0), 7)


if __name__ == '__main__':
    unittest.main()
