"""Unit tests for cytlmonitor.event_processor.EventProcessor."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.event_processor import EventProcessor
from cytlmonitor.payload import Payload


class RecordingConsumer(EventConsumer):

    def __init__(self, log=None, name=None):
        self.received = []
        self.log = log
        self.name = name

    def consume(self, event):
        self.received.append(event)
        if self.log is not None:
            self.log.append(self.name)


class Shift(EventProcessor):
    """Shifts events forward by one time unit; drops events at negative times."""

    def __init__(self):
        super().__init__()
        self.processed = []

    def process(self, e):
        self.processed.append(e)
        if e.time < 0:
            return None
        return Event(e.time + 1, e.payload)


def event(t):
    return Event(t, Payload({'t': t}))


class TestAbstractness(unittest.TestCase):

    def test_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            EventProcessor()

    def test_subclass_without_process_cannot_be_instantiated(self):
        class Incomplete(EventProcessor):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_is_an_event_consumer(self):
        self.assertIsInstance(Shift(), EventConsumer)


class TestAdd(unittest.TestCase):

    def test_consumers_are_initially_empty(self):
        self.assertEqual(Shift()._consumers, [])

    def test_add_appends_at_the_end(self):
        p = Shift()
        a, b = RecordingConsumer(), RecordingConsumer()
        p.add(a)
        p.add(b)
        self.assertEqual(p._consumers, [a, b])

    def test_add_non_consumer_raises_type_error(self):
        with self.assertRaises(TypeError):
            Shift().add(lambda e: None)

    def test_add_none_raises_type_error(self):
        with self.assertRaises(TypeError):
            Shift().add(None)


class TestConsume(unittest.TestCase):

    def test_consume_calls_process_with_the_event(self):
        p = Shift()
        e = event(1)
        p.consume(e)
        self.assertEqual(len(p.processed), 1)
        self.assertIs(p.processed[0], e)

    def test_consume_returns_none(self):
        self.assertIsNone(Shift().consume(event(1)))

    def test_processed_event_is_forwarded_to_all_consumers(self):
        p = Shift()
        a, b = RecordingConsumer(), RecordingConsumer()
        p.add(a)
        p.add(b)
        p.consume(event(1))
        expected = Event(2, Payload({'t': 1}))
        self.assertEqual(a.received, [expected])
        self.assertEqual(b.received, [expected])

    def test_result_of_process_is_forwarded_not_the_input(self):
        p = Shift()
        c = RecordingConsumer()
        p.add(c)
        e = event(1)
        p.consume(e)
        self.assertNotEqual(c.received[0], e)

    def test_none_result_is_not_forwarded(self):
        p = Shift()
        c = RecordingConsumer()
        p.add(c)
        p.consume(event(-1))
        self.assertEqual(c.received, [])

    def test_consumers_are_called_in_insertion_order(self):
        log = []
        p = Shift()
        for name in ('first', 'second', 'third'):
            p.add(RecordingConsumer(log, name))
        p.consume(event(1))
        self.assertEqual(log, ['first', 'second', 'third'])

    def test_same_consumer_added_twice_receives_event_twice(self):
        p = Shift()
        c = RecordingConsumer()
        p.add(c)
        p.add(c)
        p.consume(event(1))
        self.assertEqual(len(c.received), 2)

    def test_processors_can_be_chained(self):
        first, second = Shift(), Shift()
        c = RecordingConsumer()
        first.add(second)
        second.add(c)
        first.consume(event(1))
        self.assertEqual(c.received, [Event(3, Payload({'t': 1}))])


if __name__ == '__main__':
    unittest.main()
