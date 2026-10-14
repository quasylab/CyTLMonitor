"""Unit tests for cytlmonitor.event_relation.EventRelation."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.event_processor import EventProcessor
from cytlmonitor.event_relation import EventRelation
from cytlmonitor.payload import Payload


class RecordingConsumer(EventConsumer):

    def __init__(self):
        self.received = []

    def consume(self, event):
        self.received.append(event)


class SameTimeRelation(EventRelation):
    """Maps each event to the first recorded event having the same time."""

    def __init__(self):
        super().__init__()
        self.recorded = []
        self._first = {}

    def record(self, e):
        self.recorded.append(e)
        if e.time in self._first:
            self._map[e] = self._first[e.time]
        else:
            self._first[e.time] = e


class TestAbstractness(unittest.TestCase):

    def test_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            EventRelation()

    def test_subclass_without_record_cannot_be_instantiated(self):
        class Incomplete(EventRelation):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_is_an_event_processor(self):
        self.assertIsInstance(SameTimeRelation(), EventProcessor)


class TestGet(unittest.TestCase):

    def test_map_is_initially_empty(self):
        r = SameTimeRelation()
        self.assertIsNone(r.get(Event(1.0, Payload({'a': 1}))))

    def test_get_returns_mapped_event(self):
        r = SameTimeRelation()
        e1 = Event(1.0, Payload({'a': 1}))
        e2 = Event(1.0, Payload({'a': 2}))
        r.consume(e1)
        r.consume(e2)
        self.assertIs(r.get(e2), e1)

    def test_get_returns_none_for_unmapped_event(self):
        r = SameTimeRelation()
        e1 = Event(1.0, Payload({'a': 1}))
        r.consume(e1)
        self.assertIsNone(r.get(e1))

    def test_get_matches_equal_events(self):
        r = SameTimeRelation()
        e1 = Event(1.0, Payload({'a': 1}))
        r.consume(e1)
        r.consume(Event(1.0, Payload({'a': 2})))
        self.assertIs(r.get(Event(1.0, Payload({'a': 2}))), e1)


class TestProcess(unittest.TestCase):

    def test_process_records_the_event(self):
        r = SameTimeRelation()
        e = Event(1.0, Payload({'a': 1}))
        r.process(e)
        self.assertEqual(r.recorded, [e])

    def test_process_returns_the_received_event(self):
        r = SameTimeRelation()
        e = Event(1.0, Payload({'a': 1}))
        self.assertIs(r.process(e), e)

    def test_record_happens_before_forwarding(self):
        r = SameTimeRelation()
        e1 = Event(1.0, Payload({'a': 1}))
        e2 = Event(1.0, Payload({'a': 2}))
        seen = []

        class Probe(EventConsumer):
            def consume(self, event):
                seen.append(r.get(event))

        r.add(Probe())
        r.consume(e1)
        r.consume(e2)
        self.assertEqual(seen, [None, e1])

    def test_consume_forwards_every_event_unchanged(self):
        r = SameTimeRelation()
        c = RecordingConsumer()
        r.add(c)
        events = [Event(t, Payload({'t': t})) for t in (1.0, 1.0, 2.0)]
        for e in events:
            r.consume(e)
        self.assertEqual(len(c.received), 3)
        for got, sent in zip(c.received, events):
            self.assertIs(got, sent)


if __name__ == '__main__':
    unittest.main()
