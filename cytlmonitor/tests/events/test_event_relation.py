"""Unit tests for cytlmonitor.events.relations.EventRelation."""

import unittest

from cytlmonitor.events.event import Event
from cytlmonitor.events.consumer import EventConsumer
from cytlmonitor.events.processor import EventProcessor
from cytlmonitor.events.relations import EventRelation
from cytlmonitor.events.payload import Payload


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
            return self._first[e.time]
        self._first[e.time] = e
        return None


class FixedRelation(EventRelation):
    """Maps every event to a given event."""

    def __init__(self, target):
        super().__init__()
        self.target = target

    def record(self, e):
        return self.target


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


class TestEval(unittest.TestCase):

    @staticmethod
    def value(e):
        return float(e.payload['a'])

    def test_mapped_event_gives_f_of_the_related_event(self):
        r = SameTimeRelation()
        e1, e2 = Event(1.0, Payload({'a': 1})), Event(1.0, Payload({'a': 2}))
        r.consume(e1)
        r.consume(e2)
        self.assertEqual(r.eval(self.value, -1.0)(e2), 1.0)

    def test_unmapped_event_gives_the_default(self):
        r = SameTimeRelation()
        e1 = Event(1.0, Payload({'a': 1}))
        r.consume(e1)
        g = r.eval(self.value, -1.0)
        self.assertEqual(g(e1), -1.0)
        self.assertEqual(g(Event(5.0, Payload({'a': 5}))), -1.0)

    def test_f_is_not_applied_to_unmapped_events(self):
        calls = []
        r = SameTimeRelation()
        e1 = Event(1.0, Payload({'a': 1}))
        r.consume(e1)
        r.eval(lambda e: calls.append(e) or 0.0, 0.0)(e1)
        self.assertEqual(calls, [])

    def test_reflects_events_processed_after_its_creation(self):
        r = SameTimeRelation()
        g = r.eval(self.value, 0.0)
        e1, e2 = Event(1.0, Payload({'a': 3})), Event(1.0, Payload({'a': 4}))
        self.assertEqual(g(e2), 0.0)
        r.consume(e1)
        r.consume(e2)
        self.assertEqual(g(e2), 3.0)

    def test_usable_while_the_event_is_forwarded(self):
        r = SameTimeRelation()
        g = r.eval(self.value, 0.0)
        seen = []

        class Probe(EventConsumer):
            def consume(self, event):
                seen.append(g(event))

        r.add(Probe())
        r.consume(Event(1.0, Payload({'a': 7})))
        r.consume(Event(1.0, Payload({'a': 8})))
        self.assertEqual(seen, [0.0, 7.0])

    def test_rejects_non_callable(self):
        with self.assertRaises(TypeError):
            SameTimeRelation().eval(1.0, 0.0)


class TestOnlyPastEvents(unittest.TestCase):

    def test_rejects_an_event_not_yet_processed(self):
        future = Event(2.0, Payload({'a': 2}))
        r = FixedRelation(future)
        with self.assertRaises(ValueError):
            r.consume(Event(1.0, Payload({'a': 1})))

    def test_rejects_the_event_itself(self):
        class SelfRelation(EventRelation):
            def record(self, e):
                return e

        with self.assertRaises(ValueError):
            SelfRelation().consume(Event(1.0, Payload({'a': 1})))

    def test_rejected_event_is_not_forwarded_nor_mapped(self):
        e = Event(1.0, Payload({'a': 1}))
        r = FixedRelation(Event(2.0, Payload({'a': 2})))
        c = RecordingConsumer()
        r.add(c)
        with self.assertRaises(ValueError):
            r.consume(e)
        self.assertEqual(c.received, [])
        self.assertIsNone(r.get(e))

    def test_accepts_any_past_event(self):
        first = Event(1.0, Payload({'a': 1}))
        r = FixedRelation(None)
        r.consume(first)
        r.target = first
        events = [Event(t, Payload({'t': t})) for t in (2.0, 3.0)]
        for e in events:
            r.consume(e)
        self.assertIsNone(r.get(first))
        for e in events:
            self.assertIs(r.get(e), first)

    def test_none_removes_a_previous_mapping(self):
        a, b = Event(1.0, Payload({'a': 1})), Event(2.0, Payload({'a': 2}))
        r = FixedRelation(None)
        r.consume(a)
        r.target = a
        r.consume(b)
        r.target = None
        r.consume(b)
        self.assertIsNone(r.get(b))


if __name__ == '__main__':
    unittest.main()
