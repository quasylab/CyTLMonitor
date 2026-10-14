"""Unit tests for cytlmonitor.previous_relation.PreviousRelation."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.event_relation import EventRelation
from cytlmonitor.payload import Payload
from cytlmonitor.previous_relation import PreviousRelation


class RecordingConsumer(EventConsumer):

    def __init__(self):
        self.received = []

    def consume(self, event):
        self.received.append(event)


def event(t):
    return Event(t, Payload({'t': t}))


class TestPreviousRelation(unittest.TestCase):

    def test_is_an_event_relation(self):
        self.assertIsInstance(PreviousRelation(), EventRelation)

    def test_first_event_has_no_previous(self):
        r = PreviousRelation()
        e = event(1)
        r.consume(e)
        self.assertIsNone(r.get(e))

    def test_each_event_is_mapped_to_its_previous(self):
        r = PreviousRelation()
        events = [event(t) for t in (1, 2, 3, 4)]
        for e in events:
            r.consume(e)
        self.assertIsNone(r.get(events[0]))
        for prev, e in zip(events, events[1:]):
            self.assertIs(r.get(e), prev)

    def test_previous_is_available_when_event_is_forwarded(self):
        r = PreviousRelation()
        seen = []

        class Probe(EventConsumer):
            def consume(self, e):
                seen.append(r.get(e))

        r.add(Probe())
        e1, e2 = event(1), event(2)
        r.consume(e1)
        r.consume(e2)
        self.assertEqual(seen, [None, e1])

    def test_events_are_forwarded_unchanged(self):
        r = PreviousRelation()
        c = RecordingConsumer()
        r.add(c)
        events = [event(t) for t in (1, 2, 3)]
        for e in events:
            r.consume(e)
        self.assertEqual(c.received, events)

    def test_unseen_event_has_no_previous(self):
        r = PreviousRelation()
        r.consume(event(1))
        r.consume(event(2))
        self.assertIsNone(r.get(event(3)))

    def test_repeated_equal_event_overwrites_mapping(self):
        r = PreviousRelation()
        a, b, c = event(1), event(2), event(3)
        for e in (a, b, c, b):
            r.consume(e)
        self.assertIs(r.get(b), c)


if __name__ == '__main__':
    unittest.main()
