"""Unit tests for cytlmonitor.next_relation.NextRelation."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.event_relation import EventRelation
from cytlmonitor.next_relation import NextRelation
from cytlmonitor.payload import Payload


class RecordingConsumer(EventConsumer):

    def __init__(self):
        self.received = []

    def consume(self, event):
        self.received.append(event)


def event(t):
    return Event(t, Payload({'t': t}))


class TestNextRelation(unittest.TestCase):

    def test_is_an_event_relation(self):
        self.assertIsInstance(NextRelation(), EventRelation)

    def test_single_event_has_no_next(self):
        r = NextRelation()
        e = event(1)
        r.consume(e)
        self.assertIsNone(r.get(e))

    def test_each_event_is_mapped_to_its_next(self):
        r = NextRelation()
        events = [event(t) for t in (1, 2, 3, 4)]
        for e in events:
            r.consume(e)
        for e, nxt in zip(events, events[1:]):
            self.assertIs(r.get(e), nxt)
        self.assertIsNone(r.get(events[-1]))

    def test_next_is_not_available_when_event_is_forwarded(self):
        r = NextRelation()
        seen = []

        class Probe(EventConsumer):
            def consume(self, e):
                seen.append(r.get(e))

        r.add(Probe())
        r.consume(event(1))
        r.consume(event(2))
        self.assertEqual(seen, [None, None])

    def test_next_becomes_available_after_following_event(self):
        r = NextRelation()
        e1, e2 = event(1), event(2)
        r.consume(e1)
        self.assertIsNone(r.get(e1))
        r.consume(e2)
        self.assertIs(r.get(e1), e2)

    def test_events_are_forwarded_unchanged(self):
        r = NextRelation()
        c = RecordingConsumer()
        r.add(c)
        events = [event(t) for t in (1, 2, 3)]
        for e in events:
            r.consume(e)
        self.assertEqual(c.received, events)

    def test_repeated_equal_event_overwrites_mapping(self):
        r = NextRelation()
        a, b, c = event(1), event(2), event(3)
        for e in (a, b, a, c):
            r.consume(e)
        self.assertIs(r.get(a), c)


if __name__ == '__main__':
    unittest.main()
