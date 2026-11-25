"""Unit tests for cytlmonitor.events.relations.SessionRelation."""

import unittest

from cytlmonitor.events.consumer import EventConsumer
from cytlmonitor.events.event import Event
from cytlmonitor.events.payload import Payload
from cytlmonitor.events.relations import EventRelation, SessionRelation


class RecordingConsumer(EventConsumer):

    def __init__(self):
        self.received = []

    def consume(self, event):
        self.received.append(event)


def event(t, **fields):
    return Event(t, Payload(fields))


def f_open(e):
    return e.payload.get('open')


def f_close(e):
    return e.payload.get('close')


def relation():
    return SessionRelation(f_open, f_close)


class TestConstruction(unittest.TestCase):

    def test_is_an_event_relation(self):
        self.assertIsInstance(relation(), EventRelation)

    def test_properties(self):
        r = relation()
        self.assertIs(r.f_open, f_open)
        self.assertIs(r.f_close, f_close)

    def test_rejects_non_callable_functions(self):
        with self.assertRaises(TypeError):
            SessionRelation(1, f_close)
        with self.assertRaises(TypeError):
            SessionRelation(f_open, None)


class TestSessions(unittest.TestCase):

    def test_closing_event_is_mapped_to_the_opening_event(self):
        r = relation()
        start, end = event(1, open=7), event(2, close=7)
        r.consume(start)
        r.consume(end)
        self.assertIs(r.get(end), start)
        self.assertIsNone(r.get(start))

    def test_closing_an_index_never_opened(self):
        r = relation()
        e = event(1, close=3)
        r.consume(event(0, open=4))
        r.consume(e)
        self.assertIsNone(r.get(e))

    def test_events_neither_opening_nor_closing(self):
        r = relation()
        events = [event(t) for t in (1, 2, 3)]
        for e in events:
            r.consume(e)
        for e in events:
            self.assertIsNone(r.get(e))
        self.assertIsNone(r.opened(0))

    def test_reopening_replaces_the_previous_event(self):
        r = relation()
        first, second, end = event(1, open=1), event(2, open=1), event(3, close=1)
        for e in (first, second, end):
            r.consume(e)
        self.assertIs(r.opened(1), second)
        self.assertIs(r.get(end), second)

    def test_sessions_with_different_indexes_are_independent(self):
        r = relation()
        a, b = event(1, open=1), event(2, open=2)
        end_a, end_b = event(3, close=1), event(4, close=2)
        for e in (a, b, end_b, end_a):
            r.consume(e)
        self.assertIs(r.get(end_a), a)
        self.assertIs(r.get(end_b), b)

    def test_closing_does_not_remove_the_open_index(self):
        r = relation()
        start, end1, end2 = event(1, open=1), event(2, close=1), event(3, close=1)
        for e in (start, end1, end2):
            r.consume(e)
        self.assertIs(r.get(end1), start)
        self.assertIs(r.get(end2), start)
        self.assertIs(r.opened(1), start)

    def test_close_is_evaluated_before_open(self):
        # An event closing and opening the same index is related to the
        # event that opened it before, then becomes the opening event.
        r = relation()
        start, both, end = event(1, open=1), event(2, open=1, close=1), event(3, close=1)
        for e in (start, both, end):
            r.consume(e)
        self.assertIs(r.get(both), start)
        self.assertIs(r.get(end), both)

    def test_an_event_opening_and_closing_alone_is_not_self_related(self):
        r = relation()
        e = event(1, open=1, close=1)
        r.consume(e)
        self.assertIsNone(r.get(e))
        self.assertIs(r.opened(1), e)

    def test_closing_one_index_and_opening_another(self):
        r = relation()
        a, b, c = event(1, open=1), event(2, close=1, open=2), event(3, close=2)
        for e in (a, b, c):
            r.consume(e)
        self.assertIs(r.get(b), a)
        self.assertIs(r.get(c), b)

    def test_index_zero_is_an_index(self):
        r = relation()
        start, end = event(1, open=0), event(2, close=0)
        r.consume(start)
        r.consume(end)
        self.assertIs(r.get(end), start)

    def test_mapping_is_available_when_event_is_forwarded(self):
        r = relation()
        seen = []

        class Probe(EventConsumer):
            def consume(self, e):
                seen.append(r.get(e))

        r.add(Probe())
        start, end = event(1, open=1), event(2, close=1)
        r.consume(start)
        r.consume(end)
        self.assertEqual(seen, [None, start])

    def test_events_are_forwarded_unchanged(self):
        r = relation()
        c = RecordingConsumer()
        r.add(c)
        events = [event(1, open=1), event(2), event(3, close=1)]
        for e in events:
            r.consume(e)
        self.assertEqual(c.received, events)


if __name__ == '__main__':
    unittest.main()
