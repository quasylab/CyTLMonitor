"""Unit tests for cytlmonitor.event_sequence.EventSequence."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_sequence import EventSequence
from cytlmonitor.payload import Payload


def make_event(time, **fields):
    return Event(time, Payload(fields))


class TestConstruction(unittest.TestCase):

    def test_empty_sequence(self):
        seq = EventSequence()
        self.assertEqual(seq.length(), 0)

    def test_construct_from_ordered_iterable(self):
        events = [make_event(1.0), make_event(2.0), make_event(3.0)]
        seq = EventSequence(events)
        self.assertEqual(seq.length(), 3)
        self.assertEqual(seq[0], events[0])
        self.assertEqual(seq[2], events[2])

    def test_construct_from_unordered_iterable_raises(self):
        events = [make_event(2.0), make_event(1.0)]
        with self.assertRaises(ValueError):
            EventSequence(events)

    def test_construct_from_iterable_with_duplicate_time_raises(self):
        events = [make_event(1.0), make_event(1.0)]
        with self.assertRaises(ValueError):
            EventSequence(events)


class TestAdd(unittest.TestCase):

    def test_add_first_event(self):
        seq = EventSequence()
        e = make_event(1.0)
        seq.add(e)
        self.assertEqual(seq.length(), 1)
        self.assertEqual(seq[0], e)

    def test_add_strictly_increasing_events(self):
        seq = EventSequence()
        e1, e2, e3 = make_event(1.0), make_event(2.0), make_event(5.0)
        seq.add(e1)
        seq.add(e2)
        seq.add(e3)
        self.assertEqual(seq.length(), 3)
        self.assertEqual([seq[0], seq[1], seq[2]], [e1, e2, e3])

    def test_add_event_with_equal_time_raises(self):
        seq = EventSequence()
        seq.add(make_event(1.0))
        with self.assertRaises(ValueError):
            seq.add(make_event(1.0))

    def test_add_event_with_earlier_time_raises(self):
        seq = EventSequence()
        seq.add(make_event(5.0))
        with self.assertRaises(ValueError):
            seq.add(make_event(1.0))

    def test_failed_add_does_not_modify_sequence(self):
        seq = EventSequence()
        seq.add(make_event(5.0))
        with self.assertRaises(ValueError):
            seq.add(make_event(1.0))
        self.assertEqual(seq.length(), 1)

    def test_add_non_event_raises_type_error(self):
        seq = EventSequence()
        with self.assertRaises(TypeError):
            seq.add((1.0, {'a': 1}))


class TestIndexingAndLength(unittest.TestCase):

    def setUp(self):
        self.events = [make_event(1.0), make_event(2.0), make_event(3.0)]
        self.seq = EventSequence(self.events)

    def test_length(self):
        self.assertEqual(self.seq.length(), 3)

    def test_len_matches_length(self):
        self.assertEqual(len(self.seq), self.seq.length())

    def test_getitem_returns_correct_event(self):
        for i in range(self.seq.length()):
            self.assertEqual(self.seq[i], self.events[i])

    def test_getitem_out_of_range_raises_index_error(self):
        with self.assertRaises(IndexError):
            self.seq[self.seq.length()]

    def test_iteration_yields_events_in_order(self):
        self.assertEqual(list(self.seq), self.events)


if __name__ == '__main__':
    unittest.main()
