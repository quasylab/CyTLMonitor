"""Unit tests for cytlmonitor.event.Event."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.payload import Payload


class TestEventConstruction(unittest.TestCase):

    def test_time_and_payload_are_stored(self):
        payload = Payload({'src': '10.0.0.1'})
        e = Event(1.5, payload)
        self.assertEqual(e.time, 1.5)
        self.assertEqual(e.payload, payload)

    def test_time_is_stored_as_float(self):
        e = Event(3, Payload({}))
        self.assertIsInstance(e.time, float)

    def test_non_payload_argument_raises_type_error(self):
        with self.assertRaises(TypeError):
            Event(1.0, {'src': '10.0.0.1'})


class TestReadOnlyAttributes(unittest.TestCase):

    def setUp(self):
        self.event = Event(1.0, Payload({'a': 1}))

    def test_time_has_no_setter(self):
        with self.assertRaises(AttributeError):
            self.event.time = 2.0

    def test_payload_has_no_setter(self):
        with self.assertRaises(AttributeError):
            self.event.payload = Payload({'b': 2})

    def test_no_arbitrary_attributes_due_to_slots(self):
        with self.assertRaises(AttributeError):
            self.event.new_attribute = 42


class TestAccessors(unittest.TestCase):

    def setUp(self):
        self.payload = Payload({'src': '10.0.0.1', 'dst': '10.0.0.2'})
        self.event = Event(2.0, self.payload)

    def test_get_time(self):
        self.assertEqual(self.event.get_time(), 2.0)

    def test_get_payload(self):
        self.assertEqual(self.event.get_payload(), self.payload)


class TestPayloadDelegation(unittest.TestCase):

    def test_getitem_is_equivalent_to_payload_getitem(self):
        payload = Payload({'src': '10.0.0.1', 'size': 128})
        event = Event(0.0, payload)
        for field in payload:
            self.assertEqual(event[field], payload[field])

    def test_getitem_missing_field_raises_key_error(self):
        event = Event(0.0, Payload({'a': 1}))
        with self.assertRaises(KeyError):
            event['missing']


class TestEqualityAndRepr(unittest.TestCase):

    def test_equal_events(self):
        self.assertEqual(Event(1.0, Payload({'a': 1})), Event(1.0, Payload({'a': 1})))

    def test_different_time_not_equal(self):
        self.assertNotEqual(Event(1.0, Payload({'a': 1})), Event(2.0, Payload({'a': 1})))

    def test_different_payload_not_equal(self):
        self.assertNotEqual(Event(1.0, Payload({'a': 1})), Event(1.0, Payload({'a': 2})))

    def test_not_equal_to_other_types(self):
        self.assertNotEqual(Event(1.0, Payload({'a': 1})), (1.0, {'a': 1}))

    def test_repr_contains_time_and_payload(self):
        r = repr(Event(1.0, Payload({'a': 1})))
        self.assertIn('1.0', r)
        self.assertIn("'a': 1", r)


if __name__ == '__main__':
    unittest.main()
