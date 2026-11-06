"""Unit tests for cytlmonitor.io.json_reader.JsonEventReader: the structure
of the JSON document."""

import io
import unittest

from cytlmonitor import EventFormatError, JsonEventReader, Payload


def read(text, schema=None):
    return list(JsonEventReader(schema).read(io.StringIO(text)))


class TestStructure(unittest.TestCase):

    def assert_error(self, text, fragment, location=None):
        with self.assertRaises(EventFormatError) as raised:
            read(text)
        self.assertIn(fragment, str(raised.exception))
        self.assertEqual(raised.exception.location, location)

    def test_payload_may_be_left_out(self):
        events = read('{"events": [{"time": 1}, {"time": 2, "payload": {}}]}')
        self.assertEqual([e.payload for e in events], [Payload({}), Payload({})])

    def test_null_leaves_the_field_out(self):
        events = read('{"events": [{"time": 1, "payload": {"a": null, "b": 2}}]}')
        self.assertEqual(events[0].payload, Payload({'b': 2}))

    def test_invalid_json(self):
        self.assert_error('{"events": [', 'not valid JSON')

    def test_nan_and_infinity_are_rejected(self):
        self.assert_error('{"events": [{"time": NaN}]}', 'not valid JSON: NaN')
        self.assert_error('{"events": [{"time": 1, "payload": {"a": Infinity}}]}',
                          'not valid JSON: Infinity')

    def test_document_must_be_an_object(self):
        self.assert_error('[{"time": 1}]', 'expected an object with the events, got list')

    def test_events_key_is_required(self):
        self.assert_error('{}', "missing key 'events'")
        self.assert_error('{"evts": []}', "missing key 'events'; unexpected keys ['evts']")

    def test_other_keys_are_rejected(self):
        self.assert_error('{"events": [], "version": 1}', "unexpected keys ['version']")
        self.assert_error('{"events": [{"time": 1, "paylod": {}}]}',
                          "unexpected keys ['paylod']", 'event 0')

    def test_events_must_be_a_list_of_objects(self):
        self.assert_error('{"events": {"time": 1}}', "'events' must be a list, got dict")
        self.assert_error('{"events": [{"time": 1}, 2]}', 'an event must be an object, got int',
                          'event 1')

    def test_payload_must_be_an_object(self):
        self.assert_error('{"events": [{"time": 1, "payload": [1]}]}',
                          "'payload' must be an object, got list", 'event 0')

    def test_huge_integer_field_for_a_float_schema(self):
        with self.assertRaises(EventFormatError) as raised:
            read('{"events": [{"time": 1, "payload": {"a": ' + '9' * 400 + '}}]}', {'a': float})
        self.assertIn('too large for a float', str(raised.exception))

    def test_huge_integer_field_is_kept_without_a_schema(self):
        events = read('{"events": [{"time": 1, "payload": {"a": ' + '9' * 30 + '}}]}')
        self.assertEqual(events[0].payload['a'], int('9' * 30))


if __name__ == '__main__':
    unittest.main()
