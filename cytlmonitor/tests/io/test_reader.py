"""Unit tests for cytlmonitor.io.reader: the checks shared by every reader,
run through both the JSON and the CSV reader."""

import io
import json
import os
import tempfile
import unittest

from cytlmonitor import (
    AtomicGreaterMonitor, BooleanSignal, BooleanSignalConsumer, ConstantExpression,
    CsvEventReader, EventFormatError, EventReader, EventSequence, JsonEventReader, Payload,
    ShiftExpression, SumWindowExpression,
)


def as_json(rows):
    """A JSON document with an event per ``(time, payload)`` row; a payload
    of None leaves it out."""
    return json.dumps({'events': [{'time': t} if p is None else {'time': t, 'payload': p}
                                  for t, p in rows]})


def as_csv(columns, rows):
    """A CSV document with the given header and rows (None for an empty
    cell)."""
    lines = [','.join(columns)]
    lines += [','.join('' if v is None else str(v).lower() if isinstance(v, bool) else str(v)
                       for v in row) for row in rows]
    return '\n'.join(lines) + '\n'


class Formats:
    """Builds the same records in both formats, so each test runs on both.
    ``rows`` are ``(time, payload)`` pairs; every payload has the fields in
    ``columns``, None standing for a missing value."""

    def documents(self, columns, rows):
        yield 'json', JsonEventReader, as_json(
            [(t, {k: v for k, v in zip(columns, values) if v is not None}) for t, *values in rows])
        yield 'csv', CsvEventReader, as_csv(['time'] + list(columns), rows)

    def read_both(self, columns, rows, schema=None):
        results = {}
        for name, reader, text in self.documents(columns, rows):
            results[name] = reader(schema).read(io.StringIO(text))
        return results

    def assert_error_in_both(self, columns, rows, fragment, schema=None, where=None):
        for name, reader, text in self.documents(columns, rows):
            with self.subTest(format=name):
                with self.assertRaises(EventFormatError) as raised:
                    reader(schema).read(io.StringIO(text))
                self.assertIn(fragment, str(raised.exception))
                if where is not None:
                    self.assertEqual(raised.exception.location, where[name])


class TestValidFiles(Formats, unittest.TestCase):

    def test_events_and_payloads_are_read(self):
        for name, seq in self.read_both(
                ['size', 'protocol', 'syn'],
                [(0.5, 60, 'TCP', True), (1.25, 1500, 'UDP', False)]).items():
            with self.subTest(format=name):
                self.assertIsInstance(seq, EventSequence)
                events = list(seq)
                self.assertEqual([e.time for e in events], [0.5, 1.25])
                self.assertEqual(events[0].payload, Payload({'size': 60, 'protocol': 'TCP',
                                                             'syn': True}))
                self.assertEqual(events[1].payload['syn'], False)

    def test_missing_values_leave_the_field_out(self):
        for name, seq in self.read_both(['size', 'login'],
                                        [(1, 60, None), (2, None, 'ok')]).items():
            with self.subTest(format=name):
                first, second = list(seq)
                self.assertEqual(sorted(first.payload.fields()), ['size'])
                self.assertEqual(sorted(second.payload.fields()), ['login'])

    def test_integers_and_decimals_are_both_numbers(self):
        for name, seq in self.read_both(['size'], [(1, 60), (2, 60.5)]).items():
            with self.subTest(format=name):
                self.assertEqual([e.payload['size'] for e in seq], [60, 60.5])

    def test_integer_times_are_floats(self):
        for name, seq in self.read_both(['x'], [(0, 1), (3, 1)]).items():
            with self.subTest(format=name):
                self.assertEqual([e.time for e in seq], [0.0, 3.0])
                self.assertIsInstance(list(seq)[0].time, float)

    def test_empty_sequence(self):
        self.assertEqual(JsonEventReader().read(io.StringIO('{"events": []}')).length(), 0)
        self.assertEqual(CsvEventReader().read(io.StringIO('time,size\n')).length(), 0)


class TestTimes(Formats, unittest.TestCase):

    def test_equal_times_are_rejected(self):
        self.assert_error_in_both(['x'], [(1, 1), (1, 2)],
                                  'the time 1.0 is not after the time of the previous event',
                                  where={'json': 'event 1', 'csv': 'line 3'})

    def test_decreasing_times_are_rejected(self):
        self.assert_error_in_both(['x'], [(2, 1), (1, 2)], 'is not after')

    def test_negative_times_are_rejected(self):
        self.assert_error_in_both(['x'], [(-1, 1)], 'the time must not be negative')

    def test_non_numeric_times_are_rejected(self):
        self.assert_error_in_both(['x'], [('noon', 1)], 'the time must be a number')

    def test_boolean_times_are_rejected(self):
        self.assert_error_in_both(['x'], [(True, 1)], 'the time must be a number')

    def test_infinite_times_are_rejected(self):
        with self.assertRaises(EventFormatError) as raised:
            JsonEventReader().read(io.StringIO('{"events": [{"time": 1e999}]}'))
        self.assertIn('finite', str(raised.exception))
        with self.assertRaises(EventFormatError):
            JsonEventReader().read(io.StringIO('{"events": [{"time": ' + '9' * 400 + '}]}'))

    def test_missing_time_is_rejected(self):
        with self.assertRaises(EventFormatError) as raised:
            CsvEventReader().read(io.StringIO('time,x\n,1\n'))
        self.assertIn('the time is missing', str(raised.exception))
        with self.assertRaises(EventFormatError) as raised:
            JsonEventReader().read(io.StringIO('{"events": [{"payload": {}}]}'))
        self.assertIn('the time is missing', str(raised.exception))


class TestFieldTypes(Formats, unittest.TestCase):

    def test_string_after_number_is_rejected(self):
        self.assert_error_in_both(
            ['size'], [(1, 60), (2, 'big')],
            "field 'size': expected a number, as at ", where={'json': 'event 1', 'csv': 'line 3'})

    def test_number_after_boolean_is_rejected(self):
        self.assert_error_in_both(['syn'], [(1, True), (2, 1)],
                                  "field 'syn': expected a boolean")

    def test_boolean_after_string_is_rejected(self):
        self.assert_error_in_both(['p'], [(1, 'TCP'), (2, True)], "field 'p': expected a string")

    def test_type_is_set_by_the_first_value_even_after_a_gap(self):
        self.assert_error_in_both(['size'], [(1, None), (2, 'big'), (3, 60)],
                                  "expected a string, as at ")

    def test_fields_are_checked_independently(self):
        self.read_both(['a', 'b'], [(1, 1, 'x'), (2, 2, 'y')])

    def test_lists_and_objects_are_rejected(self):
        for value in ([1, 2], {'k': 1}):
            with self.subTest(value=value):
                with self.assertRaises(EventFormatError) as raised:
                    JsonEventReader().read(io.StringIO(as_json([(1, {'a': value})])))
                self.assertIn('a value must be a boolean, a number or a string',
                              str(raised.exception))


class TestSchema(Formats, unittest.TestCase):

    def test_values_are_converted_to_the_schema_types(self):
        schema = {'size': float, 'count': int, 'syn': bool, 'proto': str}
        for name, seq in self.read_both(['size', 'count', 'syn', 'proto'],
                                        [(1, 60, 3, True, 'TCP')], schema).items():
            with self.subTest(format=name):
                payload = list(seq)[0].payload
                self.assertIsInstance(payload['size'], float)
                self.assertEqual(payload['size'], 60.0)
                self.assertEqual(payload['count'], 3)
                self.assertIs(payload['syn'], True)
                self.assertEqual(payload['proto'], 'TCP')

    def test_integer_field_rejects_decimals_and_booleans(self):
        self.assert_error_in_both(['count'], [(1, 1.5)], "field 'count': expected an integer",
                                  schema={'count': int})
        self.assert_error_in_both(['count'], [(1, True)], "field 'count': expected an integer",
                                  schema={'count': int})

    def test_wrong_type_is_rejected_even_for_the_first_value(self):
        self.assert_error_in_both(['size'], [(1, 'big')], "field 'size': expected a number",
                                  schema={'size': float})

    def test_fields_missing_from_the_schema_are_rejected(self):
        self.assert_error_in_both(['size', 'typo'], [(1, 60, 1)], "field 'typo' is not in the schema",
                                  schema={'size': int})

    def test_schema_fields_may_be_missing_from_events(self):
        for seq in self.read_both(['size'], [(1, 60)], {'size': int, 'other': str}).values():
            self.assertEqual(sorted(list(seq)[0].payload.fields()), ['size'])

    def test_invalid_schemas_are_rejected(self):
        with self.assertRaises(TypeError):
            CsvEventReader(schema=['size'])
        with self.assertRaises(TypeError):
            CsvEventReader(schema={1: int})
        with self.assertRaises(ValueError):
            JsonEventReader(schema={'size': list})

    def test_schema_is_copied(self):
        schema = {'size': int}
        reader = JsonEventReader(schema)
        schema['size'] = str
        self.assertEqual(reader.schema, {'size': int})
        self.assertIsNone(JsonEventReader().schema)


class TestSources(unittest.TestCase):

    def write(self, suffix, text):
        handle, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(handle, 'w', encoding='utf-8') as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_reads_from_a_path(self):
        path = self.write('.csv', 'time,size\n1,60\n2,70\n')
        self.assertEqual(CsvEventReader().read(path).length(), 2)
        path = self.write('.json', as_json([(1, {'size': 60})]))
        self.assertEqual(JsonEventReader().read(path).length(), 1)

    def test_errors_name_the_file(self):
        path = self.write('.csv', 'time,size\n1,60\n1,70\n')
        with self.assertRaises(EventFormatError) as raised:
            CsvEventReader().read(path)
        self.assertEqual(raised.exception.source, path)
        self.assertEqual(raised.exception.location, 'line 3')
        self.assertTrue(str(raised.exception).startswith(f'{path}, line 3: '))

    def test_error_is_a_value_error(self):
        with self.assertRaises(ValueError):
            CsvEventReader().read(io.StringIO('time\nx\n'))

    def test_events_are_yielded_before_an_invalid_record_is_reached(self):
        events = CsvEventReader().events(io.StringIO('time,size\n1,60\n2,70\n2,80\n'))
        self.assertEqual(next(events).time, 1.0)
        self.assertEqual(next(events).time, 2.0)
        with self.assertRaises(EventFormatError):
            next(events)

    def test_a_monitor_can_be_fed_while_the_file_is_read(self):
        text = 'time,size\n' + ''.join(f'{t / 4},{100 if 8 <= t < 16 else 10}\n' for t in range(40))
        volume = ShiftExpression(SumWindowExpression(lambda e: e.payload['size'], 0, 1), 1)
        burst = AtomicGreaterMonitor(volume, ConstantExpression(300))

        class Record(BooleanSignalConsumer):
            def __init__(self):
                self.signal = BooleanSignal()

            def consume(self, i):
                self.signal.add(i)

            def set_horizon(self, t):
                self.signal.set_horizon(t)

        out = Record()
        burst.add(out)
        for event in CsvEventReader().events(io.StringIO(text)):
            burst.consume(event)
        self.assertEqual(out.signal.length(), 1)

    def test_is_an_abstract_base(self):
        with self.assertRaises(TypeError):
            EventReader()


if __name__ == '__main__':
    unittest.main()
