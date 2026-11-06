"""Unit tests for cytlmonitor.io.csv_reader: the header, the rows and how
cells are read."""

import io
import unittest

from cytlmonitor import CsvEventReader, EventFormatError, Payload
from cytlmonitor.io.csv_reader import parse_cell


def read(text, **options):
    return list(CsvEventReader(**options).read(io.StringIO(text)))


class TestParseCell(unittest.TestCase):

    def test_empty_cells_are_missing(self):
        self.assertIsNone(parse_cell(''))
        self.assertIsNone(parse_cell('   '))

    def test_booleans_in_any_case(self):
        self.assertIs(parse_cell('true'), True)
        self.assertIs(parse_cell('FALSE'), False)
        self.assertIs(parse_cell(' True '), True)

    def test_integers(self):
        for text, value in [('12', 12), ('-3', -3), ('+7', 7), ('007', 7)]:
            self.assertEqual(parse_cell(text), value)
            self.assertIsInstance(parse_cell(text), int)

    def test_decimals(self):
        for text, value in [('1.5', 1.5), ('-0.25', -0.25), ('.5', 0.5), ('3.', 3.0),
                            ('1e3', 1000.0), ('2.5E-2', 0.025)]:
            self.assertEqual(parse_cell(text), value)
            self.assertIsInstance(parse_cell(text), float)

    def test_everything_else_is_text(self):
        for text in ['TCP', 'nan', 'inf', 'Infinity', '1,5', '12a', 'yes', '0x10']:
            self.assertEqual(parse_cell(text), text)

    def test_text_is_stripped(self):
        self.assertEqual(parse_cell('  TCP '), 'TCP')


class TestHeader(unittest.TestCase):

    def assert_error(self, text, fragment, location=None):
        with self.assertRaises(EventFormatError) as raised:
            read(text)
        self.assertIn(fragment, str(raised.exception))
        self.assertEqual(raised.exception.location, location)

    def test_the_first_column_is_the_time_whatever_its_name(self):
        events = read('timestamp,size\n1,60\n')
        self.assertEqual(events[0].time, 1.0)
        self.assertEqual(events[0].payload, Payload({'size': 60}))

    def test_time_alone(self):
        self.assertEqual([e.payload for e in read('t\n1\n2\n')], [Payload({}), Payload({})])

    def test_empty_file(self):
        self.assert_error('', 'the file is empty')
        self.assert_error('\n\n', 'the file is empty')

    def test_unnamed_columns(self):
        self.assert_error(',size\n1,2\n', 'the first column, the time, has no name', 'line 1')
        self.assert_error('time,,size\n1,2,3\n', 'column 2 has no name', 'line 1')

    def test_duplicate_columns(self):
        self.assert_error('time,size,size\n1,2,3\n', "columns named more than once: ['size']",
                          'line 1')

    def test_names_are_stripped(self):
        self.assertEqual(read('time, size \n1,60\n')[0].payload, Payload({'size': 60}))


class TestRows(unittest.TestCase):

    def test_rows_must_have_one_cell_per_column(self):
        for row in ['1', '1,2,3']:
            with self.subTest(row=row):
                with self.assertRaises(EventFormatError) as raised:
                    read(f'time,size\n0,1\n{row}\n')
                self.assertIn('expected 2 values, one per column', str(raised.exception))
                self.assertEqual(raised.exception.location, 'line 3')

    def test_empty_lines_are_skipped_and_counted(self):
        text = 'time,size\n\n1,60\n\n2,big\n'
        with self.assertRaises(EventFormatError) as raised:
            read(text)
        self.assertEqual(raised.exception.location, 'line 5')
        self.assertIn('as at line 3', str(raised.exception))

    def test_quoted_cells(self):
        events = read('time,name\n1,"Smith, John"\n2,"say ""hi"""\n')
        self.assertEqual([e.payload['name'] for e in events], ['Smith, John', 'say "hi"'])

    def test_line_numbers_count_multiline_cells(self):
        with self.assertRaises(EventFormatError) as raised:
            read('time,note\n1,"two\nlines"\n1,x\n')
        self.assertEqual(raised.exception.location, 'line 4')

    def test_other_delimiters(self):
        events = read('time;size\n1;60\n', delimiter=';')
        self.assertEqual(events[0].payload, Payload({'size': 60}))
        events = read('time\tsize\n1\t60\n', delimiter='\t')
        self.assertEqual(events[0].payload, Payload({'size': 60}))

    def test_invalid_delimiters(self):
        for delimiter in ['', ';;', 1]:
            with self.subTest(delimiter=delimiter):
                with self.assertRaises(ValueError):
                    CsvEventReader(delimiter=delimiter)
        self.assertEqual(CsvEventReader(delimiter=';').delimiter, ';')


class TestTextColumns(unittest.TestCase):

    def test_number_after_text_without_a_schema_is_rejected(self):
        with self.assertRaises(EventFormatError) as raised:
            read('time,port\n1,https\n2,443\n')
        self.assertIn("field 'port': expected a string, as at line 2, got a number (443)",
                      str(raised.exception))

    def test_a_str_schema_keeps_the_text_of_numbers_and_booleans(self):
        events = read('time,port\n1,https\n2,443\n3,007\n4,true\n', schema={'port': str})
        self.assertEqual([e.payload['port'] for e in events], ['https', '443', '007', 'true'])

    def test_a_str_schema_still_treats_empty_cells_as_missing(self):
        events = read('time,port\n1,\n2,80\n', schema={'port': str})
        self.assertEqual([sorted(e.payload.fields()) for e in events], [[], ['port']])


if __name__ == '__main__':
    unittest.main()
