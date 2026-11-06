"""
cytlmonitor.io.csv_reader
=========================
Reader of sequences of events from CSV files.

The first row names the columns: the first column is the time of the events,
whatever its name, and each of the others a field of their payloads. Each
following row is an event::

    time,size,protocol,tcp_syn
    0.5,60,TCP,true
    1.25,1500,UDP,
    2,40,TCP,false

A cell is read as a boolean if it is ``true`` or ``false`` (in any case), as
an integer or a decimal number if it is one (such as ``12``, ``-3.5`` or
``1e3``), and as a string otherwise. An empty cell leaves the field out of
that event's payload. A schema giving a field the type ``str`` keeps its
cells as text, so that a column of ports such as ``443`` or ``https`` is read
as strings.

Every row must have one cell per column; empty lines are skipped. The checks
on times and fields are those of :class:`~cytlmonitor.io.reader.EventReader`,
so a column whose first value is a number must hold numbers only; problems
are reported with the line number in the file.
"""

from __future__ import annotations

import csv
import re
from typing import IO, Any, Dict, Iterator, Optional, Mapping, Tuple

from cytlmonitor.io.reader import EventReader

_INTEGER = re.compile(r'[+-]?\d+')
_DECIMAL = re.compile(r'[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?')


def parse_cell(text: str) -> Any:
    """The value of a CSV cell: None if it is empty, a ``bool`` for
    ``true`` or ``false`` (in any case), an ``int`` or a ``float`` for a
    number, and the text itself otherwise."""
    text = text.strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered in ('true', 'false'):
        return lowered == 'true'
    if _INTEGER.fullmatch(text):
        return int(text)
    if _DECIMAL.fullmatch(text):
        return float(text)
    return text


class CsvEventReader(EventReader):
    """Reads a sequence of events from a CSV file whose first row names the
    columns, the first being the time."""

    __slots__ = ('_delimiter',)

    def __init__(self, schema: Optional[Mapping[str, type]] = None, delimiter: str = ','):
        super().__init__(schema)
        if not isinstance(delimiter, str) or len(delimiter) != 1:
            raise ValueError(f"The delimiter must be a single character, got {delimiter!r}")
        self._delimiter = delimiter

    @property
    def delimiter(self) -> str:
        """The character separating the cells of a row."""
        return self._delimiter

    def _records(self, handle: IO[str], error) -> Iterator[Tuple[str, Any, Dict[str, Any]]]:
        rows = csv.reader(handle, delimiter=self._delimiter)
        try:
            header = next(rows, None)
            while header is not None and not any(c.strip() for c in header):
                header = next(rows, None)
            if header is None:
                raise error('the file is empty: the first row must name the columns', None)
            location = f'line {rows.line_num}'
            names = [c.strip() for c in header]
            if len(names) < 1 or not names[0]:
                raise error('the first column, the time, has no name', location)
            fields = names[1:]
            for k, name in enumerate(fields, start=2):
                if not name:
                    raise error(f'column {k} has no name', location)
            duplicates = sorted({n for n in names if names.count(n) > 1})
            if duplicates:
                raise error(f'columns named more than once: {duplicates}', location)

            text_fields = {name for name in fields
                           if self._schema is not None and self._schema.get(name) is str}
            for row in rows:
                if not any(c.strip() for c in row):
                    continue
                location = f'line {rows.line_num}'
                if len(row) != len(names):
                    raise error(f'expected {len(names)} values, one per column, got {len(row)}',
                                location)
                values = {}
                for name, cell in zip(fields, row[1:]):
                    if name in text_fields:
                        values[name] = cell.strip() or None
                    else:
                        values[name] = parse_cell(cell)
                yield location, parse_cell(row[0]), values
        except csv.Error as err:
            raise error(f'not valid CSV: {err}', f'line {rows.line_num}') from err
