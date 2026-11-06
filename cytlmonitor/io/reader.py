"""
cytlmonitor.io.reader
=====================
Base class of the readers building a sequence of events from a file.

An :class:`EventReader` turns the records of a file into
:class:`~cytlmonitor.events.event.Event` instances, checking them on the way:

* the time of every event is a finite number, not negative, and strictly
  greater than the time of the event before it (as
  :class:`~cytlmonitor.events.event_sequence.EventSequence` requires);
* every field keeps the same type across the events: a boolean, a number
  (an ``int`` or a ``float``) or a string. Without a schema, the type of a
  field is set by its first value. With a schema, a mapping from field names
  to ``bool``, ``int``, ``float`` or ``str``, the types are fixed in advance,
  the values are converted (an ``int`` to a ``float`` for a ``float``
  field), and fields missing from the schema are rejected.

A missing value leaves the field out of that event's payload: events do not
all need the same fields.

Any problem raises an :class:`EventFormatError` telling where it is.

Subclasses read a format: they implement :meth:`EventReader._records`,
yielding for each record where it is in the file, its time and its fields,
as Python values.
"""

from __future__ import annotations

import math
import os
from abc import ABC, abstractmethod
from typing import IO, Any, Dict, Iterator, Mapping, Optional, Tuple, Union

from cytlmonitor.events.event import Event
from cytlmonitor.events.event_sequence import EventSequence
from cytlmonitor.events.payload import Payload

#: What a reader reads from: a path, or a text file already open.
Source = Union[str, 'os.PathLike[str]', IO[str]]

#: The types a schema may give a field.
FIELD_TYPES = (bool, int, float, str)

_KIND_NAMES = {bool: 'a boolean', int: 'an integer', float: 'a number', str: 'a string'}


class EventFormatError(ValueError):
    """A file that does not describe a valid sequence of events.

    ``source`` is the name of the file (None if it has none), ``location``
    where the problem is in it (such as ``'line 4'``), and ``reason`` what
    the problem is."""

    def __init__(self, reason: str, source: Optional[str] = None,
                 location: Optional[str] = None):
        self.reason = reason
        self.source = source
        self.location = location
        where = ', '.join(p for p in (source, location) if p)
        super().__init__(f'{where}: {reason}' if where else reason)


def _kind(value: Any) -> Optional[type]:
    """``bool``, ``float`` (for any number) or ``str``: the type ``value``
    counts as in a payload, or None if it is none of them."""
    if isinstance(value, bool):
        return bool
    if isinstance(value, (int, float)):
        return float
    if isinstance(value, str):
        return str
    return None


def _finite(number) -> bool:
    """True if ``number``, an ``int`` or a ``float``, is finite (an ``int``
    always is, however large)."""
    return isinstance(number, int) or math.isfinite(number)


def _describe(value: Any) -> str:
    kind = _kind(value)
    name = _KIND_NAMES[kind] if kind else f'a {type(value).__name__}'
    return f'{name} ({value!r})'


class _Checker:
    """Checks the records of one file, in order, and builds their events."""

    def __init__(self, schema: Optional[Dict[str, type]], source: Optional[str]):
        self._schema = schema
        self._source = source
        # Without a schema, the type of each field seen so far, and where
        # it was set.
        self._kinds: Dict[str, Tuple[type, str]] = {}
        self._last_time: Optional[float] = None

    def error(self, reason: str, location: Optional[str]) -> EventFormatError:
        return EventFormatError(reason, self._source, location)

    def event(self, location: str, time: Any, fields: Mapping[str, Any]) -> Event:
        t = self._time(location, time)
        payload = {name: self._value(location, name, value)
                   for name, value in fields.items() if value is not None}
        return Event(t, Payload(payload))

    def _time(self, location: str, time: Any) -> float:
        if time is None:
            raise self.error('the time is missing', location)
        if _kind(time) is not float:
            raise self.error(f'the time must be a number, got {_describe(time)}', location)
        try:
            t = float(time)
        except OverflowError:
            t = math.inf
        if not math.isfinite(t):
            raise self.error(f'the time must be finite, got {time!r}', location)
        if t < 0:
            raise self.error(f'the time must not be negative, got {time!r}', location)
        if self._last_time is not None and t <= self._last_time:
            raise self.error(f'the time {t!r} is not after the time of the previous '
                             f'event, {self._last_time!r}', location)
        self._last_time = t
        return t

    def _value(self, location: str, name: str, value: Any) -> Any:
        kind = _kind(value)
        if kind is None:
            raise self.error(f'field {name!r}: a value must be a boolean, a number or a '
                             f'string, got {_describe(value)}', location)
        if kind is float and not _finite(value):
            raise self.error(f'field {name!r}: a number must be finite, got {value!r}', location)
        if self._schema is not None:
            return self._convert(location, name, value)
        if name not in self._kinds:
            self._kinds[name] = (kind, location)
            return value
        expected, where = self._kinds[name]
        if kind is not expected:
            raise self.error(f'field {name!r}: expected {_KIND_NAMES[expected]}, as at '
                             f'{where}, got {_describe(value)}', location)
        return value

    def _convert(self, location: str, name: str, value: Any) -> Any:
        if name not in self._schema:
            raise self.error(f'field {name!r} is not in the schema', location)
        expected = self._schema[name]
        kind = _kind(value)
        if expected is float and kind is float:
            try:
                return float(value)
            except OverflowError:
                raise self.error(f'field {name!r}: {value!r} is too large for a float',
                                 location) from None
        if expected is int and kind is float and isinstance(value, int):
            return value
        if expected in (bool, str) and kind is expected:
            return value
        raise self.error(f'field {name!r}: expected {_KIND_NAMES[expected]}, '
                         f'got {_describe(value)}', location)


class EventReader(ABC):
    """Reads a sequence of events from a file, checking the times and the
    types of the fields."""

    __slots__ = ('_schema',)

    def __init__(self, schema: Optional[Mapping[str, type]] = None):
        if schema is not None:
            if not isinstance(schema, Mapping):
                raise TypeError(f"Expected a mapping, got {type(schema).__name__}")
            for name, kind in schema.items():
                if not isinstance(name, str):
                    raise TypeError(f"Field names must be strings, got {name!r}")
                if kind not in FIELD_TYPES:
                    raise ValueError(f"Field {name!r}: the type must be bool, int, float or "
                                     f"str, got {kind!r}")
            schema = dict(schema)
        self._schema: Optional[Dict[str, type]] = schema

    @property
    def schema(self) -> Optional[Dict[str, type]]:
        """The type of each field (None if the types are taken from the
        first value of each field)."""
        return None if self._schema is None else dict(self._schema)

    def read(self, source: Source) -> EventSequence:
        """Read every event of ``source``, a path or a text file already
        open, into an EventSequence. Raises an EventFormatError if it is
        not valid."""
        return EventSequence(self.events(source))

    def events(self, source: Source) -> Iterator[Event]:
        """The events of ``source``, a path or a text file already open,
        checked and yielded one at a time, so that a monitor can be fed
        while the file is read. Raises an EventFormatError, at the first
        invalid record, if it is not valid. A file opened from a path is
        closed once the events are over."""
        if isinstance(source, (str, os.PathLike)):
            name = os.fspath(source)
            with open(name, encoding='utf-8', newline='') as handle:
                yield from self._checked(handle, name)
        else:
            yield from self._checked(source, getattr(source, 'name', None))

    def _checked(self, handle: IO[str], name: Optional[str]) -> Iterator[Event]:
        checker = _Checker(self._schema, name if isinstance(name, str) else None)
        for location, time, fields in self._records(handle, checker.error):
            yield checker.event(location, time, fields)

    @abstractmethod
    def _records(self, handle: IO[str], error) -> Iterator[Tuple[str, Any, Dict[str, Any]]]:
        """Yield, for each record of ``handle``, where it is (such as
        ``'line 4'``), its time and its fields, as Python values (None for a
        missing value). ``error(reason, location)`` builds the exception to
        raise for a record that cannot be read."""
