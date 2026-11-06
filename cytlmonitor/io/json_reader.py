"""
cytlmonitor.io.json_reader
==========================
Reader of sequences of events from JSON files.

The file mirrors :class:`~cytlmonitor.events.event_sequence.EventSequence`,
:class:`~cytlmonitor.events.event.Event` and
:class:`~cytlmonitor.events.payload.Payload`: an object whose ``events`` are
a list of objects, each with a ``time`` and, optionally, a ``payload``
mapping field names to values::

    {
      "events": [
        {"time": 0.5, "payload": {"size": 60, "protocol": "TCP", "tcp_syn": true}},
        {"time": 1.25, "payload": {"size": 1500, "protocol": "UDP"}},
        {"time": 2}
      ]
    }

Other keys are rejected, so that a misspelt ``payload`` is not silently
ignored. Values are booleans, numbers or strings; ``null`` leaves the field
out of that event's payload. ``NaN`` and ``Infinity``, which are not JSON,
are rejected. The checks on times and fields are those of
:class:`~cytlmonitor.io.reader.EventReader`; problems are reported with the
index of the event, from 0.
"""

from __future__ import annotations

import json
from typing import IO, Any, Dict, Iterator, Tuple

from cytlmonitor.io.reader import EventReader


def _reject_constant(name: str):
    raise ValueError(f'{name} is not a valid JSON value')


class JsonEventReader(EventReader):
    """Reads a sequence of events from a JSON file shaped as an
    EventSequence of Events with their Payloads."""

    __slots__ = ()

    def _records(self, handle: IO[str], error) -> Iterator[Tuple[str, Any, Dict[str, Any]]]:
        try:
            document = json.load(handle, parse_constant=_reject_constant)
        except ValueError as err:
            raise error(f'not valid JSON: {err}', None) from err
        if not isinstance(document, dict):
            raise error(f'expected an object with the events, got {type(document).__name__}',
                        None)
        extra = sorted(set(document) - {'events'})
        if 'events' not in document:
            raise error("missing key 'events'" + (f'; unexpected keys {extra}' if extra else ''),
                        None)
        if extra:
            raise error(f'unexpected keys {extra}', None)
        events = document['events']
        if not isinstance(events, list):
            raise error(f"'events' must be a list, got {type(events).__name__}", None)
        for index, record in enumerate(events):
            location = f'event {index}'
            if not isinstance(record, dict):
                raise error(f'an event must be an object, got {type(record).__name__}', location)
            extra = sorted(set(record) - {'time', 'payload'})
            if extra:
                raise error(f'unexpected keys {extra}', location)
            if 'time' not in record:
                raise error('the time is missing', location)
            payload = record.get('payload', {})
            if not isinstance(payload, dict):
                raise error(f"'payload' must be an object, got {type(payload).__name__}",
                            location)
            yield location, record['time'], payload
