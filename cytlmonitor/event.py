"""
cytlmonitor.event
===================
Representation of a timestamped event.

An :class:`Event` couples the time at which something happened with a
:class:`~cytlmonitor.payload.Payload` carrying the event's arguments. Both
fields are read-only.
"""

from __future__ import annotations

from typing import Any

from cytlmonitor.payload import Payload


class Event:
    """An event occurring at a given time, carrying a Payload of arguments."""

    __slots__ = ('_time', '_payload')

    def __init__(self, time: float, payload: Payload):
        if not isinstance(payload, Payload):
            raise TypeError(f"Expected a Payload, got {type(payload).__name__}")
        self._time = float(time)
        self._payload = payload

    @property
    def time(self) -> float:
        """The time at which the event occurred."""
        return self._time

    @property
    def payload(self) -> Payload:
        """The Payload carrying the event's arguments."""
        return self._payload

    def get_time(self) -> float:
        """Return the time at which the event occurred."""
        return self._time

    def get_payload(self) -> Payload:
        """Return the Payload carrying the event's arguments."""
        return self._payload

    def __getitem__(self, field: str) -> Any:
        """``event[field]`` is equivalent to ``event.payload[field]``."""
        return self._payload[field]

    def __eq__(self, other) -> bool:
        if not isinstance(other, Event):
            return NotImplemented
        return self._time == other._time and self._payload == other._payload

    def __repr__(self) -> str:
        return f"Event(time={self._time}, payload={self._payload!r})"
