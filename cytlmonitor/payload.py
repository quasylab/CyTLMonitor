"""
cytlmonitor.payload
=====================
Representation of a read-only payload.

A :class:`Payload` wraps a dictionary mapping field names (``str``) to
arbitrary values (``Any``). It behaves like a read-only ``dict``: values are
looked up with the standard mapping getters (``payload['field']``,
``payload.get('field')``) and the set of fields is available via
``payload.fields()`` (equivalently, iterating over or calling ``.keys()`` on
a ``Payload`` yields the same field names).

The dictionary passed to the constructor is copied, so mutating it after a
``Payload`` has been created has no effect on the instance.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, FrozenSet, Iterator


class Payload(Mapping):
    """A read-only mapping from field names (str) to values (Any)."""

    __slots__ = ('_data',)

    def __init__(self, data: Dict[str, Any]):
        self._data = dict(data)

    def fields(self) -> FrozenSet[str]:
        """The set of fields (i.e. the keys) held by this payload."""
        return frozenset(self._data.keys())

    def __getitem__(self, field: str) -> Any:
        return self._data[field]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __hash__(self) -> int:
        return hash(frozenset(self._data.items()))

    def __repr__(self) -> str:
        return f"Payload({self._data!r})"
