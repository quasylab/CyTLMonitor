"""
cytlmonitor.unary_expression
==============================
Base class for stream expressions transforming, point by point, the
signal of another expression.

A :class:`UnaryExpression` wraps a nested
:class:`~cytlmonitor.stream_expression.StreamExpression` ``arg``. Every
consumed :class:`~cytlmonitor.event.Event` is passed to ``arg``, and every
:class:`~cytlmonitor.segment.Segment` it publishes is transformed by
:meth:`UnaryExpression._apply` into the segments covering the same
interval, which are published at once.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Iterable

from cytlmonitor.event import Event
from cytlmonitor.segment import Segment
from cytlmonitor.signal_consumer import SignalConsumer
from cytlmonitor.stream_expression import StreamExpression


class _Collector(SignalConsumer):
    """SignalConsumer installed in ``arg``, forwarding its segments to the
    owning UnaryExpression."""

    __slots__ = ('_owner',)

    def __init__(self, owner: 'UnaryExpression'):
        self._owner = owner

    def consume(self, s: Segment) -> None:
        for result in self._owner._apply(s):
            self._owner.publish(result)


class UnaryExpression(StreamExpression):
    """A StreamExpression publishing, for each time ``t``, the signal of
    ``arg`` at ``t`` transformed by :meth:`_apply`."""

    __slots__ = ('_arg',)

    def __init__(self, arg: StreamExpression):
        super().__init__()
        if not isinstance(arg, StreamExpression):
            raise TypeError(f"Expected a StreamExpression, got {type(arg).__name__}")
        self._arg = arg
        arg.add(_Collector(self))

    @property
    def arg(self) -> StreamExpression:
        """The expression whose signal is transformed."""
        return self._arg

    def consume(self, event: Event) -> None:
        """Pass ``event`` to ``arg``; the segments it publishes are
        transformed and published."""
        self._arg.consume(event)

    @abstractmethod
    def _apply(self, s: Segment) -> Iterable[Segment]:
        """Return the segments, ordered by time, covering ``s.interval``
        with the transformed signal."""
