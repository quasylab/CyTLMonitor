"""
cytlmonitor.signal_consumer
=============================
Interface for objects that process streams of signal segments.

A :class:`SignalConsumer` receives :class:`~cytlmonitor.segment.Segment`
instances one at a time through :meth:`SignalConsumer.consume`. Concrete
classes implement this method to define how each incoming segment is
processed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from cytlmonitor.segment import Segment


class SignalConsumer(ABC):
    """Interface implemented by classes that process a stream of Segments."""

    __slots__ = ()

    @abstractmethod
    def consume(self, s: Segment) -> None:
        """Process a single incoming segment ``s``."""
