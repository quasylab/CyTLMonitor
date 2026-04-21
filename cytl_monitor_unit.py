from __future__ import annotations
from dataclasses import dataclass
from typing import Generic, List, Optional, Protocol, TypeVar

T = TypeVar('T')


# =========================
# TIMED EVENT
# =========================
class TimedEvent:
    def get_time(self) -> float:
        raise NotImplementedError()


@dataclass
class Payload:
    data: dict

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __getattr__(self, item):
        # Only called for attributes not found normally
        try:
            return self.data[item]
        except KeyError:
            return None


@dataclass
class PacketEvent(TimedEvent):
    timestamp: float
    payload: Payload

    def get_time(self) -> float:
        return self.timestamp


# =========================
# SEGMENT
# =========================
@dataclass
class Segment:
    start_time: float
    end_time: float
    value: float

    def __post_init__(self):
        if self.end_time < self.start_time:
            raise ValueError(
                f"Segment end_time ({self.end_time}) must be >= start_time ({self.start_time})"
            )

    def duration(self) -> float:
        return self.end_time - self.start_time

    def __repr__(self):
        return f"Segment([{self.start_time}, {self.end_time}], val={self.value})"


# =========================
# SEGMENT COLLECTOR
# =========================
class SegmentCollector:
    """Accumulates segments into a list. Use as consumer or standalone history."""

    def __init__(self):
        self.segments: List[Segment] = []

    def consume(self, segment: Segment) -> None:
        self.segments.append(segment)

    def clear(self) -> None:
        self.segments.clear()

    def __len__(self):
        return len(self.segments)


# =========================
# CONSUMER PROTOCOL
# =========================
class SegmentConsumer(Protocol):
    def consume(self, segment: Segment) -> None:
        ...


# =========================
# ATOMIC MONITOR UNIT
# =========================
class AtomicExpressionMonitorUnit(Generic[T]):
    def __init__(self, initial_value: float = 0.0):
        self.last_time: Optional[float] = None
        self.value: float = initial_value
        self._initial_value: float = initial_value
        self.consumers: List[SegmentConsumer] = []

    def add_consumer(self, consumer: SegmentConsumer):
        self.consumers.append(consumer)

    def dispatch(self, segment: Segment):
        for c in self.consumers:
            c.consume(segment)

    def evaluate_event(self, event: T) -> float:
        raise NotImplementedError()

    def on_event(self, event: T):
        t = event.get_time()

        if self.last_time is not None and t <= self.last_time:
            raise ValueError(
                f"Timestamps must be strictly increasing: "
                f"got {t} after {self.last_time}"
            )

        start = self.last_time if self.last_time is not None else 0.0
        seg = Segment(start, t, self.value)
        self.dispatch(seg)

        self.value = self.evaluate_event(event)
        self.last_time = t

    def flush(self, end_time: float):
        start = self.last_time if self.last_time is not None else 0.0
        seg = Segment(start, end_time, self.value)
        self.dispatch(seg)

    def reset(self, initial_value: Optional[float] = None):
        self.last_time = None
        if initial_value is not None:
            self.value = initial_value
            self._initial_value = initial_value
        else:
            self.value = self._initial_value
