"""Random trees of expressions and monitors fed with streams whose
timestamps are awkward floats (tenths, thirds, near-duplicates, epoch
times). Rounding must never break an operator: no exception, and the
published signals keep their contracts."""

import random
import unittest

from cytlmonitor import (
    AbsExpression, AndMonitor, AtomicGeqMonitor, AtomicGreaterMonitor, AtomicLeqMonitor,
    AtomicLessMonitor, BooleanSignal, BooleanSignalConsumer, ConstantExpression,
    DifferenceExpression, DivisionExpression, Event, EventuallyMonitor, FalseMonitor,
    GloballyMonitor, ImplyMonitor, Interval, MaxWindowExpression, MinWindowExpression,
    NegationExpression, NotMonitor, OrMonitor, Payload, ProductExpression, ShiftExpression,
    SignalConsumer, SinceMonitor, SumExpression, SumWindowExpression, TrueMonitor, UntilMonitor,
)


def stream(rng):
    t = rng.choice([0.0, 0.1, 1e6 + 1 / 3, 1_700_000_000.123456])
    events = []
    for _ in range(rng.randint(50, 200)):
        t += rng.choice([0.1, 0.3, 1 / 3, 0.7, 1e-9, 0.0, 2.2, 0.05])
        events.append(Event(t, Payload({'x': rng.choice([0, 1, 2])})))
    return events


def window(rng):
    a = rng.choice([0, 0.1, 1 / 3, 1])
    return a, a + rng.choice([0.1, 0.3, 1, 2.5, 1 / 3])


def count(rng):
    return SumWindowExpression(lambda e: e.payload['x'], *window(rng))


def expression(rng, depth):
    k = rng.randrange(7 if depth else 2)
    if k == 0:
        return count(rng)
    if k == 1:
        return ConstantExpression(rng.choice([0, 1, 2.5]))
    if k == 2:
        return ShiftExpression(expression(rng, depth - 1), rng.choice([0.1, 1 / 3, 2, -0.3, -1, 10]))
    if k == 3:
        op = rng.choice([SumExpression, DifferenceExpression, ProductExpression])
        return op(expression(rng, depth - 1), expression(rng, depth - 1))
    if k == 4:
        a, b = window(rng)
        last = ShiftExpression(SumWindowExpression(lambda e: e.payload['x'], a, b), b)
        return rng.choice([MaxWindowExpression, MinWindowExpression])(last, *window(rng))
    if k == 5:
        return rng.choice([NegationExpression, AbsExpression])(expression(rng, depth - 1))
    return DivisionExpression(expression(rng, depth - 1), ConstantExpression(rng.choice([1, 3])))


def interval(rng, bounded=True):
    a = rng.choice([0, 0.1, 1 / 3, 1])
    if not bounded and rng.random() < 0.3:
        return Interval(a, None, left_open=rng.random() < 0.5)
    b = a + rng.choice([0, 0.1, 0.3, 1, 2.5])
    if a == b:
        return Interval.point(a)
    return Interval(a, b, left_open=rng.random() < 0.5, right_open=rng.random() < 0.5)


def monitor(rng, depth):
    k = rng.randrange(9 if depth else 2)
    if k <= 1:
        op = rng.choice([AtomicLessMonitor, AtomicLeqMonitor, AtomicGreaterMonitor, AtomicGeqMonitor])
        return op(expression(rng, 2), expression(rng, 1))
    if k == 2:
        return NotMonitor(monitor(rng, depth - 1))
    if k == 3:
        op = rng.choice([AndMonitor, OrMonitor, ImplyMonitor])
        return op(monitor(rng, depth - 1), monitor(rng, depth - 1))
    if k == 4:
        return EventuallyMonitor(monitor(rng, depth - 1), interval(rng, bounded=False))
    if k == 5:
        return GloballyMonitor(monitor(rng, depth - 1), interval(rng, bounded=False))
    if k == 6:
        return UntilMonitor(monitor(rng, depth - 1), monitor(rng, depth - 1), interval(rng))
    if k == 7:
        return SinceMonitor(monitor(rng, depth - 1), monitor(rng, depth - 1),
                            interval(rng, bounded=False))
    return rng.choice([TrueMonitor, FalseMonitor])()


class CheckedBooleanSignal(BooleanSignalConsumer):
    """Fails on intervals out of order, intervals starting before the
    horizon, and horizons moving back."""

    def __init__(self):
        self.signal = BooleanSignal()
        self.horizon = 0.0

    def consume(self, i):
        assert i.start >= self.horizon, f'{i} starts before the horizon {self.horizon}'
        self.signal.add(i)

    def set_horizon(self, t):
        assert t >= self.horizon, f'the horizon moved back from {self.horizon} to {t}'
        self.horizon = t


class CheckedSignal(SignalConsumer):
    """Fails unless the segments start at 0 and are contiguous."""

    def __init__(self):
        self.last = None

    def consume(self, s):
        i = s.interval
        if self.last is None:
            assert i.start == 0 and not i.left_open, f'{i} is the first segment'
        else:
            assert i.start == self.last.end and i.left_open != self.last.right_open, \
                f'{i} does not continue {self.last}'
        self.last = i


class TestFloatTimestamps(unittest.TestCase):

    def test_random_monitors(self):
        rng = random.Random(0)
        for k in range(300):
            m, events = monitor(rng, 3), stream(rng)
            m.add(CheckedBooleanSignal())
            with self.subTest(tree=k):
                for e in events:
                    m.consume(e)

    def test_random_expressions(self):
        rng = random.Random(1)
        for k in range(300):
            x, events = expression(rng, 3), stream(rng)
            x.add(CheckedSignal())
            with self.subTest(tree=k):
                for e in events:
                    x.consume(e)


if __name__ == '__main__':
    unittest.main()
