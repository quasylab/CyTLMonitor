"""Unit tests for cytlmonitor.monitors.next.NextMonitor."""

import math
import random
import unittest

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.core.boolean_signal import BooleanSignal
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.event import Event
from cytlmonitor.events.payload import Payload
from cytlmonitor.monitors.base import EventMonitor
from cytlmonitor.monitors.boolean import AndMonitor
from cytlmonitor.monitors.constants import FalseMonitor, TrueMonitor
from cytlmonitor.monitors.next import NextMonitor
from cytlmonitor.monitors.temporal import EventuallyMonitor


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.log = []

    def consume(self, i):
        self.log.append(('interval', i))

    def set_horizon(self, t):
        self.log.append(('horizon', t))


class SignalConsumer(BooleanSignalConsumer):
    """Collects the published signal, checking the publication protocol."""

    def __init__(self, test):
        self.test = test
        self.signal = BooleanSignal()
        self.horizon = 0.0

    def consume(self, i):
        self.test.assertGreaterEqual(i.start, self.horizon)
        self.signal.add(i)

    def set_horizon(self, t):
        self.test.assertGreaterEqual(t, self.horizon)
        for i in self.signal:
            self.test.assertLessEqual(i.end, t)
        self.horizon = t


class Flag(EventMonitor):
    """True from each event whose payload sets ``field`` up to the next
    event; known up to the latest event."""

    def __init__(self, field):
        super().__init__()
        self.field, self.since, self.on = field, 0.0, False

    def consume(self, e):
        if self.on and e.time > self.since:
            self.publish(Interval(self.since, e.time))
        self.on, self.since = bool(e.payload.get(self.field)), e.time
        self.publish_horizon(e.time)


class Replay(EventMonitor):
    """Records the events it consumes and, for each, publishes the next
    batch of intervals and then the next horizon (if it is not None)."""

    def __init__(self, steps=()):
        super().__init__()
        self.steps = list(steps)
        self.events = []

    def consume(self, e):
        self.events.append(e)
        if not self.steps:
            return
        intervals, horizon = self.steps.pop(0)
        for i in intervals:
            self.publish(i)
        if horizon is not None:
            self.publish_horizon(horizon)


def event(t, **fields):
    return Event(t, Payload(fields))


def is_on(e):
    return bool(e.payload.get('on'))


def run(monitor, events):
    out = RecordingConsumer()
    monitor.add(out)
    for e in events:
        monitor.consume(e)
    return out.log


class TestNextMonitorConstruction(unittest.TestCase):

    def test_properties(self):
        inner = TrueMonitor()
        m = NextMonitor(is_on, 1, 2, inner)
        self.assertIs(m.beta, is_on)
        self.assertEqual(m.a, 1.0)
        self.assertEqual(m.b, 2.0)
        self.assertIs(m.inner, inner)

    def test_rejects_non_callable_predicate(self):
        with self.assertRaises(TypeError):
            NextMonitor(True, 0, 1, TrueMonitor())

    def test_rejects_non_monitor(self):
        with self.assertRaises(TypeError):
            NextMonitor(is_on, 0, 1, object())

    def test_rejects_invalid_bounds(self):
        for a, b in [(-1, 1), (1, 1), (2, 1), (math.nan, 1), (0, math.nan)]:
            with self.subTest(a=a, b=b), self.assertRaises(ValueError):
                NextMonitor(is_on, a, b, TrueMonitor())

    def test_accepts_unbounded_b(self):
        m = NextMonitor(is_on, 0, math.inf, TrueMonitor())
        self.assertEqual(m.b, math.inf)

    def test_rejects_non_event(self):
        with self.assertRaises(TypeError):
            NextMonitor(is_on, 0, 1, TrueMonitor()).consume(1.0)

    def test_rejects_events_out_of_order(self):
        m = NextMonitor(is_on, 0, 1, TrueMonitor())
        m.consume(event(2))
        with self.assertRaises(ValueError):
            m.consume(event(1))


class TestNextMonitorSemantics(unittest.TestCase):

    def test_true_before_a_selected_event(self):
        # The event at 3 is the next one for t in [1, 3); within [0, 1]
        # from t only for t in [2, 3).
        log = run(NextMonitor(is_on, 0, 1, TrueMonitor()),
                  [event(1), event(3, on=1), event(4)])
        self.assertEqual(log, [
            ('horizon', 1.0),
            # At 3 the stretch [2, 3) waits for TrueMonitor to be known at 3.
            ('horizon', 2.0),
            ('interval', Interval(2, 3)), ('horizon', 4.0),
        ])

    def test_lower_bound_closes_the_stretch(self):
        log = run(NextMonitor(is_on, 0.5, 1, TrueMonitor()),
                  [event(1), event(3, on=1), event(4)])
        self.assertIn(('interval', Interval(2, 2.5, right_open=False)), log)

    def test_stretch_is_cut_at_the_previous_event(self):
        # With a wide window the stretch starts at the previous event.
        log = run(NextMonitor(is_on, 0, 10, TrueMonitor()),
                  [event(1), event(3, on=1), event(4)])
        self.assertIn(('interval', Interval(1, 3)), log)

    def test_window_beyond_the_stretch_is_empty(self):
        # The event at 3 is the next one only for t in [2, 3), where its
        # delay is at most 1 < a.
        log = run(NextMonitor(is_on, 1.5, 2, TrueMonitor()),
                  [event(2), event(3, on=1), event(4)])
        self.assertEqual([m for m in log if m[0] == 'interval'], [])
        self.assertEqual(log[-1], ('horizon', 4.0))

    def test_unbounded_window(self):
        log = run(NextMonitor(is_on, 1, math.inf, TrueMonitor()),
                  [event(3, on=1), event(4)])
        self.assertIn(('interval', Interval(0, 2, right_open=False)), log)

    def test_event_not_satisfying_the_predicate(self):
        log = run(NextMonitor(is_on, 0, 1, TrueMonitor()),
                  [event(1), event(2), event(3)])
        self.assertEqual(log, [('horizon', 1.0), ('horizon', 2.0), ('horizon', 3.0)])

    def test_inner_false_at_the_next_event(self):
        # Each stretch [l, τ) is settled, as false, once FalseMonitor is
        # known beyond τ, at the following event.
        log = run(NextMonitor(is_on, 0, 1, FalseMonitor()),
                  [event(1, on=1), event(2, on=1), event(3)])
        self.assertEqual(log, [('horizon', 1.0), ('horizon', 3.0)])

    def test_only_the_first_event_at_a_time_is_the_next_event(self):
        log = run(NextMonitor(is_on, 0, 1, TrueMonitor()),
                  [event(1), event(1, on=1), event(2), event(2, on=1), event(3)])
        self.assertEqual([m for m in log if m[0] == 'interval'], [])
        log = run(NextMonitor(is_on, 0, 1, TrueMonitor()),
                  [event(1, on=1), event(1), event(2)])
        self.assertIn(('interval', Interval(0, 1)), log)

    def test_event_at_time_zero_is_never_next(self):
        log = run(NextMonitor(is_on, 0, 1, TrueMonitor()),
                  [event(0, on=1), event(1), event(2)])
        self.assertEqual([m for m in log if m[0] == 'interval'], [])

    def test_inner_sees_every_event(self):
        inner = Replay()
        events = [event(1), event(1, on=1), event(2, on=1)]
        run(NextMonitor(is_on, 0, 1, inner), events)
        self.assertEqual(inner.events, events)

    def test_inner_value_taken_at_the_next_event(self):
        # Flag('a') holds on [1, 3): true at 2, false at 3.
        log = run(NextMonitor(is_on, 0, 1, Flag('a')),
                  [event(1, a=1), event(2, on=1, a=1), event(3, on=1, a=0), event(4)])
        self.assertEqual([m for m in log if m[0] == 'interval'],
                         [('interval', Interval(1, 2))])


class TestNextMonitorPublication(unittest.TestCase):

    def test_waits_for_the_inner_monitor(self):
        # TrueMonitor is known up to 3 at the event at 3, not at 3 itself.
        log = run(NextMonitor(is_on, 0, 1, TrueMonitor()),
                  [event(1), event(3, on=1)])
        self.assertEqual(log, [('horizon', 1.0), ('horizon', 2.0)])

    def test_settled_at_once_when_the_inner_value_is_known(self):
        # An inner interval reaching beyond the event settles the stretch.
        steps = [([], 1), ([Interval(1, 5)], 3)]
        log = run(NextMonitor(is_on, 0, 1, Replay(steps)), [event(1), event(3, on=1)])
        self.assertEqual(log, [
            ('horizon', 1.0),
            ('interval', Interval(2, 3)), ('horizon', 3.0),
        ])

    def test_lagging_inner_monitor_holds_back_the_horizon(self):
        # An eventually with window [0, 2] over a false argument is known
        # 2 behind it: after the event at 6 it is known on [0, 4), so the
        # stretch [3, 4), waiting for its value at 4, is not settled.
        inner = EventuallyMonitor(FalseMonitor(), Interval(0, 2, right_open=False))
        m = NextMonitor(is_on, 0, 1, inner)
        log = run(m, [event(t, on=1) for t in range(1, 7)])
        self.assertEqual(log[-1], ('horizon', 3.0))
        self.assertEqual([i for kind, i in log if kind == 'interval'], [])

    def test_as_operand_of_a_binary_monitor(self):
        m = AndMonitor(TrueMonitor(), NextMonitor(is_on, 0, 1, TrueMonitor()))
        log = run(m, [event(1, on=1), event(2), event(3)])
        self.assertEqual(log, [
            ('interval', Interval(0, 1)), ('horizon', 2.0), ('horizon', 3.0),
        ])

    def test_memory_stays_bounded(self):
        m = NextMonitor(is_on, 0, 1, TrueMonitor())
        for t in range(1, 1000):
            m.consume(event(t, on=t % 2))
        self.assertLessEqual(len(m._pending), 1)
        self.assertLessEqual(len(m._input.intervals), 1)


class TestNextMonitorRandom(unittest.TestCase):
    """Compares the monitor with a direct evaluation of the definition."""

    def check(self, rng):
        a = rng.choice([0.0, 0.25, 0.5, 1.0])
        b = rng.choice([a + 0.25, a + 1.0, a + 3.0, math.inf])
        times, t = [], 0.0
        for _ in range(rng.randint(1, 30)):
            t += rng.choice([0.0, 0.25, 0.5, 1.0, 2.5])
            times.append(t)
        events = [event(t, on=rng.random() < 0.6, a=rng.random() < 0.5) for t in times]

        out = SignalConsumer(self)
        monitor = NextMonitor(is_on, a, b, Flag('a'))
        monitor.add(out)
        flag_out = SignalConsumer(self)
        reference_flag = Flag('a')
        reference_flag.add(flag_out)
        for e in events:
            monitor.consume(e)
            reference_flag.consume(e)

        def expected(x):
            nxt = next((e for e in events if e.time > x), None)
            if nxt is None or not (x + a <= nxt.time <= x + b) or not is_on(nxt):
                return None if nxt is None else False
            if nxt.time >= flag_out.horizon:
                return None
            return any(i.contains(nxt.time) for i in flag_out.signal)

        points = sorted({p for e in events for p in
                         (e.time, e.time - a, e.time - b, e.time + 0.1, e.time - a - 0.1,
                          e.time - b + 0.1) if p >= 0 and math.isfinite(p)} | {0.0})
        for x in points:
            if x >= out.horizon:
                continue
            value = expected(x)
            self.assertIsNotNone(value, (x, out.horizon))
            self.assertEqual(any(i.contains(x) for i in out.signal), value,
                             (x, a, b, times))
        # The signal is known up to the latest event whose value is decided.
        self.assertLessEqual(out.horizon, times[-1])

    def test_random_streams(self):
        rng = random.Random(1234)
        for _ in range(300):
            self.check(rng)


if __name__ == '__main__':
    unittest.main()
