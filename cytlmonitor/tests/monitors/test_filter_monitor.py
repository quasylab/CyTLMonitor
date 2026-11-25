"""Unit tests for cytlmonitor.monitors.filter.FilterMonitor."""

import unittest

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.event import Event
from cytlmonitor.events.payload import Payload
from cytlmonitor.monitors.base import EventMonitor
from cytlmonitor.monitors.boolean import AndMonitor
from cytlmonitor.monitors.constants import FalseMonitor, TrueMonitor
from cytlmonitor.monitors.filter import FilterMonitor
from cytlmonitor.monitors.temporal import EventuallyMonitor


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.log = []

    def consume(self, i):
        self.log.append(('interval', i))

    def set_horizon(self, t):
        self.log.append(('horizon', t))


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


class TestFilterMonitorConstruction(unittest.TestCase):

    def test_properties(self):
        inner = TrueMonitor()
        m = FilterMonitor(is_on, inner)
        self.assertIs(m.beta, is_on)
        self.assertIs(m.m, inner)

    def test_rejects_non_callable_predicate(self):
        with self.assertRaises(TypeError):
            FilterMonitor(True, TrueMonitor())

    def test_rejects_non_monitor(self):
        with self.assertRaises(TypeError):
            FilterMonitor(is_on, object())

    def test_rejects_non_event(self):
        m = FilterMonitor(is_on, TrueMonitor())
        with self.assertRaises(TypeError):
            m.consume(1.0)


class TestFilterMonitorEvents(unittest.TestCase):

    def test_passes_only_events_satisfying_the_predicate(self):
        inner = Replay()
        m = FilterMonitor(is_on, inner)
        events = [event(0, on=1), event(1, on=0), event(2, on=1), event(2, on=0),
                  event(3, on=1)]
        for e in events:
            m.consume(e)
        self.assertEqual(inner.events, [events[0], events[2], events[4]])

    def test_events_are_passed_unchanged(self):
        inner = Replay()
        m = FilterMonitor(lambda e: True, inner)
        e = event(1.5, on=1, size=60)
        m.consume(e)
        self.assertIs(inner.events[0], e)

    def test_predicate_never_true(self):
        inner = Replay([([Interval(0, 1)], 1)])
        m = FilterMonitor(lambda e: False, inner)
        out = RecordingConsumer()
        m.add(out)
        for t in range(5):
            m.consume(event(t))
        self.assertEqual(inner.events, [])
        self.assertEqual(out.log, [])


class TestFilterMonitorOutput(unittest.TestCase):

    def test_republishes_intervals_and_horizons_in_order(self):
        steps = [([Interval(0, 1), Interval(2, 3, right_open=False)], 3),
                 ([], None),
                 ([Interval(3, 5, left_open=True)], 5)]
        m = FilterMonitor(is_on, Replay(steps))
        out = RecordingConsumer()
        m.add(out)
        for t, on in [(3, 1), (4, 0), (4, 1), (5, 0), (6, 1)]:
            m.consume(event(t, on=on))
        self.assertEqual(out.log, [
            ('interval', Interval(0, 1)),
            ('interval', Interval(2, 3, right_open=False)),
            ('horizon', 3.0),
            ('interval', Interval(3, 5, left_open=True)),
            ('horizon', 5.0),
        ])

    def test_every_consumer_receives_the_output(self):
        m = FilterMonitor(is_on, TrueMonitor())
        first, second = RecordingConsumer(), RecordingConsumer()
        m.add(first)
        m.add(second)
        m.consume(event(2, on=1))
        expected = [('interval', Interval(0, 2)), ('horizon', 2.0)]
        self.assertEqual(first.log, expected)
        self.assertEqual(second.log, expected)

    def test_horizon_stays_at_the_last_selected_event(self):
        m = FilterMonitor(is_on, TrueMonitor())
        out = RecordingConsumer()
        m.add(out)
        for t, on in [(1, 1), (2, 0), (3, 0), (4, 1), (5, 0)]:
            m.consume(event(t, on=on))
        self.assertEqual(out.log, [
            ('interval', Interval(0, 1)), ('horizon', 1.0),
            ('interval', Interval(1, 4)), ('horizon', 4.0),
        ])

    def test_inner_temporal_monitor_sees_the_sub_stream(self):
        # The inner eventually only advances at the selected events.
        inner = EventuallyMonitor(TrueMonitor(), Interval(0, 1, right_open=False))
        m = FilterMonitor(is_on, inner)
        out = RecordingConsumer()
        m.add(out)
        for t, on in [(1, 1), (2, 0), (3, 1)]:
            m.consume(event(t, on=on))
        self.assertEqual(out.log, [
            ('interval', Interval(0, 1)), ('horizon', 1.0),
            ('interval', Interval(1, 3)), ('horizon', 3.0),
        ])


class TestFilterMonitorComposition(unittest.TestCase):

    def test_as_operand_of_a_binary_monitor(self):
        # The conjunction is held back by the filtered operand, whose
        # horizon only moves at the selected events.
        m = AndMonitor(TrueMonitor(), FilterMonitor(is_on, TrueMonitor()))
        out = RecordingConsumer()
        m.add(out)
        for t, on in [(1, 1), (2, 0), (3, 1)]:
            m.consume(event(t, on=on))
        self.assertEqual(out.log, [
            ('interval', Interval(0, 1)), ('horizon', 1.0),
            ('interval', Interval(1, 3)), ('horizon', 3.0),
        ])

    def test_dominant_value_moves_past_the_filtered_operand(self):
        m = AndMonitor(FalseMonitor(), FilterMonitor(is_on, TrueMonitor()))
        out = RecordingConsumer()
        m.add(out)
        for t in [1, 2, 3]:
            m.consume(event(t, on=0))
        self.assertEqual(out.log, [('horizon', 1.0), ('horizon', 2.0), ('horizon', 3.0)])

    def test_nested_filters_select_the_conjunction(self):
        inner = Replay()
        m = FilterMonitor(lambda e: e.payload.get('a'),
                          FilterMonitor(lambda e: e.payload.get('b'), inner))
        events = [event(0, a=1, b=1), event(1, a=1, b=0), event(2, a=0, b=1),
                  event(3, a=1, b=1)]
        for e in events:
            m.consume(e)
        self.assertEqual(inner.events, [events[0], events[3]])


if __name__ == '__main__':
    unittest.main()
