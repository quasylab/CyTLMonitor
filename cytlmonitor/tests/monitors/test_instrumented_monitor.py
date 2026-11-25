"""Unit tests for cytlmonitor.monitors.instrumented.InstrumentedMonitor."""

import unittest

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.consumer import EventConsumer
from cytlmonitor.events.event import Event
from cytlmonitor.events.payload import Payload
from cytlmonitor.events.relations import EventRelation, PreviousRelation, SessionRelation
from cytlmonitor.monitors.base import EventMonitor
from cytlmonitor.monitors.boolean import AndMonitor
from cytlmonitor.monitors.constants import TrueMonitor
from cytlmonitor.monitors.filter import FilterMonitor
from cytlmonitor.monitors.instrumented import InstrumentedMonitor


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.log = []

    def consume(self, i):
        self.log.append(('interval', i))

    def set_horizon(self, t):
        self.log.append(('horizon', t))


class Replay(EventMonitor):
    """Records the events it consumes, with what ``probe`` returns for each,
    and publishes the next batch of intervals and then the next horizon."""

    def __init__(self, steps=(), probe=None):
        super().__init__()
        self.steps = list(steps)
        self.probe = probe
        self.events = []
        self.probed = []

    def consume(self, e):
        self.events.append(e)
        if self.probe is not None:
            self.probed.append(self.probe(e))
        if not self.steps:
            return
        intervals, horizon = self.steps.pop(0)
        for i in intervals:
            self.publish(i)
        if horizon is not None:
            self.publish_horizon(horizon)


class Rejecting(EventRelation):
    """Relates every event to an event never processed."""

    def record(self, e):
        return Event(e.time + 1, Payload({}))


def event(t, **fields):
    return Event(t, Payload(fields))


class TestConstruction(unittest.TestCase):

    def test_properties(self):
        r1, r2, m = PreviousRelation(), PreviousRelation(), TrueMonitor()
        im = InstrumentedMonitor([r1, r2], m)
        self.assertEqual(im.relations, (r1, r2))
        self.assertIs(im.m, m)

    def test_accepts_any_iterable_of_relations(self):
        r = PreviousRelation()
        im = InstrumentedMonitor(iter([r]), TrueMonitor())
        self.assertEqual(im.relations, (r,))

    def test_accepts_no_relations(self):
        self.assertEqual(InstrumentedMonitor([], TrueMonitor()).relations, ())

    def test_relations_are_copied(self):
        relations = [PreviousRelation()]
        im = InstrumentedMonitor(relations, TrueMonitor())
        relations.append(PreviousRelation())
        self.assertEqual(len(im.relations), 1)

    def test_rejects_non_relation(self):
        with self.assertRaises(TypeError):
            InstrumentedMonitor([PreviousRelation(), object()], TrueMonitor())

    def test_rejects_non_monitor(self):
        with self.assertRaises(TypeError):
            InstrumentedMonitor([PreviousRelation()], object())

    def test_rejects_non_event(self):
        with self.assertRaises(TypeError):
            InstrumentedMonitor([], TrueMonitor()).consume(1.0)


class TestEvents(unittest.TestCase):

    def test_every_event_reaches_relations_and_monitor(self):
        r = PreviousRelation()
        inner = Replay()
        im = InstrumentedMonitor([r], inner)
        events = [event(t) for t in (1, 2, 3)]
        for e in events:
            im.consume(e)
        self.assertEqual(inner.events, events)
        for prev, e in zip(events, events[1:]):
            self.assertIs(r.get(e), prev)

    def test_relations_are_updated_before_the_monitor(self):
        r = PreviousRelation()
        inner = Replay(probe=r.eval(lambda p: p.time, -1.0))
        im = InstrumentedMonitor([r], inner)
        for t in (1, 2, 4):
            im.consume(event(t))
        self.assertEqual(inner.probed, [-1.0, 1.0, 2.0])

    def test_relations_are_updated_in_order(self):
        order = []

        class Probe(EventConsumer):
            def __init__(self, name):
                self.name = name

            def consume(self, e):
                order.append(self.name)

        r1, r2 = PreviousRelation(), PreviousRelation()
        r1.add(Probe('r1'))
        r2.add(Probe('r2'))
        im = InstrumentedMonitor([r1, r2], Replay(probe=lambda e: order.append('m')))
        im.consume(event(1))
        self.assertEqual(order, ['r1', 'r2', 'm'])

    def test_several_relations(self):
        previous = PreviousRelation()
        sessions = SessionRelation(lambda e: e.payload.get('open'),
                                   lambda e: e.payload.get('close'))
        inner = Replay(probe=lambda e: (previous.eval(lambda p: p.time, 0.0)(e),
                                        sessions.eval(lambda p: p.time, 0.0)(e)))
        im = InstrumentedMonitor([previous, sessions], inner)
        for e in [event(1, open=1), event(2), event(3, close=1)]:
            im.consume(e)
        self.assertEqual(inner.probed, [(0.0, 0.0), (1.0, 0.0), (2.0, 1.0)])

    def test_rejected_event_does_not_reach_the_monitor(self):
        inner = Replay()
        im = InstrumentedMonitor([Rejecting()], inner)
        with self.assertRaises(ValueError):
            im.consume(event(1))
        self.assertEqual(inner.events, [])


class TestOutput(unittest.TestCase):

    def test_republishes_intervals_and_horizons_in_order(self):
        steps = [([Interval(0, 1)], 1), ([], None), ([Interval(2, 3, right_open=False)], 3)]
        im = InstrumentedMonitor([PreviousRelation()], Replay(steps))
        out = RecordingConsumer()
        im.add(out)
        for t in (1, 2, 3):
            im.consume(event(t))
        self.assertEqual(out.log, [
            ('interval', Interval(0, 1)), ('horizon', 1.0),
            ('interval', Interval(2, 3, right_open=False)), ('horizon', 3.0),
        ])

    def test_monitor_using_a_relation(self):
        # Pass to the inner monitor only the events whose previous one is set.
        previous = PreviousRelation()
        after_set = previous.eval(lambda p: float(p.payload['on']), 0.0)
        im = InstrumentedMonitor([previous], FilterMonitor(lambda e: after_set(e) == 1.0,
                                                           TrueMonitor()))
        out = RecordingConsumer()
        im.add(out)
        for t, on in [(1, 1), (2, 0), (3, 0), (4, 1), (5, 0)]:
            im.consume(event(t, on=on))
        self.assertEqual(out.log, [('interval', Interval(0, 2)), ('horizon', 2.0),
                                   ('interval', Interval(2, 5)), ('horizon', 5.0)])

    def test_as_operand_of_a_binary_monitor(self):
        m = AndMonitor(TrueMonitor(), InstrumentedMonitor([PreviousRelation()], TrueMonitor()))
        out = RecordingConsumer()
        m.add(out)
        for t in (1, 2):
            m.consume(event(t))
        self.assertEqual(out.log, [('interval', Interval(0, 1)), ('horizon', 1.0),
                                   ('interval', Interval(1, 2)), ('horizon', 2.0)])


if __name__ == '__main__':
    unittest.main()
