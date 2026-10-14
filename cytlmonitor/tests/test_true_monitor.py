"""Unit tests for cytlmonitor.true_monitor.TrueMonitor."""

import unittest

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload
from cytlmonitor.true_monitor import TrueMonitor


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self):
        self.received = []
        self.horizons = []

    def consume(self, i):
        self.received.append(i)

    def set_horizon(self, t):
        self.horizons.append(t)


def event(t):
    return Event(t, Payload({}))


def run(times):
    m = TrueMonitor()
    c = RecordingConsumer()
    m.add(c)
    for t in times:
        m.consume(event(t))
    return c.received


class TestTrueMonitor(unittest.TestCase):

    def test_is_an_event_monitor(self):
        self.assertIsInstance(TrueMonitor(), EventMonitor)

    def test_last_is_initially_zero(self):
        self.assertEqual(TrueMonitor()._last, 0.0)

    def test_no_events_publishes_nothing(self):
        self.assertEqual(run([]), [])

    def test_first_event_publishes_from_zero(self):
        self.assertEqual(run([3]), [Interval(0, 3)])

    def test_each_event_publishes_from_the_previous_one(self):
        self.assertEqual(run([1, 2.5, 4]), [Interval(0, 1), Interval(1, 2.5), Interval(2.5, 4)])

    def test_consume_updates_last(self):
        m = TrueMonitor()
        m.consume(event(2))
        self.assertEqual(m._last, 2.0)

    def test_event_at_time_zero_publishes_nothing(self):
        self.assertEqual(run([0, 2]), [Interval(0, 2)])

    def test_events_with_the_same_time_publish_once(self):
        self.assertEqual(run([1, 1, 3]), [Interval(0, 1), Interval(1, 3)])

    def test_published_intervals_are_ordered(self):
        received = run([1, 2, 5, 9])
        for a, b in zip(received, received[1:]):
            self.assertTrue(a.is_before(b))
            self.assertTrue(a.just_before(b))

    def test_each_event_sets_the_horizon_of_every_consumer(self):
        m = TrueMonitor()
        a, b = RecordingConsumer(), RecordingConsumer()
        m.add(a)
        m.add(b)
        for t in (0, 1, 1, 2.5):
            m.consume(event(t))
        self.assertEqual(a.horizons, [0.0, 1.0, 1.0, 2.5])
        self.assertEqual(b.horizons, a.horizons)

    def test_horizon_is_set_after_the_interval_is_published(self):
        log = []

        class Logging(BooleanSignalConsumer):
            def consume(self, i):
                log.append(('interval', i))

            def set_horizon(self, t):
                log.append(('horizon', t))

        m = TrueMonitor()
        m.add(Logging())
        m.consume(event(2))
        m.consume(event(5))
        self.assertEqual(log, [
            ('interval', Interval(0, 2)), ('horizon', 2.0),
            ('interval', Interval(2, 5)), ('horizon', 5.0),
        ])

    def test_horizon_is_never_before_a_consumed_interval(self):
        m = TrueMonitor()
        c = RecordingConsumer()
        m.add(c)
        for t in (1, 3, 3, 7):
            m.consume(event(t))
        self.assertEqual(c.horizons, sorted(c.horizons))
        self.assertGreaterEqual(c.horizons[-1], c.received[-1].end)

    def test_out_of_order_event_does_not_set_the_horizon(self):
        m = TrueMonitor()
        c = RecordingConsumer()
        m.add(c)
        m.consume(event(2))
        with self.assertRaises(ValueError):
            m.consume(event(1))
        self.assertEqual(c.horizons, [2.0])

    def test_out_of_order_event_raises_value_error(self):
        m = TrueMonitor()
        m.consume(event(2))
        with self.assertRaises(ValueError):
            m.consume(event(1))

    def test_non_event_raises_type_error(self):
        with self.assertRaises(TypeError):
            TrueMonitor().consume(1.0)


if __name__ == '__main__':
    unittest.main()
