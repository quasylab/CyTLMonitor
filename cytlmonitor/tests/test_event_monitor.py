"""Unit tests for cytlmonitor.event_monitor.EventMonitor."""

import unittest

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.event import Event
from cytlmonitor.event_consumer import EventConsumer
from cytlmonitor.event_monitor import EventMonitor
from cytlmonitor.interval import Interval
from cytlmonitor.payload import Payload


class RecordingConsumer(BooleanSignalConsumer):

    def __init__(self, log=None, name=None):
        self.received = []
        self.horizons = []
        self.log = log
        self.name = name

    def consume(self, i):
        self.received.append(i)
        if self.log is not None:
            self.log.append(self.name)

    def set_horizon(self, t):
        self.horizons.append(t)


class FlagMonitor(EventMonitor):
    """Publishes the point interval of every event whose 'flag' is set."""

    def consume(self, e):
        if e['flag']:
            self.publish(Interval.point(e.time))


def event(t, flag):
    return Event(t, Payload({'flag': flag}))


class TestAbstractness(unittest.TestCase):

    def test_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            EventMonitor()

    def test_subclass_without_consume_cannot_be_instantiated(self):
        class Incomplete(EventMonitor):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_is_an_event_consumer(self):
        self.assertIsInstance(FlagMonitor(), EventConsumer)


class TestAdd(unittest.TestCase):

    def test_consumers_are_initially_empty(self):
        self.assertEqual(FlagMonitor()._consumers, [])

    def test_add_appends_at_the_end(self):
        m = FlagMonitor()
        a, b = RecordingConsumer(), RecordingConsumer()
        m.add(a)
        m.add(b)
        self.assertEqual(m._consumers, [a, b])

    def test_add_non_consumer_raises_type_error(self):
        with self.assertRaises(TypeError):
            FlagMonitor().add(lambda i: None)

    def test_add_none_raises_type_error(self):
        with self.assertRaises(TypeError):
            FlagMonitor().add(None)


class TestPublish(unittest.TestCase):

    def test_publish_with_no_consumers_does_nothing(self):
        FlagMonitor().publish(Interval(0, 1))

    def test_interval_is_sent_to_all_consumers(self):
        m = FlagMonitor()
        a, b = RecordingConsumer(), RecordingConsumer()
        m.add(a)
        m.add(b)
        i = Interval(0, 1)
        m.publish(i)
        self.assertEqual(a.received, [i])
        self.assertEqual(b.received, [i])
        self.assertIs(a.received[0], i)

    def test_publish_returns_none(self):
        self.assertIsNone(FlagMonitor().publish(Interval(0, 1)))

    def test_consumers_are_called_in_insertion_order(self):
        log = []
        m = FlagMonitor()
        for name in ('first', 'second', 'third'):
            m.add(RecordingConsumer(log, name))
        m.publish(Interval(0, 1))
        self.assertEqual(log, ['first', 'second', 'third'])

    def test_publish_horizon_is_sent_to_all_consumers(self):
        m = FlagMonitor()
        a, b = RecordingConsumer(), RecordingConsumer()
        m.add(a)
        m.add(b)
        m.publish_horizon(3.0)
        m.publish_horizon(5.0)
        self.assertEqual(a.horizons, [3.0, 5.0])
        self.assertEqual(b.horizons, [3.0, 5.0])
        self.assertEqual(a.received, [])

    def test_publish_horizon_with_no_consumers_does_nothing(self):
        self.assertIsNone(FlagMonitor().publish_horizon(1.0))

    def test_publish_horizon_calls_consumers_in_insertion_order(self):
        log = []

        class Logging(BooleanSignalConsumer):
            def __init__(self, name):
                self.name = name

            def consume(self, i):
                pass

            def set_horizon(self, t):
                log.append(self.name)

        m = FlagMonitor()
        for name in ('first', 'second', 'third'):
            m.add(Logging(name))
        m.publish_horizon(1.0)
        self.assertEqual(log, ['first', 'second', 'third'])

    def test_consume_in_subclass_can_publish(self):
        m = FlagMonitor()
        c = RecordingConsumer()
        m.add(c)
        for t, flag in ((1, True), (2, False), (3, True)):
            m.consume(event(t, flag))
        self.assertEqual(c.received, [Interval.point(1), Interval.point(3)])
        self.assertTrue(c.received[0].is_before(c.received[1]))


if __name__ == '__main__':
    unittest.main()
