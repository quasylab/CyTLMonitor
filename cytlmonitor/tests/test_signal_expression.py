"""Unit tests for cytlmonitor.signal_expression.SignalExpression."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_sequence import EventSequence
from cytlmonitor.interval import Interval
from cytlmonitor.measure import Measure
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal_expression import SignalExpression


def make_event(time, **fields):
    return Event(time, Payload(fields))


class TestEvalMeasure(unittest.TestCase):

    def setUp(self):
        self.measure = Measure(lambda e: e['size'])

    def test_three_events_not_starting_at_zero(self):
        sequence = EventSequence([
            make_event(2.0, size=10),
            make_event(5.0, size=20),
            make_event(9.0, size=30),
        ])
        signal = SignalExpression.eval_measure(self.measure, sequence)
        self.assertEqual(list(signal), [
            Segment(Interval(0, 2, right_open=True), Polynomial.ZERO),
            Segment(Interval.point(2), Polynomial([10.0])),
            Segment(Interval(2, 5, left_open=True, right_open=True), Polynomial.ZERO),
            Segment(Interval.point(5), Polynomial([20.0])),
            Segment(Interval(5, 9, left_open=True, right_open=True), Polynomial.ZERO),
            Segment(Interval.point(9), Polynomial([30.0])),
        ])

    def test_single_event_not_at_zero(self):
        sequence = EventSequence([make_event(3.0, size=7)])
        signal = SignalExpression.eval_measure(self.measure, sequence)
        self.assertEqual(list(signal), [
            Segment(Interval(0, 3, right_open=True), Polynomial.ZERO),
            Segment(Interval.point(3), Polynomial([7.0])),
        ])

    def test_single_event_at_zero_omits_leading_zero_segment(self):
        sequence = EventSequence([make_event(0.0, size=7)])
        signal = SignalExpression.eval_measure(self.measure, sequence)
        self.assertEqual(list(signal), [
            Segment(Interval.point(0.0), Polynomial([7.0])),
        ])

    def test_first_event_at_zero_with_more_events(self):
        sequence = EventSequence([
            make_event(0.0, size=1),
            make_event(4.0, size=2),
        ])
        signal = SignalExpression.eval_measure(self.measure, sequence)
        self.assertEqual(list(signal), [
            Segment(Interval.point(0.0), Polynomial([1.0])),
            Segment(Interval(0, 4, left_open=True, right_open=True), Polynomial.ZERO),
            Segment(Interval.point(4), Polynomial([2.0])),
        ])

    def test_signal_ends_at_the_last_event_with_nothing_after(self):
        sequence = EventSequence([make_event(3.0, size=1)])
        signal = SignalExpression.eval_measure(self.measure, sequence)
        last_interval = signal[-1].interval
        self.assertEqual(last_interval, Interval.point(3.0))

    def test_measure_receives_the_whole_event(self):
        measure = Measure(lambda e: e.get_time() * 2)
        sequence = EventSequence([make_event(3.0), make_event(7.0)])
        signal = SignalExpression.eval_measure(measure, sequence)
        self.assertEqual(signal.value_at(3.0), 6.0)
        self.assertEqual(signal.value_at(7.0), 14.0)

    def test_zero_segments_evaluate_to_zero(self):
        sequence = EventSequence([make_event(2.0, size=10), make_event(5.0, size=20)])
        signal = SignalExpression.eval_measure(self.measure, sequence)
        self.assertEqual(signal.value_at(1.0), 0.0)
        self.assertEqual(signal.value_at(3.5), 0.0)

    def test_empty_sequence_raises_value_error(self):
        with self.assertRaises(ValueError):
            SignalExpression.eval_measure(self.measure, EventSequence())

    def test_non_measure_raises_type_error(self):
        sequence = EventSequence([make_event(1.0)])
        with self.assertRaises(TypeError):
            SignalExpression.eval_measure('not a measure', sequence)

    def test_non_event_sequence_raises_type_error(self):
        with self.assertRaises(TypeError):
            SignalExpression.eval_measure(self.measure, [make_event(1.0)])

    def test_eval_measure_is_a_static_method(self):
        # callable directly on the class, without an instance
        sequence = EventSequence([make_event(1.0, size=5)])
        result = SignalExpression.eval_measure(self.measure, sequence)
        self.assertEqual(result.length(), 2)


if __name__ == '__main__':
    unittest.main()
