"""Unit tests for cytlmonitor.signal_expression.SignalExpression.apply."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.event_sequence import EventSequence
from cytlmonitor.interval import Interval
from cytlmonitor.measure import Measure
from cytlmonitor.payload import Payload
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal import Signal
from cytlmonitor.signal_expression import SignalExpression


def add_poly(a, b):
    return a.add(b)


class TestApply(unittest.TestCase):

    def test_the_given_example(self):
        p1, p2, p3 = Polynomial([1]), Polynomial([2]), Polynomial([3])
        q1, q2, q3, q4 = Polynomial([10]), Polynomial([20]), Polynomial([30]), Polynomial([40])

        signal1 = Signal([
            Segment(Interval(0, 2, right_open=True), p1),
            Segment(Interval(2, 5, right_open=True), p2),
            Segment(Interval(5, 8, right_open=True), p3),
        ])
        signal2 = Signal([
            Segment(Interval(0, 1, right_open=True), q1),
            Segment(Interval(1, 4, right_open=True), q2),
            Segment(Interval(4, 7, right_open=True), q3),
            Segment(Interval(7, 10, right_open=True), q4),
        ])

        result = SignalExpression.apply(add_poly, signal1, signal2)

        self.assertEqual(list(result), [
            Segment(Interval(0, 1, right_open=True), p1.add(q1)),
            Segment(Interval(1, 2, right_open=True), p1.add(q2)),
            Segment(Interval(2, 4, right_open=True), p2.add(q2)),
            Segment(Interval(4, 5, right_open=True), p2.add(q3)),
            Segment(Interval(5, 7, right_open=True), p3.add(q3)),
            Segment(Interval(7, 8, right_open=True), p3.add(q4)),
            Segment(Interval(8, 10, right_open=True), Polynomial.ZERO.add(q4)),
        ])

    def test_mismatched_open_closed_boundary_mid_signal(self):
        # signal1 is right-open at 1 while signal2 is closed there (then
        # left-open on its second segment): the single point {1} belongs
        # only to signal2, and {2} only to signal2's tail.
        p1, p2 = Polynomial([1]), Polynomial([2])
        q1, q2 = Polynomial([10]), Polynomial([20])
        signal1 = Signal([
            Segment(Interval(0, 1, right_open=True), p1),
            Segment(Interval(1, 2, right_open=True), p2),
        ])
        signal2 = Signal([
            Segment(Interval(0, 1, right_open=False), q1),
            Segment(Interval(1, 2, left_open=True, right_open=False), q2),
        ])

        result = SignalExpression.apply(add_poly, signal1, signal2)

        self.assertEqual(list(result), [
            Segment(Interval(0, 1, right_open=True), p1.add(q1)),
            Segment(Interval.point(1), p2.add(q1)),
            Segment(Interval(1, 2, left_open=True, right_open=True), p2.add(q2)),
            Segment(Interval.point(2), Polynomial.ZERO.add(q2)),
        ])

    def test_identical_boundaries(self):
        signal1 = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([1]))])
        signal2 = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([2]))])
        result = SignalExpression.apply(add_poly, signal1, signal2)
        self.assertEqual(list(result), [
            Segment(Interval(0, 5, right_open=True), Polynomial([3])),
        ])

    def test_second_signal_ends_earlier(self):
        signal1 = Signal([Segment(Interval(0, 10, right_open=True), Polynomial([1]))])
        signal2 = Signal([Segment(Interval(0, 4, right_open=True), Polynomial([2]))])
        result = SignalExpression.apply(add_poly, signal1, signal2)
        self.assertEqual(list(result), [
            Segment(Interval(0, 4, right_open=True), Polynomial([3])),
            Segment(Interval(4, 10, right_open=True), Polynomial([1])),
        ])

    def test_unbounded_trailing_segment(self):
        signal1 = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([1]))])
        signal2 = Signal([
            Segment(Interval(0, 5, right_open=True), Polynomial([2])),
            Segment(Interval(5), Polynomial([3])),
        ])
        result = SignalExpression.apply(add_poly, signal1, signal2)
        self.assertEqual(list(result), [
            Segment(Interval(0, 5, right_open=True), Polynomial([3])),
            Segment(Interval(5), Polynomial([3])),
        ])

    def test_combining_two_eval_measure_signals_from_the_same_sequence(self):
        sequence = EventSequence([
            Event(2.0, Payload({'a': 1, 'b': 10})),
            Event(5.0, Payload({'a': 2, 'b': 20})),
        ])
        signal_a = SignalExpression.eval_measure(Measure(lambda e: e['a']), sequence)
        signal_b = SignalExpression.eval_measure(Measure(lambda e: e['b']), sequence)
        result = SignalExpression.apply(add_poly, signal_a, signal_b)
        self.assertEqual(result.value_at(0.0), 0.0)
        self.assertEqual(result.value_at(2.0), 11.0)
        self.assertEqual(result.value_at(3.5), 0.0)
        self.assertEqual(result.value_at(5.0), 22.0)

    def test_one_signal_empty(self):
        signal1 = Signal()
        signal2 = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([2]))])
        result = SignalExpression.apply(add_poly, signal1, signal2)
        self.assertEqual(list(result), [
            Segment(Interval(0, 5, right_open=True), Polynomial([2])),
        ])

    def test_both_signals_empty(self):
        result = SignalExpression.apply(add_poly, Signal(), Signal())
        self.assertEqual(result.length(), 0)

    def test_misaligned_start_raises_value_error(self):
        # After the shared [0, 3), signal1 continues at 3 but signal2 only at 4.
        signal1 = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([1]))])
        signal2 = Signal([
            Segment(Interval(0, 3, right_open=True), Polynomial([2])),
            Segment(Interval(4, 8, right_open=True), Polynomial([2])),
        ])
        with self.assertRaises(ValueError):
            SignalExpression.apply(add_poly, signal1, signal2)

    def test_custom_function_is_used(self):
        signal1 = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([2]))])
        signal2 = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([3]))])
        result = SignalExpression.apply(lambda a, b: a.mul(b), signal1, signal2)
        self.assertEqual(list(result), [
            Segment(Interval(0, 5, right_open=True), Polynomial([6])),
        ])

    def test_non_callable_raises_type_error(self):
        signal = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([1]))])
        with self.assertRaises(TypeError):
            SignalExpression.apply('not a function', signal, signal)

    def test_non_signal_first_argument_raises_type_error(self):
        signal = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([1]))])
        with self.assertRaises(TypeError):
            SignalExpression.apply(add_poly, [1, 2], signal)

    def test_non_signal_second_argument_raises_type_error(self):
        signal = Signal([Segment(Interval(0, 5, right_open=True), Polynomial([1]))])
        with self.assertRaises(TypeError):
            SignalExpression.apply(add_poly, signal, [1, 2])


if __name__ == '__main__':
    unittest.main()
