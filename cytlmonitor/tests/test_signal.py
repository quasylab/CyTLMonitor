"""Unit tests for cytlmonitor.signal.Signal."""

import pytest

from cytlmonitor.interval import Interval
from cytlmonitor.polynomial import Polynomial
from cytlmonitor.segment import Segment
from cytlmonitor.signal import Signal


def make_segment(from_, to=None, value=1.0, left_open=False, right_open=True):
    interval = Interval(from_, to, left_open=left_open, right_open=right_open)
    return Segment(interval, Polynomial([value]))


class TestConstruction:

    def test_empty_signal(self):
        signal = Signal()
        assert signal.length() == 0
        assert len(signal) == 0

    def test_construct_from_ordered_iterable(self):
        s1 = make_segment(0, 1, value=1.0)
        s2 = make_segment(1, 2, value=2.0)
        signal = Signal([s1, s2])
        assert signal.length() == 2
        assert signal[0] == s1
        assert signal[1] == s2

    def test_construct_from_invalid_iterable_raises(self):
        s1 = make_segment(0, 1)
        s2 = make_segment(2, 3)
        s3 = make_segment(1, 4)  # overlaps s2
        with pytest.raises(ValueError):
            Signal([s1, s2, s3])


class TestAdd:

    def test_add_non_segment_raises_type_error(self):
        signal = Signal()
        with pytest.raises(TypeError):
            signal.add((Interval(0, 1), Polynomial([1])))

    def test_add_first_segment(self):
        signal = Signal()
        s = make_segment(0, 1)
        signal.add(s)
        assert signal.length() == 1
        assert signal[0] == s

    def test_add_valid_adjacent_segments(self):
        signal = Signal()
        s1 = make_segment(0, 1, right_open=True)
        s2 = make_segment(1, 2, right_open=True)
        signal.add(s1)
        signal.add(s2)
        assert signal.length() == 2

    def test_reject_boundary_overlap(self):
        signal = Signal()
        s1 = make_segment(0, 1, right_open=False)  # [0, 1]
        s2 = make_segment(1, 2, right_open=True)    # [1, 2)
        signal.add(s1)
        with pytest.raises(ValueError):
            signal.add(s2)

    def test_reject_truly_overlapping_segments(self):
        signal = Signal()
        s1 = make_segment(0, 2)
        s2 = make_segment(1, 3)
        signal.add(s1)
        with pytest.raises(ValueError):
            signal.add(s2)

    def test_reject_out_of_order_segment(self):
        signal = Signal()
        signal.add(make_segment(0, 1))
        signal.add(make_segment(5, 10))
        with pytest.raises(ValueError):
            signal.add(make_segment(2, 4))

    def test_reject_first_segment_not_starting_at_zero(self):
        with pytest.raises(ValueError):
            Signal().add(make_segment(1, 4))

    def test_reject_first_segment_left_open_at_zero(self):
        with pytest.raises(ValueError):
            Signal().add(make_segment(0, 4, left_open=True))

    def test_first_segment_can_be_the_point_zero(self):
        signal = Signal([Segment(Interval.point(0), Polynomial([1]))])
        assert signal.length() == 1

    def test_allow_temporal_gap(self):
        signal = Signal()
        s1 = make_segment(0, 1)
        s2 = make_segment(5, 6)
        signal.add(s1)
        signal.add(s2)
        assert signal.length() == 2

    def test_reject_segment_after_right_unbounded(self):
        signal = Signal()
        s1 = Segment(Interval(0), Polynomial([1]))  # right-unbounded
        s2 = make_segment(10, 20)
        signal.add(s1)
        with pytest.raises(ValueError):
            signal.add(s2)

    def test_failed_add_does_not_modify_signal(self):
        signal = Signal()
        signal.add(make_segment(0, 10))
        with pytest.raises(ValueError):
            signal.add(make_segment(2, 4))
        assert signal.length() == 1

    def test_failed_first_add_does_not_modify_signal(self):
        signal = Signal()
        with pytest.raises(ValueError):
            signal.add(make_segment(2, 4))
        assert signal.length() == 0


class TestIndexingAndIteration:

    def setup_method(self):
        self.s1 = make_segment(0, 1, value=1.0)
        self.s2 = make_segment(1, 2, value=2.0)
        self.signal = Signal([self.s1, self.s2])

    def test_len(self):
        assert len(self.signal) == 2

    def test_getitem(self):
        assert self.signal[0] == self.s1
        assert self.signal[1] == self.s2

    def test_getitem_out_of_range_raises_index_error(self):
        with pytest.raises(IndexError):
            self.signal[2]

    def test_iteration_yields_segments_in_order(self):
        assert list(self.signal) == [self.s1, self.s2]


class TestContainsAndValueAt:

    def setup_method(self):
        # [0, 1) -> p(t) = 1 ; gap ; [2, 3) -> p(t) = t
        self.s1 = make_segment(0, 1, value=1.0)
        self.s2 = Segment(Interval(2, 3), Polynomial([0, 1]))
        self.signal = Signal([self.s1, self.s2])

    def test_value_inside_first_segment(self):
        assert self.signal.value_at(0.5) == 1.0

    def test_value_inside_second_segment(self):
        assert self.signal.value_at(2.5) == 2.5

    def test_contains_inside_segments(self):
        assert self.signal.contains(0.5)
        assert 0.5 in self.signal
        assert self.signal.contains(2.5)
        assert 2.5 in self.signal

    def test_gap_not_contained(self):
        assert not self.signal.contains(1.5)
        assert 1.5 not in self.signal

    def test_gap_value_at_raises(self):
        with pytest.raises(ValueError):
            self.signal.value_at(1.5)

    def test_empty_signal_contains_nothing(self):
        signal = Signal()
        assert not signal.contains(0)
        with pytest.raises(ValueError):
            signal.value_at(0)

    def test_get_segment_at_returns_correct_segment(self):
        assert self.signal.get_segment_at(0.5) == self.s1
        assert self.signal.get_segment_at(2.5) == self.s2

    def test_get_segment_at_outside_raises(self):
        with pytest.raises(ValueError):
            self.signal.get_segment_at(1.5)


class TestEqualityAndRepr:

    def test_equal_signals(self):
        s1 = make_segment(0, 1)
        s2 = make_segment(1, 2)
        assert Signal([s1, s2]) == Signal([s1, s2])

    def test_different_signals_not_equal(self):
        s1 = make_segment(0, 1)
        s2 = make_segment(1, 2)
        assert Signal([s1]) != Signal([s1, s2])

    def test_not_equal_to_other_types(self):
        s1 = make_segment(0, 1)
        assert Signal([s1]) != [s1]

    def test_repr_contains_segments(self):
        s1 = make_segment(0, 1)
        signal = Signal([s1])
        r = repr(signal)
        assert 'Signal' in r
        assert repr(s1) in r


class TestShift:

    def _signal(self):
        return Signal([
            Segment(Interval(0, 4), Polynomial([1, 2])),
            Segment(Interval(5, 10, right_open=False), Polynomial([3])),
            Segment(Interval(12), Polynomial([0, 0, 1])),
        ])

    def test_forward_adds_leading_zero_segment(self):
        signal = self._signal()
        assert signal.shift(3) == Signal(
            [Segment(Interval(0, 3), Polynomial.ZERO)]
            + [segment.shift(3) for segment in signal]
        )

    def test_forward_values_move_with_the_signal(self):
        signal = self._signal()
        result = signal.shift(2.5)
        for x in [0.0, 3.5, 5.0, 10.0, 12.0, 20.0]:
            assert result.value_at(x + 2.5) == pytest.approx(signal.value_at(x))
        for x in [0.0, 1.0, 2.4]:
            assert result.value_at(x) == 0.0

    def test_forward_empty_signal_is_the_zero_segment(self):
        assert Signal().shift(3) == Signal([Segment(Interval(0, 3), Polynomial.ZERO)])

    def test_back_shifts_every_segment(self):
        signal = self._signal()
        assert signal.shift(-0.5) == Signal([segment.shift(-0.5) for segment in signal])

    def test_back_clips_segment_crossing_zero(self):
        signal = self._signal()
        result = signal.shift(-2)
        assert result[0] == Segment(Interval(0, 2), Polynomial([5, 2]))
        assert len(result) == 3

    def test_back_fills_a_leading_gap_with_zero(self):
        # Shifting back by 4.5: [0, 4) vanishes, [5, 10] becomes [0.5, 5.5],
        # so [0, 0.5) is filled with zero.
        signal = self._signal()
        assert signal.shift(-4.5) == Signal([
            Segment(Interval(0, 0.5), Polynomial.ZERO),
            Segment(Interval(0.5, 5.5, right_open=False), Polynomial([3])),
            Segment(Interval(7.5), Polynomial([0, 0, 1]).shift(-4.5)),
        ])

    def test_back_fills_a_left_open_start_with_the_zero_point(self):
        # [0, 4) vanishes and (4, 6] becomes (0, 2]: the point {0} is filled with zero.
        signal = Signal([
            Segment(Interval(0, 4), Polynomial([1])),
            Segment(Interval(4, 6, left_open=True, right_open=False), Polynomial([2])),
        ])
        assert signal.shift(-4) == Signal([
            Segment(Interval.point(0), Polynomial.ZERO),
            Segment(Interval(0, 2, left_open=True, right_open=False), Polynomial([2])),
        ])

    def test_back_past_every_segment_is_empty(self):
        signal = Signal([Segment(Interval(0, 4), Polynomial([1]))])
        assert signal.shift(-5) == Signal()

    def test_shift_by_zero_returns_equal_signal(self):
        signal = self._signal()
        assert signal.shift(0) == signal

    def test_empty_signal_shifted_back_is_empty(self):
        assert Signal().shift(-3) == Signal()

    def test_does_not_mutate_original(self):
        signal = self._signal()
        signal.shift(-6)
        signal.shift(2)
        assert signal == self._signal()
