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
        s1 = make_segment(5, 10)
        s2 = make_segment(0, 4)
        signal.add(s1)
        with pytest.raises(ValueError):
            signal.add(s2)

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
        s1 = make_segment(5, 10)
        signal.add(s1)
        with pytest.raises(ValueError):
            signal.add(make_segment(0, 4))
        assert signal.length() == 1


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
