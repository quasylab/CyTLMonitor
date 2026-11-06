"""Unit tests for cytlmonitor.consumers.plot.boolean_signal.PlotBooleanSignalConsumer."""

import math
import unittest

import matplotlib

matplotlib.use('Agg')

import matplotlib.pyplot as plt  # noqa: E402

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer  # noqa: E402
from cytlmonitor.events.event import Event  # noqa: E402
from cytlmonitor.monitors.constants import FalseMonitor  # noqa: E402
from cytlmonitor.core.interval import Interval  # noqa: E402
from cytlmonitor.events.payload import Payload  # noqa: E402
from cytlmonitor.consumers.plot.boolean_signal import PlotBooleanSignalConsumer  # noqa: E402
from cytlmonitor.monitors.constants import TrueMonitor  # noqa: E402


def line_data(p):
    xs, ys = p.axes.lines[0].get_data()
    return list(xs), list(ys)


def line_points(p):
    return list(zip(*line_data(p)))


def dot_points(p):
    return list(zip(*p.axes.lines[1].get_data()))


def horizon_line(p):
    return p.axes.lines[2]


def same(a, b):
    """Equality treating NaN as equal to NaN."""
    return len(a) == len(b) and all(
        (math.isnan(x) and math.isnan(y)) or x == y for x, y in zip(a, b))


def plotted(intervals, horizon):
    p = PlotBooleanSignalConsumer()
    for i in intervals:
        p.consume(i)
    p.set_horizon(horizon)
    return p


class PlotTestCase(unittest.TestCase):

    def tearDown(self):
        plt.close('all')
        matplotlib.interactive(False)


class TestConstruction(PlotTestCase):

    def test_is_a_boolean_signal_consumer(self):
        self.assertIsInstance(PlotBooleanSignalConsumer(), BooleanSignalConsumer)

    def test_title_is_set(self):
        p = PlotBooleanSignalConsumer('Alarm raised')
        self.assertEqual(p.axes.get_title(loc='left'), 'Alarm raised')

    def test_starts_empty_without_a_horizon(self):
        p = PlotBooleanSignalConsumer()
        self.assertEqual(p.intervals, [])
        self.assertIsNone(p.horizon)
        self.assertEqual(line_points(p), [])
        self.assertEqual(dot_points(p), [])
        self.assertFalse(horizon_line(p).get_visible())

    def test_y_axis_shows_false_and_true(self):
        p = PlotBooleanSignalConsumer()
        self.assertEqual(list(p.axes.get_yticks()), [0, 1])
        self.assertEqual([t.get_text() for t in p.axes.get_yticklabels()], ['false', 'true'])

    def test_uses_given_axes(self):
        figure, (top, bottom) = plt.subplots(2)
        p = PlotBooleanSignalConsumer(axes=bottom)
        self.assertIs(p.axes, bottom)
        self.assertIs(p.figure, figure)

    def test_dark_surface(self):
        p = PlotBooleanSignalConsumer(dark=True)
        self.assertEqual(matplotlib.colors.to_hex(p.axes.get_facecolor()), '#1a1a19')

    def test_invalid_unbounded_extent_raises_value_error(self):
        with self.assertRaises(ValueError):
            PlotBooleanSignalConsumer(unbounded_extent=-1)

    def test_dots_use_the_signal_color(self):
        p = PlotBooleanSignalConsumer()
        self.assertEqual(p.axes.lines[0].get_color(), p.axes.lines[1].get_color())


class TestConsume(PlotTestCase):

    def test_non_interval_raises_type_error(self):
        with self.assertRaises(TypeError):
            PlotBooleanSignalConsumer().consume((0, 1))

    def test_intervals_are_recorded_in_order(self):
        p = PlotBooleanSignalConsumer()
        i1, i2 = Interval(0, 1), Interval(2, 3)
        p.consume(i1)
        p.consume(i2)
        self.assertEqual(p.intervals, [i1, i2])

    def test_interval_without_a_horizon_is_at_one(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        self.assertEqual(line_points(p), [(1, 1), (3, 1)])
        self.assertEqual(dot_points(p), [(1, 1)])

    def test_separate_intervals_are_kept_apart_without_a_horizon(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        p.consume(Interval(5, 6))
        xs, ys = line_data(p)
        nan = float('nan')
        self.assertTrue(same(xs, [1.0, 3.0, nan, 5.0, 6.0]))
        self.assertTrue(same(ys, [1.0, 1.0, nan, 1.0, 1.0]))

    def test_unbounded_interval_is_drawn_beyond_the_horizon(self):
        p = PlotBooleanSignalConsumer(unbounded_extent=2)
        p.set_horizon(4)
        p.consume(Interval(4))
        self.assertEqual(line_points(p), [(0, 0), (4, 0), (4, 1), (6, 1)])
        p.set_horizon(10)
        self.assertEqual(line_points(p)[-1], (12, 1))


class TestPiecewiseConstant(PlotTestCase):

    def test_signal_with_open_and_closed_ends(self):
        # [2,3) (4.5,7.5) [10,26], known up to 30.
        p = plotted([Interval(2, 3), Interval(4.5, 7.5, left_open=True),
                     Interval(10, 26, right_open=False)], 30)
        self.assertEqual(line_points(p), [
            (0, 0), (2, 0), (2, 1), (3, 1), (3, 0), (4.5, 0), (4.5, 1), (7.5, 1),
            (7.5, 0), (10, 0), (10, 1), (26, 1), (26, 0), (30, 0)])
        # A dot at the value of the signal at each end: 1 if it is closed,
        # 0 if it is open.
        self.assertEqual(dot_points(p), [
            (2, 1), (3, 0), (4.5, 0), (7.5, 0), (10, 1), (26, 1)])

    def test_empty_signal_is_false_up_to_the_horizon(self):
        p = plotted([], 4)
        self.assertEqual(line_points(p), [(0, 0), (4, 0)])
        self.assertEqual(dot_points(p), [])

    def test_horizon_inside_a_gap_extends_it_later(self):
        p = PlotBooleanSignalConsumer()
        p.set_horizon(2)
        p.set_horizon(5)
        self.assertEqual(line_points(p), [(0, 0), (5, 0)])

    def test_signal_true_from_zero_has_no_rising_edge(self):
        p = plotted([Interval(0, 2)], 5)
        self.assertEqual(line_points(p), [(0, 1), (2, 1), (2, 0), (5, 0)])
        self.assertEqual(dot_points(p), [(0, 1), (2, 0)])

    def test_signal_open_at_zero_rises_from_zero(self):
        p = plotted([Interval(0, 2, left_open=True)], 5)
        self.assertEqual(line_points(p)[:3], [(0, 0), (0, 1), (2, 1)])
        self.assertEqual(dot_points(p)[0], (0, 0))

    def test_point_interval_is_a_spike_with_a_dot_at_one(self):
        p = plotted([Interval.point(2)], 4)
        self.assertEqual(line_points(p), [(0, 0), (2, 0), (2, 1), (2, 0), (4, 0)])
        self.assertEqual(dot_points(p), [(2, 1)])

    def test_intervals_continuing_one_another_are_one_interval(self):
        p = plotted([Interval(1, 3), Interval(3, 5)], 8)
        self.assertEqual(line_points(p), [(0, 0), (1, 0), (1, 1), (5, 1), (5, 0), (8, 0)])
        self.assertEqual(dot_points(p), [(1, 1), (5, 0)])

    def test_point_continuing_an_interval_closes_its_end(self):
        p = plotted([Interval(1, 3), Interval.point(3)], 8)
        self.assertEqual(dot_points(p), [(1, 1), (3, 1)])
        p = plotted([Interval(1, 3), Interval.point(3), Interval(3, 5, left_open=True)], 8)
        self.assertEqual(dot_points(p), [(1, 1), (5, 0)])

    def test_missing_point_between_two_intervals_drops_to_zero(self):
        # [1,3) (3,5) is false at 3 only.
        p = plotted([Interval(1, 3), Interval(3, 5, left_open=True)], 8)
        self.assertEqual(line_points(p), [
            (0, 0), (1, 0), (1, 1), (3, 1), (3, 0), (3, 1), (5, 1), (5, 0), (8, 0)])
        self.assertEqual(dot_points(p), [(1, 1), (3, 0), (3, 0), (5, 0)])

    def test_end_is_drawn_once_the_horizon_passes_it(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        p.set_horizon(3)
        # The next interval may still continue it: no falling edge, no dot.
        self.assertEqual(line_points(p), [(0, 0), (1, 0), (1, 1), (3, 1)])
        self.assertEqual(dot_points(p), [(1, 1)])
        p.consume(Interval(3, 4))
        p.set_horizon(6)
        self.assertEqual(line_points(p), [(0, 0), (1, 0), (1, 1), (4, 1), (4, 0), (6, 0)])
        self.assertEqual(dot_points(p), [(1, 1), (4, 0)])

    def test_interval_reaching_past_the_horizon(self):
        p = plotted([Interval(1, 8)], 4)
        self.assertEqual(line_points(p), [(0, 0), (1, 0), (1, 1), (8, 1)])
        p.set_horizon(10)
        self.assertEqual(line_points(p)[-3:], [(8, 1), (8, 0), (10, 0)])

    def test_unbounded_interval_leaves_nothing_false_after_it(self):
        p = plotted([Interval(3)], 10)
        self.assertEqual(line_points(p), [(0, 0), (3, 0), (3, 1), (11, 1)])
        self.assertEqual(dot_points(p), [(3, 1)])

    def test_nothing_at_zero_after_the_horizon(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(0, 2))
        p.set_horizon(2)
        p.consume(Interval(6, 7))
        xs, ys = line_data(p)
        nan = float('nan')
        self.assertTrue(same(xs, [0.0, 2.0, nan, 6.0, 7.0]))
        self.assertTrue(same(ys, [1.0, 1.0, nan, 1.0, 1.0]))
        p.set_horizon(9)
        self.assertEqual(line_points(p), [
            (0, 1), (2, 1), (2, 0), (6, 0), (6, 1), (7, 1), (7, 0), (9, 0)])

    def test_rising_edge_when_the_interval_arrives_after_the_horizon(self):
        p = PlotBooleanSignalConsumer()
        p.set_horizon(2)
        p.consume(Interval(2, 4))
        p.set_horizon(6)
        self.assertEqual(line_points(p), [(0, 0), (2, 0), (2, 1), (4, 1), (4, 0), (6, 0)])


class TestHorizon(PlotTestCase):

    def test_horizon_is_a_vertical_line_at_its_position(self):
        p = PlotBooleanSignalConsumer()
        p.set_horizon(5)
        line = horizon_line(p)
        self.assertTrue(line.get_visible())
        self.assertEqual(list(line.get_xdata()), [5.0, 5.0])
        self.assertEqual(p.horizon, 5.0)

    def test_horizon_line_moves(self):
        p = PlotBooleanSignalConsumer()
        p.set_horizon(5)
        p.set_horizon(8)
        self.assertEqual(list(horizon_line(p).get_xdata()), [8.0, 8.0])
        self.assertEqual(len(p.axes.lines), 3)

    def test_horizon_line_spans_the_whole_height(self):
        p = PlotBooleanSignalConsumer()
        p.set_horizon(5)
        line = horizon_line(p)
        self.assertEqual(list(line.get_ydata()), [0, 1])
        self.assertIs(line.get_transform(), p.axes.get_xaxis_transform())

    def test_horizon_is_drawn_apart_from_the_signal(self):
        p = PlotBooleanSignalConsumer()
        signal, horizon = p.axes.lines[0], horizon_line(p)
        self.assertNotEqual(signal.get_color(), horizon.get_color())
        self.assertNotEqual(horizon.get_linestyle(), '-')

    def test_view_includes_intervals_and_horizon(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(0, 3))
        p.set_horizon(10)
        low, high = p.axes.get_xlim()
        self.assertLess(low, 0)
        self.assertGreater(high, 10)


class TestRefresh(PlotTestCase):

    def test_redraws_are_throttled_and_data_kept_up_to_date(self):
        matplotlib.interactive(True)
        p = PlotBooleanSignalConsumer(refresh_interval=60)
        calls = []
        original = p.figure.canvas.flush_events

        def flush_events(*args, **kwargs):
            calls.append(1)
            return original(*args, **kwargs)

        p.figure.canvas.flush_events = flush_events
        for k in range(50):
            p.consume(Interval(2 * k, 2 * k + 1))
            p.set_horizon(2 * k + 2)
        # Only the first change is drawn.
        self.assertEqual(len(calls), 1)
        self.assertEqual(p.horizon, 100.0)
        self.assertEqual(line_points(p)[-1], (100, 0))
        self.assertEqual(len(dot_points(p)), 100)
        self.assertGreater(p.axes.get_xlim()[1], 100)
        p.refresh()
        self.assertEqual(len(calls), 2)


class TestWithMonitors(PlotTestCase):

    def test_plots_a_monitor_as_it_publishes(self):
        m = TrueMonitor()
        p = PlotBooleanSignalConsumer('True')
        m.add(p)
        for t in (1, 3):
            m.consume(Event(t, Payload({})))
        self.assertEqual(p.intervals, [Interval(0, 1), Interval(1, 3)])
        self.assertEqual(p.horizon, 3.0)
        self.assertEqual(list(horizon_line(p).get_xdata()), [3.0, 3.0])
        # The pieces join into one interval, true from 0.
        self.assertEqual(line_points(p), [(0, 1), (3, 1)])
        self.assertEqual(dot_points(p), [(0, 1)])

    def test_false_monitor_is_zero_up_to_the_horizon(self):
        m = FalseMonitor()
        p = PlotBooleanSignalConsumer('False')
        m.add(p)
        for t in (1, 3):
            m.consume(Event(t, Payload({})))
        self.assertEqual(line_points(p), [(0, 0), (3, 0)])


if __name__ == '__main__':
    unittest.main()
