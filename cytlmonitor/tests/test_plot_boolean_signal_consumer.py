"""Unit tests for cytlmonitor.plot_boolean_signal_consumer.PlotBooleanSignalConsumer."""

import math
import unittest

import matplotlib

matplotlib.use('Agg')

import matplotlib.pyplot as plt  # noqa: E402

from cytlmonitor.boolean_signal_consumer import BooleanSignalConsumer  # noqa: E402
from cytlmonitor.event import Event  # noqa: E402
from cytlmonitor.false_monitor import FalseMonitor  # noqa: E402
from cytlmonitor.interval import Interval  # noqa: E402
from cytlmonitor.payload import Payload  # noqa: E402
from cytlmonitor.plot_boolean_signal_consumer import PlotBooleanSignalConsumer  # noqa: E402
from cytlmonitor.true_monitor import TrueMonitor  # noqa: E402


def line_data(p):
    xs, ys = p.axes.lines[0].get_data()
    return list(xs), list(ys)


def false_data(p):
    xs, ys = p.axes.lines[1].get_data()
    return list(xs), list(ys)


def point_data(p):
    xs, ys = p.axes.lines[2].get_data()
    return list(xs), list(ys)


def horizon_line(p):
    return p.axes.lines[3]


def same(a, b):
    """Equality treating NaN as equal to NaN."""
    return len(a) == len(b) and all(
        (math.isnan(x) and math.isnan(y)) or x == y for x, y in zip(a, b))


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
        self.assertEqual(line_data(p), ([], []))
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

    def test_interval_is_a_constant_one(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        self.assertEqual(line_data(p), ([1.0, 3.0], [1.0, 1.0]))

    def test_separate_intervals_are_not_joined(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        p.consume(Interval(5, 6))
        xs, ys = line_data(p)
        nan = float('nan')
        self.assertTrue(same(xs, [1.0, 3.0, nan, 5.0, 6.0]))
        self.assertTrue(same(ys, [1.0, 1.0, nan, 1.0, 1.0]))

    def test_interval_continuing_the_previous_one_extends_its_line(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        p.consume(Interval(3, 5))
        self.assertEqual(line_data(p), ([1.0, 5.0], [1.0, 1.0]))

    def test_point_touching_the_line_is_not_a_marker(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        p.consume(Interval.point(3))
        p.consume(Interval(3, 5, left_open=True))
        self.assertEqual(point_data(p), ([], []))
        self.assertEqual(line_data(p), ([1.0, 5.0], [1.0, 1.0]))

    def test_marker_is_dropped_when_an_interval_continues_the_point(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval.point(2))
        p.consume(Interval(2, 4, left_open=True))
        self.assertEqual(point_data(p), ([], []))
        self.assertEqual(line_data(p), ([2.0, 4.0], [1.0, 1.0]))

    def test_point_interval_is_a_marker_at_one(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval.point(2))
        self.assertEqual(point_data(p), ([2.0], [1.0]))
        self.assertEqual(line_data(p), ([], []))

    def test_unbounded_interval_is_drawn_beyond_the_furthest_point(self):
        p = PlotBooleanSignalConsumer(unbounded_extent=2)
        p.set_horizon(4)
        p.consume(Interval(4))
        self.assertEqual(line_data(p), ([4.0, 6.0], [1.0, 1.0]))


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
        self.assertEqual(len(p.axes.lines), 4)

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


class TestFalsePart(PlotTestCase):

    def test_nothing_at_zero_without_a_horizon(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        self.assertEqual(false_data(p), ([], []))

    def test_empty_signal_is_false_up_to_the_horizon(self):
        p = PlotBooleanSignalConsumer()
        p.set_horizon(4)
        self.assertEqual(false_data(p), ([0.0, 4.0], [0.0, 0.0]))

    def test_gaps_before_the_horizon_are_drawn_at_zero_with_edges(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 3))
        p.set_horizon(5)
        xs, ys = false_data(p)
        nan = float('nan')
        # [0, 1) rising to the interval, then (3, 5) falling from it.
        self.assertTrue(same(xs, [0.0, 1.0, 1.0, nan, 3.0, 3.0, 5.0]))
        self.assertTrue(same(ys, [0.0, 0.0, 1.0, nan, 1.0, 0.0, 0.0]))

    def test_nothing_at_zero_after_the_horizon(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(0, 2))
        p.set_horizon(2)
        p.consume(Interval(6, 7))
        self.assertEqual(false_data(p), ([], []))
        p.set_horizon(9)
        xs, ys = false_data(p)
        nan = float('nan')
        self.assertTrue(same(xs, [2.0, 2.0, 6.0, 6.0, nan, 7.0, 7.0, 9.0]))
        self.assertTrue(same(ys, [1.0, 0.0, 0.0, 1.0, nan, 1.0, 0.0, 0.0]))

    def test_rising_edge_when_the_interval_arrives_after_the_horizon(self):
        # The horizon reaches 2 before the interval starting at 2 arrives.
        p = PlotBooleanSignalConsumer()
        p.set_horizon(2)
        p.consume(Interval(2, 4))
        p.set_horizon(6)
        xs, ys = false_data(p)
        nan = float('nan')
        self.assertTrue(same(xs, [0.0, 2.0, 2.0, nan, 4.0, 4.0, 6.0]))
        self.assertTrue(same(ys, [0.0, 0.0, 1.0, nan, 1.0, 0.0, 0.0]))

    def test_horizon_inside_a_gap_extends_it_later(self):
        p = PlotBooleanSignalConsumer()
        p.set_horizon(2)
        p.set_horizon(5)
        self.assertEqual(false_data(p), ([0.0, 5.0], [0.0, 0.0]))

    def test_interval_reaching_past_the_horizon(self):
        # The interval [1, 8) is true past the horizon 4: no false part
        # until it ends and the horizon passes it.
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(1, 8))
        p.set_horizon(4)
        self.assertEqual(false_data(p), ([0.0, 1.0, 1.0], [0.0, 0.0, 1.0]))
        p.set_horizon(10)
        xs, ys = false_data(p)
        self.assertEqual(xs[-3:], [8.0, 8.0, 10.0])
        self.assertEqual(ys[-3:], [1.0, 0.0, 0.0])

    def test_unbounded_interval_leaves_nothing_false_after_it(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval(3))
        p.set_horizon(10)
        self.assertEqual(false_data(p), ([0.0, 3.0, 3.0], [0.0, 0.0, 1.0]))

    def test_point_interval_keeps_the_zero_line_under_its_marker(self):
        p = PlotBooleanSignalConsumer()
        p.consume(Interval.point(2))
        p.set_horizon(4)
        self.assertEqual(false_data(p), ([0.0, 4.0], [0.0, 0.0]))
        self.assertEqual(point_data(p), ([2.0], [1.0]))

    def test_false_part_uses_the_signal_color(self):
        p = PlotBooleanSignalConsumer()
        self.assertEqual(p.axes.lines[0].get_color(), p.axes.lines[1].get_color())


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
        self.assertEqual(false_data(p)[0][-1], 100.0)
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
        self.assertEqual(false_data(p), ([], []))

    def test_false_monitor_is_zero_up_to_the_horizon(self):
        m = FalseMonitor()
        p = PlotBooleanSignalConsumer('False')
        m.add(p)
        for t in (1, 3):
            m.consume(Event(t, Payload({})))
        self.assertEqual(false_data(p), ([0.0, 3.0], [0.0, 0.0]))


if __name__ == '__main__':
    unittest.main()
