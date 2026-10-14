"""Unit tests for cytlmonitor.plot_signal_consumer.PlotSignalConsumer."""

import unittest

import matplotlib

matplotlib.use('Agg')

import matplotlib.pyplot as plt  # noqa: E402

from cytlmonitor.event import Event  # noqa: E402
from cytlmonitor.interval import Interval  # noqa: E402
from cytlmonitor.payload import Payload  # noqa: E402
from cytlmonitor.plot_signal_consumer import PlotSignalConsumer  # noqa: E402
from cytlmonitor.polynomial import Polynomial  # noqa: E402
from cytlmonitor.segment import Segment  # noqa: E402
from cytlmonitor.signal_consumer import SignalConsumer  # noqa: E402
from cytlmonitor.sum_window_expression import SumWindowExpression  # noqa: E402


def segment(interval, *coefficients):
    return Segment(interval, Polynomial(coefficients))


def line_data(p):
    xs, ys = p.axes.lines[0].get_data()
    return list(xs), list(ys)


def point_data(p):
    xs, ys = p.axes.lines[1].get_data()
    return list(xs), list(ys)


class PlotTestCase(unittest.TestCase):

    def tearDown(self):
        plt.close('all')
        matplotlib.interactive(False)


class TestConstruction(PlotTestCase):

    def test_is_a_signal_consumer(self):
        self.assertIsInstance(PlotSignalConsumer(), SignalConsumer)

    def test_title_is_set(self):
        p = PlotSignalConsumer('Packets per second')
        self.assertEqual(p.axes.get_title(loc='left'), 'Packets per second')

    def test_starts_empty(self):
        p = PlotSignalConsumer()
        self.assertEqual(p.segments, [])
        self.assertEqual(line_data(p), ([], []))

    def test_uses_given_axes(self):
        figure, (top, bottom) = plt.subplots(2)
        p = PlotSignalConsumer(axes=bottom)
        self.assertIs(p.axes, bottom)
        self.assertIs(p.figure, figure)

    def test_light_and_dark_surfaces(self):
        light = PlotSignalConsumer()
        dark = PlotSignalConsumer(dark=True)
        self.assertEqual(matplotlib.colors.to_hex(light.axes.get_facecolor()), '#fcfcfb')
        self.assertEqual(matplotlib.colors.to_hex(dark.axes.get_facecolor()), '#1a1a19')

    def test_line_is_two_pixels_wide(self):
        self.assertEqual(PlotSignalConsumer().axes.lines[0].get_linewidth(), 2)

    def test_invalid_samples_raise_value_error(self):
        with self.assertRaises(ValueError):
            PlotSignalConsumer(samples=1)

    def test_invalid_unbounded_extent_raises_value_error(self):
        with self.assertRaises(ValueError):
            PlotSignalConsumer(unbounded_extent=0)


class TestConsume(PlotTestCase):

    def test_non_segment_raises_type_error(self):
        with self.assertRaises(TypeError):
            PlotSignalConsumer().consume((0, 1))

    def test_segments_are_recorded_in_order(self):
        p = PlotSignalConsumer()
        s1, s2 = segment(Interval(0, 1), 2), segment(Interval(1, 3), 5)
        p.consume(s1)
        p.consume(s2)
        self.assertEqual(p.segments, [s1, s2])

    def test_constant_segment_is_drawn_from_its_endpoints(self):
        p = PlotSignalConsumer()
        p.consume(segment(Interval(0, 2), 3))
        self.assertEqual(line_data(p), ([0.0, 2.0], [3.0, 3.0]))

    def test_jump_between_segments_is_a_vertical_step(self):
        p = PlotSignalConsumer()
        p.consume(segment(Interval(0, 2), 3))
        p.consume(segment(Interval(2, 5), 1))
        self.assertEqual(line_data(p), ([0.0, 2.0, 2.0, 5.0], [3.0, 3.0, 1.0, 1.0]))

    def test_non_constant_segment_is_sampled(self):
        p = PlotSignalConsumer(samples=5)
        p.consume(segment(Interval(0, 4), 0, 0, 1))
        xs, ys = line_data(p)
        self.assertEqual(xs, [0.0, 1.0, 2.0, 3.0, 4.0])
        self.assertEqual(ys, [0.0, 1.0, 4.0, 9.0, 16.0])

    def test_point_segment_is_drawn_as_a_marker(self):
        p = PlotSignalConsumer()
        p.consume(segment(Interval(0, 2), 1))
        p.consume(segment(Interval.point(2), 7))
        self.assertEqual(point_data(p), ([2.0], [7.0]))
        self.assertEqual(line_data(p), ([0.0, 2.0], [1.0, 1.0]))
        self.assertGreaterEqual(p.axes.lines[1].get_markersize(), 8)

    def test_unbounded_segment_is_drawn_beyond_the_furthest_point(self):
        p = PlotSignalConsumer(unbounded_extent=2)
        p.consume(segment(Interval(0, 5), 1))
        p.consume(segment(Interval(5), 3))
        self.assertEqual(line_data(p), ([0.0, 5.0, 5.0, 7.0], [1.0, 1.0, 3.0, 3.0]))

    def test_view_follows_the_signal(self):
        p = PlotSignalConsumer()
        p.consume(segment(Interval(0, 2), 1))
        p.consume(segment(Interval(2, 50), 100))
        x_low, x_high = p.axes.get_xlim()
        y_low, y_high = p.axes.get_ylim()
        self.assertLessEqual(x_low, 0)
        self.assertGreaterEqual(x_high, 50)
        self.assertLessEqual(y_low, 1)
        self.assertGreaterEqual(y_high, 100)

    def test_each_segment_triggers_a_redraw_without_throttling(self):
        matplotlib.interactive(True)
        p = PlotSignalConsumer(refresh_interval=0)
        original = p.figure.canvas.flush_events
        calls = []

        def flush_events(*args, **kwargs):
            calls.append(1)
            return original(*args, **kwargs)

        p.figure.canvas.flush_events = flush_events
        p.consume(segment(Interval(0, 1), 1))
        p.consume(segment(Interval(1, 2), 2))
        self.assertEqual(len(calls), 2)


class TestRefresh(PlotTestCase):

    def count_draws(self, p):
        calls = []
        original = p.figure.canvas.flush_events

        def flush_events(*args, **kwargs):
            calls.append(1)
            return original(*args, **kwargs)

        p.figure.canvas.flush_events = flush_events
        return calls

    def test_redraws_are_throttled(self):
        matplotlib.interactive(True)
        p = PlotSignalConsumer(refresh_interval=60)
        calls = self.count_draws(p)
        for k in range(100):
            p.consume(segment(Interval(k, k + 1), k))
        self.assertEqual(len(calls), 1)

    def test_data_and_view_are_up_to_date_between_redraws(self):
        p = PlotSignalConsumer(refresh_interval=60)
        for k in range(100):
            p.consume(segment(Interval(k, k + 1), k))
        xs, ys = line_data(p)
        self.assertEqual(xs[-1], 100.0)
        self.assertGreaterEqual(p.axes.get_xlim()[1], 100)
        self.assertGreaterEqual(p.axes.get_ylim()[1], 99)

    def test_refresh_forces_a_redraw(self):
        matplotlib.interactive(True)
        p = PlotSignalConsumer(refresh_interval=60)
        calls = self.count_draws(p)
        p.consume(segment(Interval(0, 1), 1))
        p.consume(segment(Interval(1, 2), 2))
        p.refresh()
        self.assertEqual(len(calls), 2)

    def test_no_redraw_outside_interactive_mode(self):
        p = PlotSignalConsumer(refresh_interval=0)
        calls = self.count_draws(p)
        for k in range(10):
            p.consume(segment(Interval(k, k + 1), k))
        self.assertEqual(calls, [])
        p.refresh()
        self.assertEqual(len(calls), 1)

    def test_negative_refresh_interval_raises_value_error(self):
        with self.assertRaises(ValueError):
            PlotSignalConsumer(refresh_interval=-1)


class TestWithExpressions(PlotTestCase):

    def test_plots_a_window_sum_as_it_is_published(self):
        sw = SumWindowExpression(lambda e: e['v'], 0, 2)
        p = PlotSignalConsumer('Sum of v over [t, t + 2]')
        sw.add(p)
        for t, v in ((1, 3), (2, 1), (5, 0)):
            sw.consume(Event(t, Payload({'v': v})))
        self.assertGreater(len(p.segments), 0)
        xs, ys = line_data(p)
        self.assertEqual(xs[0], 0.0)
        self.assertEqual(ys[0], 4.0)
        self.assertEqual(xs[-1], 3.0)


if __name__ == '__main__':
    unittest.main()
