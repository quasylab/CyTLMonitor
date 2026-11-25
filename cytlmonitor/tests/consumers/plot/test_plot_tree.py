"""Unit tests for cytlmonitor.consumers.plot.tree.plot."""

import unittest

import matplotlib

matplotlib.use('Agg')

import matplotlib.pyplot as plt  # noqa: E402

from cytlmonitor import (  # noqa: E402
    AndMonitor, AtomicGreaterMonitor, ConstantExpression, Event, EventuallyMonitor, Interval,
    NotMonitor, Payload, PlotBooleanSignalConsumer, PlotSignalConsumer, SumWindowExpression,
    TrueMonitor, plot,
)


def count(e):
    return 1.0


class PlotTreeTestCase(unittest.TestCase):

    def setUp(self):
        self.rate = SumWindowExpression(count, 0, 1)
        self.high = AtomicGreaterMonitor(self.rate, ConstantExpression(2))
        self.ahead = EventuallyMonitor(self.high, Interval(0, 2, right_open=False))
        self.root = AndMonitor(NotMonitor(TrueMonitor()), self.ahead)

    def tearDown(self):
        plt.close('all')

    def titles(self, plotters):
        return [p.axes.get_title(loc='left') for p in plotters]


class TestSelection(PlotTreeTestCase):

    def test_whole_tree_by_default(self):
        plotters = plot(self.root)
        self.assertEqual(len(plotters), len(list(self.root.nodes())))
        self.assertEqual(self.titles(plotters), [str(n) for n in self.root.nodes()])

    def test_down_to_a_depth(self):
        plotters = plot(self.root, depth=1)
        self.assertEqual(self.titles(plotters),
                         [str(self.root), 'not true', str(self.ahead)])

    def test_explicit_nodes_and_paths(self):
        plotters = plot(self.root, nodes=[self.ahead, (1, 0, 0), ()])
        self.assertEqual(self.titles(plotters),
                         [str(self.ahead), str(self.rate), str(self.root)])

    def test_depth_and_nodes_are_exclusive(self):
        with self.assertRaises(ValueError):
            plot(self.root, depth=1, nodes=[self.ahead])

    def test_no_node(self):
        with self.assertRaises(ValueError):
            plot(self.root, nodes=[])

    def test_invalid_path(self):
        with self.assertRaises(IndexError):
            plot(self.root, nodes=[(5,)])

    def test_rejects_non_node(self):
        with self.assertRaises(TypeError):
            plot(object())
        with self.assertRaises(TypeError):
            plot(self.root, nodes=[object()])


class TestFigure(PlotTreeTestCase):

    def test_consumer_matches_the_kind_of_node(self):
        plotters = plot(self.root, nodes=[self.high, self.rate])
        self.assertIsInstance(plotters[0], PlotBooleanSignalConsumer)
        self.assertIsInstance(plotters[1], PlotSignalConsumer)

    def test_one_figure_with_stacked_axes_sharing_time(self):
        plotters = plot(self.root, depth=1, title='Demo')
        figure = plotters[0].figure
        self.assertTrue(all(p.figure is figure for p in plotters))
        self.assertEqual(len(figure.axes), 3)
        self.assertEqual(figure.get_suptitle(), 'Demo')
        shared = plotters[0].axes.get_shared_x_axes()
        self.assertTrue(shared.joined(plotters[0].axes, plotters[2].axes))
        self.assertEqual([p.axes.get_xlabel() for p in plotters][:-1], ['', ''])

    def test_custom_titles(self):
        plotters = plot(self.root, depth=1, titles={self.ahead: 'Burst ahead'})
        self.assertEqual(self.titles(plotters)[2], 'Burst ahead')
        self.assertEqual(self.titles(plotters)[0], str(self.root))

    def test_options_reach_the_consumers(self):
        plotters = plot(self.root, nodes=[self.high], dark=True)
        self.assertEqual(matplotlib.colors.to_hex(plotters[0].axes.get_facecolor()), '#1a1a19')


class TestGivenAxes(PlotTreeTestCase):

    def test_plots_on_the_given_axes(self):
        figure, grid = plt.subplots(2, 2)
        left = plot(self.root, nodes=[self.root, self.ahead], axes=grid[:, 0])
        right = plot(self.root, nodes=[self.root, self.ahead], axes=grid[:, 1])
        self.assertEqual([p.axes for p in left], list(grid[:, 0]))
        self.assertEqual([p.axes for p in right], list(grid[:, 1]))
        self.assertEqual(len(plt.get_fignums()), 1)
        self.assertEqual(left[0].axes.get_xlabel(), '')

    def test_one_axes_per_node(self):
        figure, grid = plt.subplots(3, 1)
        with self.assertRaises(ValueError):
            plot(self.root, nodes=[self.root, self.ahead], axes=grid)

    def test_no_figure_title_with_axes(self):
        figure, grid = plt.subplots(1, 1, squeeze=False)
        with self.assertRaises(ValueError):
            plot(self.root, nodes=[self.root], axes=grid[0], title='Demo')


class TestPlotting(PlotTreeTestCase):

    def test_plotted_nodes_receive_the_signals_through_the_root(self):
        plotters = plot(self.root, nodes=[self.root, self.ahead, self.rate])
        for k in range(30):
            self.root.consume(Event(0.1 * k, Payload({})))
        root_plot, ahead_plot, rate_plot = plotters
        self.assertEqual(root_plot.intervals, [])
        self.assertGreater(ahead_plot.horizon, 0)
        self.assertTrue(ahead_plot.intervals)
        self.assertTrue(rate_plot.segments)

    def test_plots_can_be_added_at_several_levels_later(self):
        first = plot(self.root, nodes=[self.ahead])
        second = plot(self.root, nodes=[self.ahead])
        self.root.consume(Event(1.0, Payload({})))
        self.root.consume(Event(2.0, Payload({})))
        self.assertEqual(first[0].horizon, second[0].horizon)
        self.assertIsNot(first[0].figure, second[0].figure)


if __name__ == '__main__':
    unittest.main()
