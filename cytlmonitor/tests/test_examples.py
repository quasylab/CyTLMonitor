"""Smoke tests for the scripts in ``examples/``: each one runs and raises the
alarms it is meant to show."""

import importlib
import sys
import unittest
from pathlib import Path

import matplotlib

matplotlib.use('Agg')

import matplotlib.pyplot as plt  # noqa: E402

EXAMPLES = Path(__file__).resolve().parents[2] / 'examples'


def example(name):
    if str(EXAMPLES) not in sys.path:
        sys.path.insert(0, str(EXAMPLES))
    return importlib.import_module(name)


def spans(alarms):
    return [(round(i.start, 1), round(i.end, 1)) for i in alarms]


class TestExamples(unittest.TestCase):

    def assertAround(self, alarm, start, end, tolerance=1.0):
        self.assertAlmostEqual(alarm.start, start, delta=tolerance)
        self.assertAlmostEqual(alarm.end, end, delta=tolerance)

    def test_syn_flood(self):
        alarms = example('syn_flood').main(quiet=True)
        self.assertEqual(len(alarms['SYN flood']), 1)
        self.assertAround(alarms['SYN flood'][0], 25.5, 44.5)

    def test_sustained_rate(self):
        alarms = example('sustained_rate').main(quiet=True)
        self.assertEqual(len(alarms['high']), 2)
        self.assertEqual(len(alarms['sustained']), 1)
        self.assertAround(alarms['sustained'][0], 30.3, 35.7)
        self.assertEqual(len(alarms['burst ahead']), 2)
        # Looking 2 s ahead, the warning starts 2 s before the rate is high.
        for warning, high in zip(alarms['burst ahead'], alarms['high']):
            self.assertAlmostEqual(warning.start, high.start - 2, delta=0.01)

    def test_port_scan(self):
        alarms = example('port_scan').main(quiet=True)
        self.assertEqual(len(alarms['port scan']), 1)
        self.assertAround(alarms['port scan'][0], 20.5, 25.5)
        self.assertEqual(len(alarms['ICMP flood']), 1)
        self.assertAround(alarms['ICMP flood'][0], 40.3, 44.7)
        self.assertEqual(len(alarms['suspicious']), 2)
        # The flash crowd at 50 s has many SYNs, but is not a port scan.
        self.assertEqual(len(alarms['many SYNs']), 2)
        self.assertGreater(alarms['many SYNs'][1].start, 50)
        # The rule written with an implication gives the same alarms.
        self.assertEqual(spans(alarms['not (many SYNs -> not few ACKs)']),
                         spans(alarms['port scan']))

    def test_until_since(self):
        alarms = example('until_since').main(quiet=True)
        self.assertEqual(len(alarms['brute force']), 2)
        self.assertEqual(len(alarms['login']), 2)
        self.assertEqual(spans(alarms['breach']), [(12.5, 20.0)])
        self.assertEqual(spans(alarms['still failing after login']), [(19.0, 33.0)])

    def test_quiet_since_attack(self):
        from cytlmonitor import Interval
        alarms = example('quiet_since_attack').main(quiet=True)
        # The attacks are right-open: they do not contain the point where
        # quiet starts.
        self.assertEqual(alarms['attack'], [Interval(20, 28), Interval(50, 53)])
        # Cooling down starts right after each attack ends, through its open
        # end, and lasts 30 s after the second one.
        self.assertEqual(alarms['cooling down'], [
            Interval(28, 50, left_open=True),
            Interval(53, 83, left_open=True, right_open=False),
        ])
        # All clear only 30 s after the second attack: between the two
        # attacks fewer than 30 quiet seconds pass.
        self.assertEqual(len(alarms['all clear']), 1)
        self.assertEqual(alarms['all clear'][0].start, 83.0)

    def test_scalability_runs_and_reports_linear_growth(self):
        module = example('scalability')
        sizes = [2_000, 4_000, 8_000]
        results = module.run(sizes, memory=True, quiet=True,
                             monitors={'SYN flood': module.syn_flood_monitor,
                                       'all clear': module.all_clear_monitor})
        self.assertEqual(set(results), {'SYN flood', 'all clear'})
        for rows in results.values():
            self.assertEqual([r['events'] for r in rows], sizes)
            for r in rows:
                self.assertGreater(r['seconds'], 0)
                self.assertGreater(r['peak_bytes'], 0)
                self.assertGreater(r['horizon'], 0)
        self.assertGreater(results['SYN flood'][-1]['intervals'], 0)

    def test_scalability_stream_has_the_requested_length_in_time_order(self):
        module = example('scalability')
        events = [e for cycle in module.stream(7_500) for e in cycle]
        self.assertEqual(len(events), 7_500)
        self.assertEqual(events, sorted(events, key=lambda e: e.time))

    def test_growth_exponent(self):
        module = example('scalability')
        linear = [{'events': n, 'seconds': 2e-6 * n} for n in (1e3, 1e4, 1e5, 1e6)]
        quadratic = [{'events': n, 'seconds': 1e-9 * n * n} for n in (1e3, 1e4, 1e5, 1e6)]
        self.assertAlmostEqual(module.growth_exponent(linear), 1.0)
        self.assertAlmostEqual(module.growth_exponent(quadratic), 2.0)

    def test_plot_option(self):
        module = example('syn_flood')
        saved = []
        module.show = lambda: saved.append(plt.gcf())
        try:
            module.main(plot=True, quiet=True)
        finally:
            del module.show
            importlib.reload(module)
        self.assertEqual(len(saved), 1)
        self.assertEqual(len(saved[0].axes), 2)
        plt.close('all')


if __name__ == '__main__':
    unittest.main()
