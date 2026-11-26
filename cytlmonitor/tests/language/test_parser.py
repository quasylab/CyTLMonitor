"""Unit tests for cytlmonitor.language: parsing a specification and the
monitors and expressions it builds."""

import math
import random
import unittest
from pathlib import Path

from cytlmonitor.consumers.boolean_signal_consumer import BooleanSignalConsumer
from cytlmonitor.consumers.signal_consumer import SignalConsumer
from cytlmonitor.core.boolean_signal import BooleanSignal
from cytlmonitor.core.interval import Interval
from cytlmonitor.events.event import Event
from cytlmonitor.events.payload import Payload
from cytlmonitor.events.relations import PreviousRelation, SessionRelation
from cytlmonitor.expressions.arithmetic import (
    AbsExpression, DifferenceExpression, DivisionExpression, NegationExpression,
    ProductExpression, SumExpression)
from cytlmonitor.expressions.constant import ConstantExpression
from cytlmonitor.expressions.shift import ShiftExpression
from cytlmonitor.expressions.window import (
    MaxWindowExpression, MinWindowExpression, SumWindowExpression)
from cytlmonitor.language import RESERVED, Specification, SpecificationError, load, parse
from cytlmonitor.monitors.atomic import (
    AtomicGeqMonitor, AtomicGreaterMonitor, AtomicLeqMonitor, AtomicLessMonitor)
from cytlmonitor.monitors.boolean import AndMonitor, ImplyMonitor, NotMonitor, OrMonitor
from cytlmonitor.monitors.constants import FalseMonitor, TrueMonitor
from cytlmonitor.monitors.filter import FilterMonitor
from cytlmonitor.monitors.next import NextMonitor
from cytlmonitor.monitors.temporal import (
    EventuallyMonitor, GloballyMonitor, SinceMonitor, UntilMonitor)

EXAMPLES = Path(__file__).resolve().parents[3] / 'examples'


def event(time, **payload):
    return Event(time, Payload(payload))


class Signal(BooleanSignalConsumer):
    def __init__(self):
        self.signal = BooleanSignal()
        self.horizon = 0.0

    def consume(self, i):
        self.signal.add(i)

    def set_horizon(self, t):
        self.horizon = t

    def intervals(self):
        return [(i.start, i.end, i.left_open, i.right_open) for i in self.signal]


class Segments(SignalConsumer):
    def __init__(self):
        self.segments = []

    def consume(self, s):
        i = s.interval
        self.segments.append((i.start, i.end, i.left_open, i.right_open,
                              tuple(s.polynomial.coefficients)))


def run_monitor(monitor, events):
    signal = Signal()
    monitor.add(signal)
    for e in events:
        monitor.consume(e)
    return signal.intervals(), signal.horizon


def run_expression(expression, events):
    segments = Segments()
    expression.add(segments)
    for e in events:
        expression.consume(e)
    return segments.segments


def spec_signal(spec, name, events):
    signal = Signal()
    spec[name].add(signal)
    spec.run(events)
    return signal.intervals(), signal.horizon


def spec_segments(spec, name, events):
    segments = Segments()
    spec[name].add(segments)
    spec.run(events)
    return segments.segments


def random_events(seed, n=120):
    rng = random.Random(seed)
    t, events = 0.0, []
    for _ in range(n):
        t += rng.choice((0.0, 0.2, 0.5, 1.0, 1.5))
        events.append(event(t, op=rng.choice(('START', 'STEP', 'DONE')),
                            x=rng.randint(0, 5), kind=rng.choice('AB')))
    return events


HEADER = '''
events
  start : op is "START"
  done  : op is "DONE"
'''


class TestValues(unittest.TestCase):
    """The values and conditions of the events, read through a sum over a
    window of length 1, which is their value at each event."""

    def values(self, text, events, **options):
        spec = parse(HEADER + 'values\n  v = ' + text + '\n'
                     'measures\n  m = sum of v in the next 1\n', **options)
        values = []
        weight = spec['m'].w
        for e in events:
            spec.consume(e)
            values.append(weight(e))
        return values

    def test_arithmetic_and_fields(self):
        events = [event(1, x=2, y=3), event(2, x=4, y=0)]
        self.assertEqual(self.values('x * y + 1', events), [7.0, 1.0])
        self.assertEqual(self.values('-x - (y - 1) * 2', events), [-6.0, -2.0])
        self.assertEqual(self.values('x / y', events), [2 / 3, 0.0])  # none when y is 0
        self.assertEqual(self.values('time * 10', events), [10.0, 20.0])

    def test_missing_fields_are_none(self):
        events = [event(1, x=2), event(2)]
        self.assertEqual(self.values('x + 1', events), [3.0, 0.0])
        self.assertEqual(self.values('x + 1, otherwise 10', events), [3.0, 10.0])
        self.assertEqual(self.values('x otherwise 10', events), [2.0, 10.0])

    def test_when(self):
        events = [event(1, op='START', x=2), event(2, op='DONE', x=4)]
        self.assertEqual(self.values('x when done', events), [0.0, 4.0])
        self.assertEqual(self.values('x when start otherwise -1', events), [2.0, -1.0])

    def test_conditions(self):
        events = [event(1, x=2, k='A'), event(2, x=4, k='B'), event(3, k='A')]
        self.assertEqual(self.values('x > 2', events), [0.0, 1.0, 0.0])
        self.assertEqual(self.values('x is between 1 and 3', events), [1.0, 0.0, 0.0])
        self.assertEqual(self.values('k "A"', events), [1.0, 0.0, 1.0])
        self.assertEqual(self.values('k is not "A"', events), [0.0, 1.0, 0.0])
        self.assertEqual(self.values('x is none', events), [0.0, 0.0, 1.0])
        self.assertEqual(self.values('x is above 3 or k is "A"', events), [1.0, 1.0, 1.0])
        # A comparison with none is false.
        self.assertEqual(self.values('not (x is at least 3) and k is "A"', events),
                         [1.0, 0.0, 1.0])
        self.assertEqual(self.values('x is at most 2', events), [1.0, 0.0, 0.0])
        self.assertEqual(self.values('x != 2', events), [0.0, 1.0, 0.0])

    def test_events_are_conditions(self):
        events = [event(1, op='START'), event(2, op='DONE'), event(3, op='STEP')]
        self.assertEqual(self.values('start + 2 * done', events), [1.0, 2.0, 0.0])

    def test_if_then_else(self):
        events = [event(1, x=2), event(2, x=4)]
        self.assertEqual(self.values('if x > 3 then 10 else 20', events), [20.0, 10.0])

    def test_field_and_strings(self):
        events = [event(1, **{'to': 3, 'n': 'a'})]
        self.assertEqual(self.values('field "to"', events), [3.0])
        self.assertEqual(self.values("n is 'a'", events), [1.0])

    def test_functions(self):
        events = [event(1, x=-2, y=3)]
        self.assertEqual(self.values('abs(x) + max(x, y) + min(x, y)', events), [3.0])
        self.assertEqual(self.values('square(x)', events,
                                     functions={'square': lambda v: v * v}), [4.0])
        self.assertEqual(self.values('square(z)', events,
                                     functions={'square': lambda v: v * v}), [0.0])

    def test_constants(self):
        spec = parse('constants\n  A = 2  B = A * 3 + 1, C = (B - 1) / 2\n'
                     '  D = inf\n')
        self.assertEqual(spec.constants, {'A': 2.0, 'B': 7.0, 'C': 3.0, 'D': math.inf})

    def test_constants_can_be_replaced(self):
        spec = parse('constants\n  A = 2\n  B = A + 1\n', constants={'A': 5})
        self.assertEqual(spec.constants, {'A': 5.0, 'B': 6.0})

    def test_a_string_in_arithmetic_is_an_error(self):
        spec = parse('values\n  v = x + 1\nmeasures\n  m = sum of v in the next 1\n')
        with self.assertRaises(SpecificationError) as raised:
            spec.consume(event(1, x='a'))
        self.assertEqual(raised.exception.line, 2)

    def test_a_string_weight_is_an_error(self):
        spec = parse('measures\n  m = sum of x in the next 1\n')
        with self.assertRaises(SpecificationError):
            spec.consume(event(1, x='a'))


class TestLinks(unittest.TestCase):

    def test_a_link_reads_the_fields_of_the_linked_event(self):
        spec = parse(HEADER + '''
links
  job : from start to done, matched by session
values
  duration = time - job.time
  kind = job.kind
  previous_x = previous.x
measures
  d = sum of duration in the next 1
''')
        weight = spec['d'].w
        events = [event(1, op='START', session=1, kind='A'),
                  event(2, op='START', session=2, kind='B', x=5),
                  event(4, op='DONE', session=1),
                  event(7, op='DONE', session=2),
                  event(8, op='DONE', session=2)]
        values = []
        for e in events:
            spec.consume(e)
            values.append(weight(e))
        self.assertEqual(values, [0.0, 0.0, 3.0, 5.0, 6.0])
        self.assertEqual(len(spec.relations), 2)
        self.assertIsInstance(spec.relations[0], PreviousRelation)
        self.assertIsInstance(spec.relations[1], SessionRelation)

    def test_previous_is_created_only_when_used(self):
        spec = parse(HEADER + 'links\n  job : from start to done matched by session\n')
        self.assertEqual(len(spec.relations), 1)


class TestCounters(unittest.TestCase):

    def test_a_counter_includes_the_change_of_the_event(self):
        spec = parse(HEADER + '''
counters
  running : starts at 2, +1 at start, -1 at done
  big : +2.5 at x > 3
measures
  r = sum of running in the next 1
  b = sum of big in the next 1
''')
        events = [event(1, op='START'), event(2, op='START', x=4), event(3, op='DONE'),
                  event(4, op='STEP', x=5)]
        r, b = [], []
        for e in events:
            spec.consume(e)
            r.append(spec['r'].w(e))
            b.append(spec['b'].w(e))
        self.assertEqual(r, [3.0, 4.0, 3.0, 3.0])
        self.assertEqual(b, [0.0, 2.5, 2.5, 5.0])


class TestMeasures(unittest.TestCase):
    """Each measure gives the signal of the expression built by hand."""

    def check(self, text, build, events=None, extra=''):
        events = events or random_events(1)
        spec = parse(HEADER + extra + 'measures\n  m = ' + text + '\n')
        self.assertEqual(spec_segments(spec, 'm', events), run_expression(build(), events))

    def test_sum_and_number(self):
        x = lambda e: float(e.payload.get('x', 0))
        start = lambda e: e.payload['op'] == 'START'
        self.check('sum of x in the next 3', lambda: SumWindowExpression(x, 0, 3))
        self.check('sum of x over start events between 1 and 4 from now',
                   lambda: SumWindowExpression(lambda e: x(e) if start(e) else 0.0, 1, 4))
        self.check('number of start events with x > 2 in the next 2',
                   lambda: SumWindowExpression(
                       lambda e: float(start(e) and e.payload['x'] > 2), 0, 2))
        self.check('number of events in the next 2',
                   lambda: SumWindowExpression(lambda e: 1.0, 0, 2))

    def test_rate(self):
        self.check('rate of done events over the next 4',
                   lambda: DivisionExpression(
                       SumWindowExpression(lambda e: float(e.payload['op'] == 'DONE'), 0, 4),
                       ConstantExpression(4)))

    def test_average(self):
        x = lambda e: float(e.payload['x'])
        done = lambda e: e.payload['op'] == 'DONE'
        self.check('average of x over done events in the next 3',
                   lambda: DivisionExpression(
                       SumWindowExpression(lambda e: x(e) if done(e) else 0.0, 0, 3),
                       SumWindowExpression(lambda e: float(done(e)), 0, 3)))

    def test_average_skips_none(self):
        events = [event(1, x=4), event(1.5), event(2, x=2)]
        spec = parse('measures\n  m = average of x in the next 2\n')
        segments = spec_segments(spec, 'm', events + [event(10)])
        self.assertEqual(segments[0][-1], (3.0,))

    def test_time_average(self):
        # running is 1 on [1, 3), 2 on [3, 4), 1 on [4, 6): over [0, 6] the
        # weights are those of the events in the window.
        events = [event(1, op='START'), event(3, op='START'), event(4, op='DONE'),
                  event(6, op='STEP'), event(20, op='STEP')]
        spec = parse(HEADER + '''
counters
  running : +1 at start, -1 at done
measures
  m = time average of running over the next 6
''')
        segments = spec_segments(spec, 'm', events)
        first = segments[0]
        # At 0 the window [0, 6] holds the events at 1, 3, 4 and 6: running
        # is 1 for 2, 2 for 1 and 1 for 2 time units since the first one.
        self.assertEqual(first[0], 0.0)
        self.assertAlmostEqual(first[-1][0], (1 * 2 + 2 * 1 + 1 * 2) / 5)

    def test_extremes_and_shift(self):
        x = lambda: SumWindowExpression(lambda e: float(e.payload['x']), 0, 1)
        self.check('largest of sum of x in the next 1 over the next 3',
                   lambda: MaxWindowExpression(x(), 0, 3))
        self.check('minimum of (sum of x in the next 1) between 1 and 2 from now',
                   lambda: MinWindowExpression(x(), 1, 2))
        self.check('(sum of x in the next 1) delayed by 2',
                   lambda: ShiftExpression(x(), 2))
        self.check('(sum of x in the next 1) advanced by 0.5',
                   lambda: ShiftExpression(x(), -0.5))

    def test_arithmetic(self):
        x = lambda: SumWindowExpression(lambda e: float(e.payload['x']), 0, 1)
        n = lambda: SumWindowExpression(lambda e: 1.0, 0, 2)
        self.check('sum of x in the next 1 + number of events in the next 2 * 3',
                   lambda: SumExpression(x(), ProductExpression(n(), ConstantExpression(3))))
        self.check('-(sum of x in the next 1 - 2) / number of events in the next 2',
                   lambda: DivisionExpression(
                       NegationExpression(DifferenceExpression(x(), ConstantExpression(2))),
                       n()))
        self.check('abs(sum of x in the next 1 - 3)',
                   lambda: AbsExpression(DifferenceExpression(x(), ConstantExpression(3))))

    def test_measures_and_constants_by_name(self):
        x = lambda: SumWindowExpression(lambda e: float(e.payload['x']), 0, 1)
        events = random_events(2)
        spec = parse('constants\n  K = 2\nmeasures\n  a = sum of x in the next 1\n'
                     '  b = a * K - a\n')
        self.assertEqual(spec_segments(spec, 'b', events),
                         run_expression(DifferenceExpression(
                             ProductExpression(x(), ConstantExpression(2)), x()), events))

    def test_every_use_builds_new_nodes(self):
        spec = parse('measures\n  a = sum of x in the next 1\n  b = a - a\n')
        b = spec['b']
        self.assertIsNot(b.node(0), b.node(1))
        self.assertIsNot(spec['a'], b.node(0))
        self.assertIsNot(spec.build('a'), spec['a'])


class TestProperties(unittest.TestCase):
    """Each property gives the signal of the monitor built by hand."""

    MEASURES = '''
measures
  n = number of events in the next 1
  s = sum of x in the next 1
'''

    def check(self, text, build, events=None, extra=''):
        events = events or random_events(3)
        spec = parse(HEADER + extra + self.MEASURES + 'properties\n  p : ' + text + '\n')
        self.assertEqual(spec_signal(spec, 'p', events), run_monitor(build(), events))

    @staticmethod
    def n():
        return SumWindowExpression(lambda e: 1.0, 0, 1)

    @staticmethod
    def s():
        return SumWindowExpression(lambda e: float(e.payload['x']), 0, 1)

    def high(self):
        return AtomicGreaterMonitor(self.s(), ConstantExpression(4))

    def low(self):
        return AtomicLessMonitor(self.n(), ConstantExpression(2))

    def test_comparisons(self):
        c = ConstantExpression
        self.check('s > 4', lambda: AtomicGreaterMonitor(self.s(), c(4)))
        self.check('s >= n', lambda: AtomicGeqMonitor(self.s(), self.n()))
        self.check('s < 4', lambda: AtomicLessMonitor(self.s(), c(4)))
        self.check('s <= 4', lambda: AtomicLeqMonitor(self.s(), c(4)))
        self.check('s is above 4', lambda: AtomicGreaterMonitor(self.s(), c(4)))
        self.check('s is below 4', lambda: AtomicLessMonitor(self.s(), c(4)))
        self.check('s is at least 4', lambda: AtomicGeqMonitor(self.s(), c(4)))
        self.check('s is at most 4', lambda: AtomicLeqMonitor(self.s(), c(4)))
        self.check('s is between 2 and n + 3',
                   lambda: AndMonitor(AtomicGeqMonitor(self.s(), c(2)),
                                      AtomicLeqMonitor(self.s(), SumExpression(self.n(), c(3)))))

    def test_boolean_operators(self):
        self.check('s > 4 and n < 2', lambda: AndMonitor(self.high(), self.low()))
        self.check('s > 4 or n < 2', lambda: OrMonitor(self.high(), self.low()))
        self.check('not s > 4', lambda: NotMonitor(self.high()))
        self.check('s > 4 implies n < 2', lambda: ImplyMonitor(self.high(), self.low()))
        self.check('whenever s > 4, n < 2', lambda: ImplyMonitor(self.high(), self.low()))
        self.check('if s > 4 then n < 2', lambda: ImplyMonitor(self.high(), self.low()))
        self.check('true', TrueMonitor)
        self.check('false or s > 4', lambda: OrMonitor(FalseMonitor(), self.high()))
        self.check('not (s > 4 or n < 2) and true',
                   lambda: AndMonitor(NotMonitor(OrMonitor(self.high(), self.low())),
                                      TrueMonitor()))

    def test_parentheses_around_a_measure(self):
        self.check('(s) > 4', self.high)
        self.check('(s - 1) + 1 > 4',
                   lambda: AtomicGreaterMonitor(
                       SumExpression(DifferenceExpression(self.s(), ConstantExpression(1)),
                                     ConstantExpression(1)), ConstantExpression(4)))

    def test_temporal_operators(self):
        closed = lambda a, b: Interval(a, b, right_open=False)
        self.check('throughout the next 3, s > 4',
                   lambda: GloballyMonitor(self.high(), closed(0, 3)))
        self.check('throughout between 1 and 3 from now, s > 4',
                   lambda: GloballyMonitor(self.high(), closed(1, 3)))
        self.check('at some point within the next 2, s > 4 and n < 2',
                   lambda: EventuallyMonitor(AndMonitor(self.high(), self.low()),
                                             closed(0, 2)))
        self.check('eventually within 2, s > 4',
                   lambda: EventuallyMonitor(self.high(), closed(0, 2)))
        self.check('s > 4 until, within 3, n < 2',
                   lambda: UntilMonitor(self.high(), self.low(), closed(0, 3)))
        self.check('s > 4 since n < 2',
                   lambda: SinceMonitor(self.high(), self.low(), Interval(0)))
        self.check('always s > 4', lambda: GloballyMonitor(self.high(), Interval(0)))
        self.check('eventually, s > 4', lambda: EventuallyMonitor(self.high(), Interval(0)))
        self.check('s > 4 since, within the last 3, n < 2',
                   lambda: SinceMonitor(self.high(), self.low(), closed(0, 3)))
        self.check('s > 4 since between 1 and 3 ago, n < 2',
                   lambda: SinceMonitor(self.high(), self.low(), closed(1, 3)))

    def test_next_and_filter(self):
        start = lambda e: e.payload['op'] == 'START'
        self.check('the next event comes within 1',
                   lambda: NextMonitor(lambda e: True, 0, 1, TrueMonitor()))
        self.check('next event between 0.5 and 1 and has x > 2',
                   lambda: NextMonitor(lambda e: e.payload['x'] > 2, 0.5, 1, TrueMonitor()))
        self.check('the next event comes within 1 and is start, then s > 4',
                   lambda: NextMonitor(start, 0, 1, self.high()))
        self.check('considering only start events with x > 1, the next event comes within 1',
                   lambda: FilterMonitor(
                       lambda e: start(e) and e.payload['x'] > 1,
                       NextMonitor(lambda e: True, 0, 1, TrueMonitor())))
        self.check('considering only done events, s > 4',
                   lambda: FilterMonitor(lambda e: e.payload['op'] == 'DONE', self.high()))

    def test_properties_by_name(self):
        events = random_events(4)
        spec = parse(self.MEASURES + 'properties\n  high : s > 4\n'
                     '  p : throughout the next 2, high or n < 2\n')
        self.assertEqual(
            spec_signal(spec, 'p', events),
            run_monitor(GloballyMonitor(OrMonitor(self.high(), self.low()),
                                        Interval(0, 2, right_open=False)), events))

    def test_formula(self):
        spec = parse(HEADER + self.MEASURES + 'properties\n'
                     '  p : considering only start events, the next event comes within 1\n'
                     '  q : throughout the next 2, s > 4\n')
        self.assertEqual(str(spec['p']), 'filter[start events] <any>[0,1] true')
        self.assertEqual(str(spec['q']), 'G[0,2] (sum[0,1] x > 4)')


class TestLayout(unittest.TestCase):

    def test_comments_continuations_and_separators(self):
        spec = parse('''
# A comment
constants:  # the header may end with ':'
    A = 1   # a comment
measures
    m =
        number of events
        in the next A   # continued
properties
    p :
      m > 0

''')
        self.assertEqual(list(spec.measures), ['m'])
        self.assertEqual(list(spec.properties), ['p'])

    def test_tabs_indent(self):
        spec = parse('constants\n\tA = 1\n\tB = 2\n')
        self.assertEqual(spec.constants, {'A': 1.0, 'B': 2.0})

    def test_show(self):
        source = ('measures\n  a = number of events in the next 1\n'
                  'properties\n  p : a > 1\n  q : a < 1\n')
        self.assertEqual(parse(source).show, ('p', 'q', 'a'))
        self.assertEqual(parse(source + 'show\n  a, q\n').show, ('a', 'q'))
        self.assertEqual(parse(source + 'show\n  all measures, all properties\n').show,
                         ('a', 'p', 'q'))

    def test_empty(self):
        spec = parse('')
        self.assertEqual((spec.properties, spec.measures), ({}, {}))
        spec.consume(event(1))


class TestErrors(unittest.TestCase):

    def error(self, source, **options):
        with self.assertRaises(SpecificationError) as raised:
            parse(source, **options)
        return raised.exception

    def test_position(self):
        error = self.error('measures\n  a = number of events in the next 1\n'
                           'properties\n  p : a >\n')
        self.assertEqual((error.line, error.column), (4, 10))
        self.assertIn('expected a measure', error.message)
        self.assertIn('    p : a >', str(error))

    def test_layout(self):
        self.assertIn('must name a section', self.error('events\nstart : op is "A"\n').message)
        self.assertIn('must name a section', self.error('things\n  a = 1\n').message)
        self.assertIn('before the first section', self.error('  a = 1\n').message)
        self.assertIn('indented less',
                      self.error('constants\n    A = 1\n  B = 2\n').message)
        self.assertIn('unexpected character', self.error('constants\n  A = 1 $\n').message)

    def test_names(self):
        self.assertIn('word of the language', self.error('constants\n  next = 1\n').message)
        self.assertIn('already defined',
                      self.error('constants\n  A = 1\nevents\n  A : x > 1\n').message)
        self.assertIn('defined later', self.error(
            'measures\n  a = b\n  b = number of events in the next 1\n').message)
        self.assertIn("did you mean 'rate_a'", self.error(
            'measures\n  rate_a = number of events in the next 1\n'
            'properties\n  p : rate_b > 1\n').message)
        self.assertIn('no constant named', self.error('constants\n  A = 1\n',
                                                      constants={'B': 2}).message)
        self.assertIn('expected', self.error('constants\n  A 1\n').message)

    def test_kinds(self):
        self.assertIn('not a signal over time', self.error(
            'values\n  v = x\nproperties\n  p : v > 1\n').message)
        self.assertIn('here a value of each event is needed', self.error(
            'measures\n  m = number of events in the next 1\nvalues\n  v = m + 1\n').message)
        self.assertIn('is a link', self.error(
            'links\n  j : from x to y matched by s\nvalues\n  v = j\n').message)
        self.assertIn('not a link', self.error('constants\n  A = 1\nvalues\n  v = A.x\n')
                      .message)
        self.assertIn('a number or a constant', self.error(
            'values\n  v = x\nmeasures\n  m = number of events in the next v\n').message)
        self.assertIn('not a function', self.error('constants\n  A = 1\nvalues\n  v = A(1)\n')
                      .message)
        self.assertIn('cannot compare measures', self.error(
            'measures\n  m = number of events in the next 1\nproperties\n  p : m == 1\n')
            .message)
        self.assertIn('only properties and measures', self.error(
            'constants\n  A = 1\nshow\n  A\n').message)

    def test_windows(self):
        self.assertIn('window of a measure',
                      self.error('measures\n  m = number of events in the next 0\n').message)
        self.assertIn('window of a measure', self.error(
            'measures\n  m = number of events between 2 and 1 from now\n').message)
        self.assertIn('expected a window',
                      self.error('measures\n  m = number of events\n').message)
        self.assertIn('next event', self.error(
            'properties\n  p : the next event comes between 1 and 1\n').message)
        self.assertIn('window must go', self.error(
            'measures\n  m = number of events in the next 1\n'
            'properties\n  p : throughout between 2 and 1, m > 1\n').message)

    def test_until_needs_a_bounded_window(self):
        self.assertIn('bounded window', self.error(
            'measures\n  m = number of events in the next 1\n'
            'properties\n  p : m > 1 until m < 1\n').message)

    def test_functions_must_be_callable(self):
        with self.assertRaises(TypeError):
            parse('', functions={'f': 3})
        with self.assertRaises(SpecificationError):
            parse('', functions={'next': len})

    def test_reserved_words_are_names(self):
        self.assertTrue(all(w.isidentifier() for w in RESERVED))


class TestSpecification(unittest.TestCase):

    SOURCE = '''
measures
  a = number of events in the next 1
properties
  p : a > 1
'''

    def test_access(self):
        spec = parse(self.SOURCE)
        self.assertIsInstance(spec, Specification)
        self.assertIs(spec['p'], spec.properties['p'])
        self.assertIs(spec['a'], spec.measures['a'])
        self.assertIn('p', spec)
        self.assertNotIn('b', spec)
        with self.assertRaises(KeyError):
            spec['b']
        with self.assertRaises(KeyError):
            spec.build('b')
        self.assertEqual(repr(spec), "Specification(properties=['p'], measures=['a'])")

    def test_plot(self):
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        spec = parse(self.SOURCE)
        plotters = spec.plot(titles={'a': 'events'})
        self.assertEqual([p.axes.get_title(loc='left') for p in plotters], ['p', 'events'])
        plotters = spec.plot('a')
        self.assertEqual([p.axes.get_title(loc='left') for p in plotters], ['a'])
        plt.close('all')

    def test_load(self):
        spec = load(EXAMPLES / 'worker.mon')
        self.assertEqual(list(spec.properties),
                         ['load', 'completion_time', 'heavy', 'next_job', 'b_service',
                          'recovery'])
        self.assertEqual(list(spec.measures),
                         ['load_avg', 'completion', 'heavy_jobs', 'arrivals', 'throughput'])


if __name__ == '__main__':
    unittest.main()
