"""Unit tests for cytlmonitor.core.node: navigating the tree of a formula
and writing its nodes."""

import math
import unittest

from cytlmonitor import (
    AbsExpression, AndMonitor, AtomicGeqMonitor, AtomicGreaterMonitor, AtomicLeqMonitor,
    AtomicLessMonitor, ConstantExpression, DifferenceExpression, DivisionExpression,
    EventMonitor, EventuallyMonitor, FalseMonitor, FilterMonitor, FormulaNode,
    GloballyMonitor, ImplyMonitor, InstrumentedMonitor, Interval, MaxWindowExpression,
    MinWindowExpression, NegationExpression, NextMonitor, NotMonitor, OrMonitor,
    PreviousRelation, ProductExpression, ShiftExpression, SinceMonitor, StreamExpression,
    SumExpression, SumWindowExpression, TrueMonitor, UntilMonitor,
)


def size(e):
    return e.payload['size']


def c(x):
    return ConstantExpression(x)


class Flag(EventMonitor):

    def consume(self, e):
        pass


class TestNavigation(unittest.TestCase):

    def setUp(self):
        self.rate = SumWindowExpression(size, 0, 1)
        self.high = AtomicGreaterMonitor(self.rate, c(100))
        self.ahead = EventuallyMonitor(self.high, Interval(0, 2, right_open=False))
        self.root = AndMonitor(NotMonitor(TrueMonitor()), self.ahead)

    def test_every_expression_and_monitor_is_a_node(self):
        self.assertIsInstance(self.rate, FormulaNode)
        self.assertIsInstance(self.root, FormulaNode)
        self.assertIsInstance(Flag(), FormulaNode)

    def test_operands(self):
        self.assertEqual(self.root.operands[1], self.ahead)
        self.assertEqual(self.ahead.operands, (self.high,))
        self.assertEqual(self.high.operands, (self.rate, self.high.arg2))
        self.assertEqual(self.rate.operands, ())
        self.assertEqual(Flag().operands, ())

    def test_operands_of_every_operator(self):
        e1, e2 = c(1), c(2)
        m1, m2 = TrueMonitor(), FalseMonitor()
        i = Interval(0, 1)
        cases = [
            (SumExpression(e1, e2), (e1, e2)), (DifferenceExpression(e1, e2), (e1, e2)),
            (ProductExpression(e1, e2), (e1, e2)), (DivisionExpression(e1, e2), (e1, e2)),
            (NegationExpression(e1), (e1,)), (AbsExpression(e1), (e1,)),
            (ShiftExpression(e1, 1), (e1,)), (MaxWindowExpression(e1, 0, 1), (e1,)),
            (MinWindowExpression(e1, 0, 1), (e1,)), (c(3), ()),
            (SumWindowExpression(size, 0, 1), ()),
            (AtomicLeqMonitor(e1, e2), (e1, e2)), (AndMonitor(m1, m2), (m1, m2)),
            (OrMonitor(m1, m2), (m1, m2)), (ImplyMonitor(m1, m2), (m1, m2)),
            (NotMonitor(m1), (m1,)), (EventuallyMonitor(m1, i), (m1,)),
            (GloballyMonitor(m1, i), (m1,)), (UntilMonitor(m1, m2, i), (m1, m2)),
            (SinceMonitor(m1, m2, i), (m1, m2)), (NextMonitor(size, 0, 1, m1), (m1,)),
            (FilterMonitor(size, m1), (m1,)), (InstrumentedMonitor([], m1), (m1,)),
            (TrueMonitor(), ()), (FalseMonitor(), ()),
        ]
        for node, operands in cases:
            with self.subTest(node=type(node).__name__):
                self.assertEqual(len(node.operands), len(operands))
                for got, expected in zip(node.operands, operands):
                    self.assertIs(got, expected)

    def test_nodes_in_pre_order(self):
        nodes = list(self.root.nodes())
        expected = [self.root, self.root.operands[0], self.root.operands[0].operands[0],
                    self.ahead, self.high, self.rate, self.high.arg2]
        self.assertEqual(len(nodes), len(expected))
        for got, node in zip(nodes, expected):
            self.assertIs(got, node)

    def test_nodes_down_to_a_depth(self):
        self.assertEqual(list(self.root.nodes(0)), [self.root])
        self.assertEqual(list(self.root.nodes(1)),
                         [self.root, self.root.operands[0], self.ahead])
        self.assertEqual(len(list(self.root.nodes(2))), 5)

    def test_rejects_negative_depth(self):
        with self.assertRaises(ValueError):
            list(self.root.nodes(-1))

    def test_shared_node_is_listed_once(self):
        m = TrueMonitor()
        root = OrMonitor(m, m)
        self.assertEqual(list(root.nodes()), [root, m])

    def test_node_by_path(self):
        self.assertIs(self.root.node(), self.root)
        self.assertIs(self.root.node(1), self.ahead)
        self.assertIs(self.root.node(1, 0, 0), self.rate)
        self.assertIs(self.root.node(-1, 0), self.high)

    def test_node_by_invalid_path(self):
        for path in [(2,), (1, 1), (1, 0, 0, 0)]:
            with self.subTest(path=path), self.assertRaises(IndexError):
                self.root.node(*path)

    def test_consumers_can_be_added_to_a_node_after_building(self):
        from cytlmonitor import BooleanSignalConsumer, Event, Payload

        class Record(BooleanSignalConsumer):
            def __init__(self):
                self.intervals = []

            def consume(self, i):
                self.intervals.append(i)

            def set_horizon(self, t):
                pass

        root = AndMonitor(TrueMonitor(), NotMonitor(FalseMonitor()))
        record = Record()
        root.node(1, 0).add(record)
        root.consume(Event(1, Payload({})))
        self.assertEqual(record.intervals, [])
        record2 = Record()
        root.node(1).add(record2)
        root.consume(Event(2, Payload({})))
        self.assertEqual(record2.intervals, [Interval(1, 2)])


class TestFormula(unittest.TestCase):

    def test_expressions(self):
        cases = [
            (c(2.0), '2'), (c(-0.5), '-0.5'), (c(math.inf), 'inf'),
            (SumWindowExpression(size, 0, 1), 'sum[0,1] size'),
            (SumWindowExpression(lambda e: 1.0, 0, 1), 'sum[0,1] w'),
            (SumExpression(c(1), c(2)), '1 + 2'), (DifferenceExpression(c(1), c(2)), '1 - 2'),
            (ProductExpression(c(1), c(2)), '1 * 2'), (DivisionExpression(c(1), c(2)), '1 / 2'),
            (NegationExpression(c(1)), '-1'), (AbsExpression(c(1)), '|1|'),
            (ShiftExpression(c(1), 2), 'shift[2] 1'),
            (MaxWindowExpression(c(1), 0, 3), 'max[0,3] 1'),
            (MinWindowExpression(c(1), 0.5, 3), 'min[0.5,3] 1'),
        ]
        for node, text in cases:
            with self.subTest(text=text):
                self.assertEqual(str(node), text)

    def test_infix_operands_are_parenthesised(self):
        self.assertEqual(str(ProductExpression(SumExpression(c(1), c(2)), c(3))), '(1 + 2) * 3')
        self.assertEqual(str(NegationExpression(SumExpression(c(1), c(2)))), '-(1 + 2)')
        self.assertEqual(str(AbsExpression(SumExpression(c(1), c(2)))), '|1 + 2|')
        self.assertEqual(str(MaxWindowExpression(SumExpression(c(1), c(2)), 0, 1)),
                         'max[0,1] (1 + 2)')

    def test_monitors(self):
        t, f = TrueMonitor(), FalseMonitor()
        cases = [
            (t, 'true'), (f, 'false'),
            (AtomicLeqMonitor(c(1), c(2)), '1 <= 2'), (AtomicLessMonitor(c(1), c(2)), '1 < 2'),
            (AtomicGeqMonitor(c(1), c(2)), '1 >= 2'),
            (AtomicGreaterMonitor(c(1), c(2)), '1 > 2'),
            (AndMonitor(t, f), 'true & false'), (OrMonitor(t, f), 'true | false'),
            (ImplyMonitor(t, f), 'true -> false'), (NotMonitor(t), 'not true'),
            (EventuallyMonitor(t, Interval(0, 2, right_open=False)), 'F[0,2] true'),
            (GloballyMonitor(t, Interval(1, None, left_open=True)), 'G(1,inf) true'),
            (UntilMonitor(t, f, Interval(0, 3)), 'true U[0,3) false'),
            (SinceMonitor(t, f, Interval(0, math.inf)), 'true S[0,inf) false'),
            (NextMonitor(size, 0, 1, t), '<size>[0,1] true'),
            (NextMonitor(lambda e: True, 1, math.inf, t), '<beta>[1,inf) true'),
            (FilterMonitor(size, t), 'filter[size] true'),
            (FilterMonitor(lambda e: True, t), 'filter[beta] true'),
            (InstrumentedMonitor([PreviousRelation()], t), 'true'),
            (Flag(), 'Flag'),
        ]
        for node, text in cases:
            with self.subTest(text=text):
                self.assertEqual(str(node), text)

    def test_nested_monitor(self):
        rate = SumWindowExpression(size, 0, 1)
        m = AndMonitor(NotMonitor(AtomicGreaterMonitor(rate, c(100))),
                       EventuallyMonitor(OrMonitor(TrueMonitor(), FalseMonitor()),
                                         Interval(0, 2, right_open=False)))
        self.assertEqual(str(m), 'not (sum[0,1] size > 100) & F[0,2] (true | false)')

    def test_expression_and_monitor_bases(self):
        self.assertTrue(issubclass(StreamExpression, FormulaNode))
        self.assertTrue(issubclass(EventMonitor, FormulaNode))


if __name__ == '__main__':
    unittest.main()
