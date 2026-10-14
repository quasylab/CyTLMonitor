"""Unit tests for cytlmonitor.measure.Measure."""

import unittest

from cytlmonitor.event import Event
from cytlmonitor.measure import Measure
from cytlmonitor.payload import Payload


class TestConstruction(unittest.TestCase):

    def test_wraps_a_plain_function(self):
        m = Measure(lambda e: e['size'])
        self.assertIsNone(m.name)

    def test_wraps_a_named_function(self):
        m = Measure(lambda e: e['size'], name='size')
        self.assertEqual(m.name, 'size')

    def test_non_callable_raises_type_error(self):
        with self.assertRaises(TypeError):
            Measure(42)


class TestEvaluate(unittest.TestCase):

    def setUp(self):
        self.event = Event(1.0, Payload({'size': 128, 'flag': True}))

    def test_evaluate_applies_the_function_to_the_event(self):
        m = Measure(lambda e: e['size'])
        self.assertEqual(m.evaluate(self.event), 128.0)

    def test_call_is_equivalent_to_evaluate(self):
        m = Measure(lambda e: e['size'])
        self.assertEqual(m(self.event), m.evaluate(self.event))

    def test_result_is_coerced_to_float(self):
        m = Measure(lambda e: e['size'])
        self.assertIsInstance(m.evaluate(self.event), float)

    def test_function_receives_the_whole_event(self):
        m = Measure(lambda e: e.get_time())
        self.assertEqual(m.evaluate(self.event), 1.0)

    def test_evaluate_with_non_event_raises_type_error(self):
        m = Measure(lambda e: 1.0)
        with self.assertRaises(TypeError):
            m.evaluate({'size': 128})

    def test_constant_measure(self):
        m = Measure(lambda e: 3)
        self.assertEqual(m.evaluate(self.event), 3.0)
        other_event = Event(5.0, Payload({}))
        self.assertEqual(m.evaluate(other_event), 3.0)


class TestRepr(unittest.TestCase):

    def test_repr_includes_name_when_present(self):
        m = Measure(lambda e: 1.0, name='size')
        self.assertIn('size', repr(m))

    def test_repr_falls_back_to_the_function_when_unnamed(self):
        def my_function(e):
            return 1.0

        m = Measure(my_function)
        self.assertIn('my_function', repr(m))


if __name__ == '__main__':
    unittest.main()
