"""Unit tests for cytlmonitor.payload.Payload."""

import unittest
from collections.abc import Mapping

from cytlmonitor.payload import Payload


class TestPayloadConstruction(unittest.TestCase):

    def test_empty_payload(self):
        p = Payload({})
        self.assertEqual(len(p), 0)
        self.assertEqual(p.fields(), frozenset())

    def test_is_a_mapping(self):
        self.assertIsInstance(Payload({}), Mapping)

    def test_mutating_source_dict_after_construction_has_no_effect(self):
        source = {'a': 1}
        p = Payload(source)
        source['a'] = 999
        source['b'] = 2
        self.assertEqual(p['a'], 1)
        self.assertNotIn('b', p)


class TestGetters(unittest.TestCase):

    def setUp(self):
        self.payload = Payload({'src': '10.0.0.1', 'dst': '10.0.0.2', 'size': 128})

    def test_getitem(self):
        self.assertEqual(self.payload['src'], '10.0.0.1')
        self.assertEqual(self.payload['size'], 128)

    def test_getitem_missing_field_raises_key_error(self):
        with self.assertRaises(KeyError):
            self.payload['missing']

    def test_get_with_existing_field(self):
        self.assertEqual(self.payload.get('dst'), '10.0.0.2')

    def test_get_missing_field_returns_none_by_default(self):
        self.assertIsNone(self.payload.get('missing'))

    def test_get_missing_field_returns_given_default(self):
        self.assertEqual(self.payload.get('missing', 'fallback'), 'fallback')

    def test_contains(self):
        self.assertIn('src', self.payload)
        self.assertNotIn('missing', self.payload)

    def test_len(self):
        self.assertEqual(len(self.payload), 3)

    def test_iter_yields_fields(self):
        self.assertEqual(set(iter(self.payload)), {'src', 'dst', 'size'})

    def test_keys_values_items(self):
        self.assertEqual(set(self.payload.keys()), {'src', 'dst', 'size'})
        self.assertEqual(set(self.payload.values()), {'10.0.0.1', '10.0.0.2', 128})
        self.assertEqual(
            set(self.payload.items()),
            {('src', '10.0.0.1'), ('dst', '10.0.0.2'), ('size', 128)}
        )


class TestFields(unittest.TestCase):

    def test_fields_returns_the_set_of_keys(self):
        p = Payload({'a': 1, 'b': 2})
        self.assertEqual(p.fields(), {'a', 'b'})

    def test_fields_is_a_frozenset(self):
        p = Payload({'a': 1})
        self.assertIsInstance(p.fields(), frozenset)

    def test_mutating_returned_fields_does_not_affect_payload(self):
        p = Payload({'a': 1})
        fields = p.fields()
        with self.assertRaises(AttributeError):
            fields.add('b')  # frozenset has no 'add' method
        self.assertEqual(p.fields(), {'a'})


class TestReadOnlyness(unittest.TestCase):

    def test_no_setitem(self):
        p = Payload({'a': 1})
        with self.assertRaises(TypeError):
            p['a'] = 2

    def test_no_delitem(self):
        p = Payload({'a': 1})
        with self.assertRaises(TypeError):
            del p['a']


class TestEqualityAndRepr(unittest.TestCase):

    def test_equal_payloads(self):
        self.assertEqual(Payload({'a': 1, 'b': 2}), Payload({'b': 2, 'a': 1}))

    def test_different_payloads_are_not_equal(self):
        self.assertNotEqual(Payload({'a': 1}), Payload({'a': 2}))
        self.assertNotEqual(Payload({'a': 1}), Payload({'a': 1, 'b': 2}))

    def test_repr_contains_data(self):
        p = Payload({'a': 1})
        self.assertIn("'a': 1", repr(p))


if __name__ == '__main__':
    unittest.main()
