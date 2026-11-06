"""Run the examples of the documentation in ``docs/`` as doctests, so that
the outputs it shows stay those the code produces."""

import doctest
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / 'docs'


class TestDocs(unittest.TestCase):

    def test_examples_in_the_documentation(self):
        pages = sorted(DOCS.glob('*.md'))
        self.assertTrue(pages)
        examples = 0
        for page in pages:
            with self.subTest(page=page.name):
                result = doctest.testfile(str(page), module_relative=False,
                                          optionflags=doctest.ELLIPSIS)
                self.assertEqual(result.failed, 0, f'{page.name}: see the doctest output above')
                examples += result.attempted
        self.assertGreater(examples, 0)


if __name__ == '__main__':
    unittest.main()
