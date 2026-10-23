"""Local tooling checks only. These do not simulate a switch or prove controller correctness."""
import ast
import tempfile
import unittest
from pathlib import Path
from check_mutations import classify
from make_variants import materialize


class EvidenceChecks(unittest.TestCase):
    def test_crashes_and_missing_tests_cannot_kill_mutants(self):
        self.assertEqual(classify(1, [{'id': 'x', 'status': 'ERROR'}], ['x']), 'INVALID')
        self.assertEqual(classify(1, [], ['x']), 'INVALID')
        self.assertEqual(classify(1, [{'id': 'y', 'status': 'FAIL'}], ['x']), 'INVALID')
        self.assertEqual(classify(1, [{'id': 'x', 'status': 'PASS'}], ['x']), 'INVALID')
        self.assertEqual(classify(-9, [{'id': 'x', 'status': 'FAIL'}], ['x']), 'INVALID')
        self.assertEqual(classify(1, [{'id': 'x', 'status': 'FAIL'}], ['x']), 'FAIL')
        self.assertEqual(classify(0, [{'id': 'x', 'status': 'PASS'}], ['x']), 'PASS')

    def test_variants_are_reproducible_and_do_not_use_runtime_bug_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = materialize(root / 'a')
            second = materialize(root / 'b')
            self.assertEqual(first, second)
            self.assertEqual(len(set(first['variants'].values())), 4)
            for name in first['variants']:
                source = (root / 'a' / (name + '.py')).read_text()
                self.assertNotIn('RAIN_BUG', source)
                self.assertNotIn('self.bug', source)
                ast.parse(source, feature_version=(3, 8))
            with self.assertRaises(FileExistsError):
                materialize(root / 'a')


if __name__ == '__main__':
    unittest.main()
