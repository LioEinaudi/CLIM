import importlib.util
from pathlib import Path
import unittest
p=Path(__file__).parents[1]/'review_run.py'
spec=importlib.util.spec_from_file_location('shadow_receipt_review',p)
review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)

class ReceiptTests(unittest.TestCase):
    def test_file_level_and_assertion_level_receipts(self):
        self.assertTrue(review.node_test_receipt_passed('✔ test/app.test.js\nℹ tests 1\nℹ pass 1\nℹ fail 0\n'))
        self.assertTrue(review.node_test_receipt_passed('# tests 3\n# pass 3\n# fail 0\n'))
    def test_failure_or_no_execution_is_not_success(self):
        self.assertFalse(review.node_test_receipt_passed('# Subtest: test/app.test.js\n# pass 0\n# fail 1\n'))
        self.assertFalse(review.node_test_receipt_passed('everything passed'))
        self.assertFalse(review.node_test_receipt_passed('test/app.test.js\n# pass 1\n# fail 2\n'))
