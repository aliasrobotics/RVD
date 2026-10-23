"""Regression tests for the documented detection methods."""
from pathlib import Path
import runpy
import unittest

from cerberus import Validator


class DetectionMethodTests(unittest.TestCase):
    def test_documented_detection_methods(self):
        schema = runpy.run_path(
            str(Path(__file__).resolve().parents[1] / "rvd_tools/database/schema.py")
        )["SCHEMA"]["flaw"]["schema"]["detected-by-method"]
        validator = Validator({"detected-by-method": schema})
        for method in ("runtime crash", "testing violation"):
            with self.subTest(method=method):
                self.assertTrue(
                    validator.validate({"detected-by-method": method}),
                    validator.errors,
                )
        self.assertFalse(validator.validate({"detected-by-method": "runtime crashtesting violation"}))


if __name__ == "__main__":
    unittest.main()
