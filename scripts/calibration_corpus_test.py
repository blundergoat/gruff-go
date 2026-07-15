#!/usr/bin/env python3
"""Focused tests for calibration command and temporary-binary ownership."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("calibration-corpus.py")
SPEC = importlib.util.spec_from_file_location("calibration_corpus", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CALIBRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CALIBRATION)


class CalibrationInvocationTest(unittest.TestCase):
    """Pin provenance and run-private binary defaults."""

    def test_direct_invocation_records_python_and_arguments(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            sys, "argv", [str(SCRIPT), "--spec", "custom.json"]
        ):
            command = CALIBRATION.recorded_calibration_command()

        self.assertIn("calibration-corpus.py", command)
        self.assertIn("--spec", command)
        self.assertIn("custom.json", command)
        self.assertTrue(command.startswith(sys.executable))

    def test_wrapper_command_is_preserved(self) -> None:
        wrapper = "scripts/calibrate-scratchpad-corpus.sh --spec custom.json"
        with mock.patch.dict(os.environ, {"GRUFF_GO_CALIBRATION_COMMAND": wrapper}, clear=True):
            self.assertEqual(CALIBRATION.recorded_calibration_command(), wrapper)

    def test_default_binary_belongs_to_unique_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            binary, owned = CALIBRATION.calibration_binary(None, stage)

        self.assertEqual(binary, stage / "gruff-go-calibration")
        self.assertTrue(owned)

    def test_explicit_binary_remains_external(self) -> None:
        explicit = Path("/opt/gruff-go")
        binary, owned = CALIBRATION.calibration_binary(explicit, Path("/tmp/stage"))
        self.assertEqual(binary, explicit)
        self.assertFalse(owned)


if __name__ == "__main__":
    unittest.main()
