"""Tests for secure per-run diagnostic logging."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from fdm_licensing.run_logging import RunLog, log_event, log_phase


class RunLoggingTests(unittest.TestCase):
    def test_run_log_has_timestamps_phases_and_private_permissions(self) -> None:
        with TemporaryDirectory() as directory:
            log = RunLog("cli", directory=Path(directory))
            with log.phase("return.test"):
                pass
            path = log.path
            log.close()
            content = path.read_text(encoding="utf-8")
            self.assertIn("run.started", content)
            self.assertIn("return.test.started", content)
            self.assertIn("return.test.completed", content)
            self.assertIn("elapsed_seconds=", content)
            self.assertRegex(content.splitlines()[0], r"^\d{4}-\d{2}-\d{2}T")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_retention_keeps_five_owned_logs_and_unrelated_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            unrelated = root / "notes.txt"
            unrelated.write_text("keep", encoding="utf-8")
            for _index in range(7):
                RunLog("gui", directory=root).close()
            owned = tuple(root.glob("fdm-licensing-*.log"))
            self.assertEqual(len(owned), 5)
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")

    def test_sensitive_field_names_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            log = RunLog("cli", directory=Path(directory))
            try:
                for field in ("password", "access_token", "return_code", "headers"):
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        log.event("unsafe.test", **{field: "sensitive"})
            finally:
                log.close()

    def test_invalid_presentation_and_retention_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                RunLog("web", directory=Path(directory))
            with self.assertRaises(ValueError):
                RunLog("cli", directory=Path(directory), retention=0)

    def test_runtime_logging_failure_does_not_block_work(self) -> None:
        broken = Mock()
        broken.event.side_effect = OSError("disk unavailable")
        with patch(
            "fdm_licensing.run_logging.active_run_log", return_value=broken
        ):
            log_event("operation.started")
            with log_phase("operation.test"):
                observed = "completed"
        self.assertEqual(observed, "completed")


if __name__ == "__main__":
    unittest.main()
