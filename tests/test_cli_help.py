"""Tests that human-facing command help remains complete and side-effect free."""

import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import redirect_stdout

from cisco_support_token_client import parse_args as parse_token_args
from example import parse_args as parse_example_args
from fdm_licensing.cli import _parser as application_parser
from key_manager import parse_args as parse_key_manager_args


class CliHelpTests(unittest.TestCase):
    def _help_text(self, parser_call) -> str:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            parser_call(["--help"])
        self.assertEqual(raised.exception.code, 0)
        return output.getvalue()

    def test_example_help_documents_all_switches_and_environment(self) -> None:
        help_text = self._help_text(parse_example_args)
        for option in (
            "--host",
            "--port",
            "--username",
            "--password",
            "--ca-bundle",
            "--certificate-store-dir",
            "--bootstrap-certificate",
            "--api-version",
            "--debug-logging",
            "--log-file",
            "--verify-certificate",
            "--no-verify-certificate",
        ):
            self.assertIn(option, help_text)
        self.assertIn("FDM_HOST", help_text)
        self.assertIn("python example.py", help_text)

    def test_token_help_documents_safe_live_check(self) -> None:
        help_text = self._help_text(parse_token_args)
        self.assertIn("--check", help_text)
        self.assertIn("live OAuth request", help_text)
        self.assertIn("never displays", help_text)

    def test_key_manager_help_documents_group_update(self) -> None:
        help_text = self._help_text(parse_key_manager_args)
        self.assertIn("update", help_text)
        update_help = self._help_text(
            lambda argv: parse_key_manager_args(["update", *argv])
        )
        self.assertIn("CISCO_CLIENT", update_help)
        self.assertIn("FDM", update_help)

    def test_account_help_documents_selection_switches_and_example(self) -> None:
        help_text = self._help_text(
            lambda argv: application_parser().parse_args(["cisco", "accounts", *argv])
        )
        self.assertIn("--smart-account", help_text)
        self.assertIn("--virtual-account", help_text)
        self.assertIn("example:", help_text)

    def test_plr_help_documents_stages_and_keeps_secrets_off_command_line(self) -> None:
        top = self._help_text(
            lambda argv: application_parser().parse_args(["plr", *argv])
        )
        for command in (
            "run", "inspect", "reserve", "install", "return-inspect",
            "return-generate", "return-complete", "return",
        ):
            self.assertIn(command, top)
        run = self._help_text(
            lambda argv: application_parser().parse_args(["plr", "run", *argv])
        )
        self.assertIn("--smart-account", run)
        self.assertIn("--virtual-account", run)
        self.assertIn("--unattended", run)
        self.assertIn("existing trusted", run)
        self.assertIn("FDM certificate", run)
        self.assertIn("prompted when omitted", run)
        install = self._help_text(
            lambda argv: application_parser().parse_args(["plr", "install", *argv])
        )
        self.assertNotIn("--authorization-code", install)
        self.assertIn("example:", install)

    def test_gui_package_module_smoke_launch(self) -> None:
        environment = os.environ.copy()
        environment["QT_QPA_PLATFORM"] = "offscreen"
        result = subprocess.run(
            [sys.executable, "-m", "fdm_licensing.gui", "--smoke-test"],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
