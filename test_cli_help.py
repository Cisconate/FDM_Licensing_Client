"""Tests that human-facing command help remains complete and side-effect free."""

import io
import unittest
from contextlib import redirect_stdout

from cisco_support_token_client import parse_args as parse_token_args
from example import parse_args as parse_example_args
from fdm_licensing.cli import _parser as application_parser


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

    def test_account_help_documents_selection_switches_and_example(self) -> None:
        help_text = self._help_text(
            lambda argv: application_parser().parse_args(["cisco", "accounts", *argv])
        )
        self.assertIn("--smart-account", help_text)
        self.assertIn("--virtual-account", help_text)
        self.assertIn("example:", help_text)


if __name__ == "__main__":
    unittest.main()
