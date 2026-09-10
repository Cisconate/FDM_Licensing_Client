"""Tests for shared application services and capability registration."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from cisco_support_api_client import SmartAccount, VirtualAccount

from fdm_licensing.capabilities import CAPABILITIES, get_capability
from fdm_licensing.cli import _select_account, main as cli_main
from fdm_licensing.models import (
    CiscoCredentialsCommand,
    FdmBootstrapCommand,
    FdmConnectionCommand,
)
from fdm_licensing.services import (
    CiscoAccountService,
    CiscoAuthenticationService,
    CredentialService,
    FdmAuthenticationService,
    FdmCertificateService,
)


class ApplicationModelTests(unittest.TestCase):
    def test_capability_ids_and_page_keys_are_unique(self) -> None:
        self.assertEqual(len({item.id for item in CAPABILITIES}), len(CAPABILITIES))
        self.assertEqual(len({item.page_key for item in CAPABILITIES}), len(CAPABILITIES))
        self.assertEqual(get_capability("fdm.connection").page_key, "fdm")

    def test_cli_lists_registry_capabilities(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = cli_main(["capabilities"])
        self.assertEqual(result, 0)
        for capability in CAPABILITIES:
            self.assertIn(capability.id, output.getvalue())

    def test_commands_validate_gui_and_cli_input_at_creation(self) -> None:
        with self.assertRaises(ValueError):
            CiscoCredentialsCommand.from_untrusted("client\n", "secret")
        with self.assertRaises(ValueError):
            FdmBootstrapCommand.from_untrusted(
                host="https://device", port=443, certificate_store_dir="certificates"
            )
        command = FdmConnectionCommand.from_untrusted(
            host="FTD.EXAMPLE.COM",
            port=443,
            username="admin",
            password="secret",
            api_version="latest",
            certificate_store_dir="certificates",
        )
        self.assertEqual(command.host, "ftd.example.com")
        self.assertIsInstance(command.certificate_store_dir, Path)

    def test_cli_selection_auto_selects_one_and_matches_exact_identifiers(self) -> None:
        accounts = (
            SmartAccount("First", "first.example", "10"),
            SmartAccount("Second", "second.example", "20"),
        )
        selected = _select_account(
            accounts,
            "20",
            label="smart account",
            keys=lambda item: (item.domain, item.account_id, item.name),
            display=lambda item: item.name,
        )
        self.assertEqual(selected.name, "Second")
        self.assertIs(
            _select_account(
                accounts[:1], None, label="smart account",
                keys=lambda item: (item.domain,), display=lambda item: item.name,
            ),
            accounts[0],
        )

    def test_cli_requires_selection_for_multiple_noninteractive_results(self) -> None:
        accounts = (
            SmartAccount("First", "first.example", "10"),
            SmartAccount("Second", "second.example", "20"),
        )
        with patch("fdm_licensing.cli.sys.stdin.isatty", return_value=False):
            with self.assertRaisesRegex(ValueError, "--smart-account"):
                _select_account(
                    accounts, None, label="smart account",
                    keys=lambda item: (item.domain,), display=lambda item: item.name,
                )


class ApplicationServiceTests(unittest.TestCase):
    def test_account_service_closes_token_and_licensing_clients(self) -> None:
        manager = Mock()
        manager.get_cisco_credentials.return_value = SimpleNamespace(
            client_id="client-id", client_secret="client-secret"
        )
        tokens = Mock()
        licensing = Mock()
        licensing.list_smart_accounts.return_value = (
            SmartAccount("Example", "example.com", "10"),
        )
        service = CiscoAccountService(
            manager_factory=lambda: manager,
            token_client_factory=lambda **_kwargs: tokens,
            licensing_client_factory=lambda **_kwargs: licensing,
        )
        self.assertEqual(service.list_smart_accounts()[0].domain, "example.com")
        licensing.close.assert_called_once_with()
        tokens.close.assert_called_once_with()

    def test_credential_service_passes_validated_values_to_manager(self) -> None:
        manager = Mock()
        service = CredentialService(manager_factory=lambda: manager)
        command = CiscoCredentialsCommand.from_untrusted("client-id", "secret")
        result = service.store(command)
        manager.store_cisco_credentials.assert_called_once_with("client-id", "secret")
        self.assertNotIn("secret", result.message)

    def test_cisco_authentication_closes_client_and_returns_safe_metadata(self) -> None:
        manager = Mock()
        manager.get_cisco_credentials.return_value = SimpleNamespace(
            client_id="client-id", client_secret="client-secret"
        )
        client = Mock()
        client.authenticate.return_value = SimpleNamespace(
            token_type="Bearer", scope="scope", access_token="sensitive-token"
        )
        service = CiscoAuthenticationService(
            manager_factory=lambda: manager,
            client_factory=lambda **_kwargs: client,
        )
        result = service.validate()
        client.close.assert_called_once_with()
        self.assertNotIn("sensitive-token", result.message)
        self.assertNotIn("client-secret", result.message)

    def test_fdm_authentication_uses_context_manager_cleanup(self) -> None:
        context = MagicMock()
        context.__enter__.return_value.software_version = "7.6.2-329"
        client_factory = Mock(return_value=context)
        command = FdmConnectionCommand.from_untrusted(
            host="ftd.example.com",
            port=443,
            username="admin",
            password="secret",
            api_version="latest",
            certificate_store_dir="certificates",
        )
        result = FdmAuthenticationService(client_factory=client_factory).validate(command)
        context.__enter__.assert_called_once_with()
        context.__exit__.assert_called_once()
        self.assertIn("succeeded", result.message)
        self.assertIn("7.6.2-329", result.message)

    def test_certificate_service_uses_validated_command(self) -> None:
        bootstrap = Mock(return_value=Path("certificates/fdm-ca-bundle.pem"))
        command = FdmBootstrapCommand.from_untrusted(
            host="ftd.example.com", port=443, certificate_store_dir="certificates"
        )
        result = FdmCertificateService(bootstrap=bootstrap).bootstrap(command)
        bootstrap.assert_called_once_with(
            host="ftd.example.com",
            port=443,
            certificate_store_dir=command.certificate_store_dir,
        )
        self.assertIn("fingerprint", result.message)


if __name__ == "__main__":
    unittest.main()
