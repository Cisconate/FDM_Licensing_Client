"""Tests for shared application services and capability registration."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

from fdm_licensing.capabilities import CAPABILITIES, get_capability
from fdm_licensing.cli import main as cli_main
from fdm_licensing.models import (
    CiscoCredentialsCommand,
    FdmBootstrapCommand,
    FdmConnectionCommand,
)
from fdm_licensing.services import (
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


class ApplicationServiceTests(unittest.TestCase):
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
