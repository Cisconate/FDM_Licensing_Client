"""Tests for shared application services and capability registration."""

import io
import unittest
from threading import Barrier
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from cisco_support_api_client import (
    LicenseSummary,
    LicenseSummaryItem,
    SmartAccount,
    VirtualAccount,
)
from fdm_plr_client import PlrRequestCode

from fdm_licensing.capabilities import CAPABILITIES, get_capability
from fdm_licensing.cli import (
    _cisco_credentials,
    _confirmed,
    _select_account,
    _with_certificate_recovery,
    main as cli_main,
)
from fdm_client import FDMAuthenticationError, FDMClient, FDMRequestError
from fdm_compatibility import FTD_7_6_PROFILE
from key_manager import CredentialsNotFoundError
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
from fdm_licensing.plr_workflow import (
    AuthorizationHandoff,
    FdmPlrState,
    UniversalPlrWorkflowService,
)
from fdm_licensing.gui.pages import _prompt_cisco_credentials
from PySide6.QtWidgets import QMessageBox


class ApplicationModelTests(unittest.TestCase):
    def test_cli_retries_once_after_confirmed_tls_certificate_recovery(self) -> None:
        command = FdmConnectionCommand.from_untrusted(
            host="fdm.example.com", port=443, username="admin", password="secret",
            api_version="latest", certificate_store_dir="certificates",
        )
        operation = Mock(
            side_effect=[FDMAuthenticationError("TLS validation failed"), "ready"]
        )
        with patch("fdm_licensing.cli._bootstrap_fdm_certificate") as bootstrap:
            self.assertEqual(
                _with_certificate_recovery(command, operation), "ready"
            )
        bootstrap.assert_called_once_with(command)
        self.assertEqual(operation.call_count, 2)

    def test_cli_plr_run_reserves_then_installs_returned_code(self) -> None:
        command = FdmConnectionCommand.from_untrusted(
            host="fdm.example.com", port=443, username="admin", password="secret",
            api_version="latest", certificate_store_dir="certificates",
        )
        workflow = Mock()
        workflow.inspect_fdm.return_value = SimpleNamespace(
            state=FdmPlrState.REQUEST_CODE_AVAILABLE,
            request_codes=(SimpleNamespace(code="DC-ZCSF-220:device-nonce-02"),),
        )
        workflow.preflight.return_value = SimpleNamespace(
            may_reserve=True,
            identity=SimpleNamespace(product_id="CSF-220"),
        )
        workflow.license_summary.return_value = SimpleNamespace(items=())
        workflow.reservation_preview.return_value = (
            SimpleNamespace(items=()), workflow.preflight.return_value
        )
        workflow.compatible_licenses.return_value = ()
        workflow.reserve.return_value = AuthorizationHandoff(
            "ABC123-ABC123-ABC123-ABC123-ABC123-ABC123",
            "DC-ZCSF-220:device-nonce-02",
            "SUCCESS",
        )
        accounts = Mock()
        accounts.list_smart_accounts.return_value = (
            SmartAccount("Example", "example.com", "10"),
        )
        accounts.list_virtual_accounts.return_value = (
            VirtualAccount("Default", "20", True),
        )
        workflow.list_smart_accounts.return_value = accounts.list_smart_accounts.return_value
        workflow.list_virtual_accounts.return_value = accounts.list_virtual_accounts.return_value
        with patch("fdm_licensing.cli._fdm_command", return_value=command), patch(
            "fdm_licensing.cli._ensure_fdm_certificate"
        ), patch("fdm_licensing.cli._cisco_credentials"), patch(
            "fdm_licensing.cli.CiscoAccountService", return_value=accounts
        ), patch(
            "fdm_licensing.cli.UniversalPlrWorkflowService", return_value=workflow
        ), patch("fdm_licensing.cli._confirmed", return_value=True), redirect_stdout(
            io.StringIO()
        ):
            result = cli_main(["plr", "run", "--host", "fdm.example.com"])
        self.assertEqual(result, 0)
        workflow.reserve.assert_called_once()
        workflow.install.assert_called_once_with(
            command, "ABC123-ABC123-ABC123-ABC123-ABC123-ABC123"
        )

    def test_cli_missing_credentials_can_be_used_for_session_only(self) -> None:
        manager = Mock()
        manager.get_cisco_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.cli.KeyManager", return_value=manager), patch(
            "fdm_licensing.cli.sys.stdin.isatty", return_value=True
        ), patch("fdm_licensing.cli.input", side_effect=["client-id", "n"]), patch(
            "fdm_licensing.cli.getpass.getpass", return_value="client-secret"
        ), redirect_stdout(io.StringIO()):
            credentials = _cisco_credentials()
        self.assertEqual(credentials.client_id, "client-id")
        self.assertEqual(credentials.client_secret, "client-secret")
        manager.store_cisco_credentials.assert_not_called()

    def test_cli_missing_credentials_can_be_saved_to_os_vault(self) -> None:
        manager = Mock()
        manager.get_cisco_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.cli.KeyManager", return_value=manager), patch(
            "fdm_licensing.cli.sys.stdin.isatty", return_value=True
        ), patch("fdm_licensing.cli.input", side_effect=["client-id", "yes"]), patch(
            "fdm_licensing.cli.getpass.getpass", return_value="client-secret"
        ), redirect_stdout(io.StringIO()):
            _cisco_credentials()
        manager.store_cisco_credentials.assert_called_once_with(
            "client-id", "client-secret"
        )

    def test_gui_missing_credentials_can_be_used_for_session_only(self) -> None:
        manager = Mock()
        manager.get_cisco_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager), patch(
            "fdm_licensing.gui.pages.QInputDialog.getText",
            side_effect=[("client-id", True), ("client-secret", True)],
        ), patch(
            "fdm_licensing.gui.pages.QMessageBox.question",
            return_value=QMessageBox.StandardButton.No,
        ):
            credentials = _prompt_cisco_credentials(Mock())
        self.assertEqual(credentials.client_id, "client-id")
        manager.store_cisco_credentials.assert_not_called()

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

    def test_cli_interactive_selection_accepts_exact_name(self) -> None:
        accounts = (
            SmartAccount("First Account", "first.example", "10"),
            SmartAccount("Second Account", "second.example", "20"),
        )
        with patch("fdm_licensing.cli.sys.stdin.isatty", return_value=True), patch(
            "fdm_licensing.cli.input", return_value="Second Account"
        ), redirect_stdout(io.StringIO()):
            selected = _select_account(
                accounts, None, label="smart account",
                keys=lambda item: (item.domain, item.account_id, item.name),
                display=lambda item: item.name,
            )
        self.assertEqual(selected.account_id, "20")

    def test_supplied_numeric_selection_uses_displayed_index(self) -> None:
        accounts = (
            SmartAccount("First", "first.example", "10"),
            SmartAccount("Second", "second.example", "20"),
        )
        selected = _select_account(
            accounts, "2", label="smart account",
            keys=lambda item: (item.domain, item.account_id, item.name),
            display=lambda item: item.name,
        )
        self.assertEqual(selected.name, "Second")

    def test_unattended_confirmation_emits_notification_without_input(self) -> None:
        output = io.StringIO()
        with patch("fdm_licensing.cli.input") as prompt, redirect_stdout(output):
            self.assertTrue(_confirmed(
                "Remove device?", unattended=True,
                notification="Removing device",
            ))
        prompt.assert_not_called()
        self.assertEqual(output.getvalue().strip(), "Removing device")

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
    def test_workflow_reuses_and_closes_one_authenticated_fdm_session(self) -> None:
        fdm = object.__new__(FDMClient)
        fdm.require_api_profile = Mock(return_value=FTD_7_6_PROFILE)
        fdm.get_json = Mock(return_value={"items": []})
        fdm.close = Mock()
        factory = Mock(return_value=fdm)
        service = UniversalPlrWorkflowService(fdm_factory=factory)
        command = FdmConnectionCommand.from_untrusted(
            host="fdm.example.com", port=443, username="admin", password="secret",
            api_version="latest", certificate_store_dir="certificates",
        )
        with patch.object(FDMClient, "__enter__", return_value=fdm) as enter:
            service.start_reuse()
            service.inspect_fdm(command)
            service.inspect_fdm(command)
            service.close()
        factory.assert_called_once()
        enter.assert_called_once()
        fdm.close.assert_called_once()

    def test_workflow_reuses_and_closes_one_cisco_session_and_caches_accounts(self) -> None:
        tokens = Mock()
        licensing = Mock()
        smart = (SmartAccount("Example", "example.com", "10"),)
        licensing.list_smart_accounts.return_value = smart
        licensing.list_virtual_accounts.return_value = (
            VirtualAccount("Default", "20", True),
        )
        token_factory = Mock(return_value=tokens)
        licensing_factory = Mock(return_value=licensing)
        service = UniversalPlrWorkflowService(
            credentials=SimpleNamespace(client_id="id", client_secret="secret"),
            token_client_factory=token_factory,
            licensing_client_factory=licensing_factory,
        )
        service.start_reuse()
        self.assertEqual(service.list_smart_accounts(), smart)
        self.assertEqual(service.list_smart_accounts(), smart)
        service.list_virtual_accounts(smart[0])
        service.list_virtual_accounts(smart[0])
        service.close()
        token_factory.assert_called_once()
        licensing_factory.assert_called_once()
        licensing.list_smart_accounts.assert_called_once()
        licensing.list_virtual_accounts.assert_called_once()
        licensing.close.assert_called_once()
        tokens.close.assert_called_once()

    def test_reservation_preview_runs_independent_reads_concurrently(self) -> None:
        barrier = Barrier(2)
        licensing = Mock()
        summary = SimpleNamespace(items=())
        preflight = SimpleNamespace(may_reserve=True)
        licensing.get_license_summary.side_effect = lambda _selection: (
            barrier.wait(timeout=1), summary
        )[1]
        licensing.preflight_universal_plr.side_effect = lambda _selection, _code: (
            barrier.wait(timeout=1), preflight
        )[1]
        service = UniversalPlrWorkflowService(
            credentials=SimpleNamespace(client_id="id", client_secret="secret"),
            token_client_factory=Mock(return_value=Mock()),
            licensing_client_factory=Mock(return_value=licensing),
        )
        selection = SimpleNamespace()
        self.assertEqual(
            service.reservation_preview(selection, "request-code"),
            (summary, preflight),
        )

    def test_fpr_1010_maps_only_to_fpr_1000_threat_defense_ulr(self) -> None:
        def item(tag: str, name: str) -> LicenseSummaryItem:
            return LicenseSummaryItem(
                tag=tag, entitled=4, future_entitled=0, in_use=0, reserved=0,
                compliance_status="IN_COMPLIANCE", display_name=name,
                enforced=True, export_restricted=False, license_details=(),
            )
        expected = item(
            "regid.example.com.cisco.FPR1K-TD-ULR,1.0_id",
            "Cisco Firepower 1000 Threat Defense Universal License",
        )
        unrelated = item("regid.example.FPR3105TD-TP,1.0_id", "FPR3105 Threat")
        result = UniversalPlrWorkflowService.compatible_licenses(
            "FPR-1010", LicenseSummary("Retrieved", 0, (expected, unrelated))
        )
        self.assertEqual(result, (expected,))
    def test_plr_readiness_polling_tolerates_expected_convergence_error(self) -> None:
        service = UniversalPlrWorkflowService(
            readiness_timeout=5, poll_interval=1
        )
        plr = Mock()
        plr.list_smart_agent_connections.return_value = (
            {"connectionType": "UNIVERSAL_PLR"},
        )
        code = PlrRequestCode("DC-ZCSF-220:device-nonce-02")
        plr.list_plr_request_codes.side_effect = [
            FDMRequestError("HTTP 400 unableToGeneratePLRRequestCode"),
            (code,),
        ]
        with patch("fdm_licensing.plr_workflow.time.monotonic", side_effect=[0, 0, 1]), patch(
            "fdm_licensing.plr_workflow.time.sleep"
        ) as sleep:
            result = service._wait_for_request_code(plr)
        self.assertEqual(result.request_codes, (code,))
        sleep.assert_called_once_with(1)

    def test_plr_inspection_classifies_only_unambiguous_states(self) -> None:
        inspect = UniversalPlrWorkflowService._inspection
        self.assertEqual(inspect((), ()).state, FdmPlrState.NOT_CONFIGURED)
        self.assertEqual(
            inspect(({"connectionType": "UNIVERSAL_PLR"},), ()).state,
            FdmPlrState.UNIVERSAL_CONFIGURED,
        )
        self.assertEqual(
            inspect(
                ({"connectionType": "UNIVERSAL_PLR"},),
                (PlrRequestCode("DC-ZCSF-220:device-nonce-02"),),
            ).state,
            FdmPlrState.REQUEST_CODE_AVAILABLE,
        )
        self.assertEqual(
            inspect(({"connectionType": "OTHER"},), ()).state,
            FdmPlrState.OTHER_CONFIGURED,
        )
        self.assertFalse(
            UniversalPlrWorkflowService._request_codes_applicable(
                ({"connectionType": "OTHER"},)
            )
        )
        self.assertTrue(
            UniversalPlrWorkflowService._request_codes_applicable(
                ({"connectionType": "UNIVERSAL_PLR"},)
            )
        )

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
        result = FdmCertificateService(
            bootstrap=bootstrap, fingerprint=lambda _path: "AA:BB"
        ).bootstrap(command)
        bootstrap.assert_called_once_with(
            host="ftd.example.com",
            port=443,
            certificate_store_dir=command.certificate_store_dir,
        )
        self.assertIn("fingerprint", result.message)
        self.assertIn("AA:BB", result.message)


if __name__ == "__main__":
    unittest.main()
