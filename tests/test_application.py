"""Tests for shared application services and capability registration."""

import io
import os
import threading
import unittest
from threading import Barrier
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from cisco_support_api_client import (
    LicenseSummary,
    LicenseSummaryItem,
    SmartAccount,
    VirtualAccount,
)
from fdm_plr_client import PlrRequestCode

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from fdm_licensing.capabilities import (
    CAPABILITIES,
    FTD_LICENSING_OPERATIONS,
    get_capability,
)
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
    FdmCredentialsCommand,
)
from fdm_licensing.services import (
    CiscoAccountService,
    CiscoAuthenticationService,
    CredentialService,
    FdmCredentialService,
    FdmAuthenticationService,
    FdmCertificateService,
)
from fdm_licensing.plr_workflow import (
    AuthorizationHandoff,
    FdmPlrState,
    UniversalPlrWorkflowService,
)
from fdm_licensing.gui.app import APPLICATION_STYLESHEET
from fdm_licensing.gui.pages import (
    CapabilityPage,
    CredentialPage,
    FdmConnectionPage,
    WorkflowPage,
    _prompt_cisco_credentials,
    _save_code_file,
)
from fdm_licensing.gui.progress import ActivityPanel
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox


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

    def test_workflow_operation_registry_has_unique_renderable_actions(self) -> None:
        self.assertEqual(
            len({item.id for item in FTD_LICENSING_OPERATIONS}),
            len(FTD_LICENSING_OPERATIONS),
        )
        self.assertEqual(
            {item.id for item in FTD_LICENSING_OPERATIONS},
            {"bootstrap", "inspect", "request_code", "reserve", "install", "return"},
        )
        self.assertEqual(
            next(
                item.title
                for item in FTD_LICENSING_OPERATIONS
                if item.id == "request_code"
            ),
            "Configure PLR",
        )
        for operation in FTD_LICENSING_OPERATIONS:
            self.assertTrue(hasattr(WorkflowPage, operation.handler))

    def test_gui_styles_define_readable_light_control_foreground(self) -> None:
        self.assertIn("QLineEdit, QSpinBox, QListWidget", APPLICATION_STYLESHEET)
        self.assertIn("background: white; color: #172235", APPLICATION_STYLESHEET)
        self.assertIn("QWidget { color: #172235; }", APPLICATION_STYLESHEET)
        self.assertIn('QPushButton[workflowAction="true"]:enabled', APPLICATION_STYLESHEET)
        self.assertIn("background: #c9f2cf", APPLICATION_STYLESHEET)
        self.assertIn('QPushButton[workflowAction="true"]:disabled', APPLICATION_STYLESHEET)
        self.assertIn("color: #c7cdd4", APPLICATION_STYLESHEET)
        self.assertIn('QLineEdit[credentialState="missing"]', APPLICATION_STYLESHEET)
        self.assertIn("border: 1px solid #d32f2f", APPLICATION_STYLESHEET)

    def test_workflow_page_hydrates_stored_fdm_identity_and_stages_actions(self) -> None:
        QApplication.instance() or QApplication([])
        stored = SimpleNamespace(
            host="fdm.example.com", port=8443, username="operator", password="secret"
        )
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=1, only_host="fdm.example.com"
        )
        manager.get_fdm_credentials.return_value = stored
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager), patch(
            "fdm_licensing.gui.pages.certificate_bundle_path"
        ) as bundle_path:
            bundle_path.return_value.is_file.return_value = False
            page = WorkflowPage()
        self.assertEqual(page._host.text(), "fdm.example.com")
        self.assertEqual(page._port.value(), 8443)
        self.assertEqual(page._username.text(), "")
        self.assertEqual(page._password.text(), "")
        self.assertEqual(page._host.property("credentialState"), "keychain")
        self.assertEqual(page._username.placeholderText(), "Using Keychain")
        self.assertEqual(page._password.placeholderText(), "Using Keychain")
        self.assertEqual(page._host.property("credentialState"), "keychain")
        self.assertTrue(page._operation_buttons["bootstrap"].isEnabled())
        self.assertTrue(page._operation_buttons["inspect"].isEnabled())
        self.assertFalse(page._operation_buttons["request_code"].isEnabled())
        self.assertFalse(page._operation_buttons["reserve"].isEnabled())
        self.assertFalse(page._operation_buttons["install"].isEnabled())
        for button in page._operation_buttons.values():
            self.assertTrue(button.property("workflowAction"))
        self.assertEqual(
            page._authorization.placeholderText(),
            "Authorization or Return code (generated or pasted)",
        )
        page._workflow.close()

    def test_workflow_marks_missing_credentials_red_and_clears_error_on_input(self) -> None:
        QApplication.instance() or QApplication([])
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=0, only_host=None
        )
        manager.get_fdm_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()
        for field in (page._host, page._username, page._password):
            self.assertEqual(field.property("credentialState"), "missing")
            self.assertEqual(field.placeholderText(), "Required")
        page._username.setText("operator")
        page._username.textEdited.emit("operator")
        self.assertEqual(page._username.property("credentialState"), "provided")
        self.assertEqual(page._username.placeholderText(), "")
        page._username.clear()
        page._username.textEdited.emit("")
        self.assertEqual(page._username.property("credentialState"), "missing")
        page._workflow.close()

    def test_multiple_hosts_stay_unlisted_and_exact_typed_host_keeps_password(self) -> None:
        QApplication.instance() or QApplication([])
        selected = SimpleNamespace(
            host="192.168.223.22", port=443,
            username="operator", password="secret",
        )
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=2000, only_host=None
        )
        manager.get_fdm_credentials.return_value = selected
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()
            self.assertEqual(page._host.text(), "")
            self.assertIn("Multiple FDM records", page._credential_status.text())
            page._host.setText("192.168.223.22")
            page._host.textEdited.emit("192.168.223.22")
            page._lookup_typed_host()
        manager.get_fdm_credentials.assert_called_with(host="192.168.223.22")
        self.assertEqual(page._password.placeholderText(), "Using Keychain")
        self.assertEqual(page._password.property("credentialState"), "keychain")
        self.assertEqual(page._username.placeholderText(), "Using Keychain")
        page._workflow.close()

    def test_gui_exposes_default_fdm_credential_management(self) -> None:
        QApplication.instance() or QApplication([])
        page = CredentialPage()
        self.assertEqual(page._fdm_username.text(), "")
        self.assertEqual(page._fdm_port.value(), 443)
        self.assertEqual(page._fdm_password.echoMode(), page._fdm_password.EchoMode.Password)
        page._fdm_host.setText("fdm.example.com")
        page._fdm_username.setText("operator")
        page._fdm_password.setText("secret")
        page._fdm_service = Mock()
        page._fdm_service.store.return_value = SimpleNamespace(message="stored")
        changed = Mock()
        page.fdm_credentials_changed.connect(changed)
        page._store_fdm()
        command = page._fdm_service.store.call_args.args[0]
        self.assertEqual(command.host, "fdm.example.com")
        self.assertEqual(command.username, "operator")
        self.assertEqual(page._fdm_password.text(), "")
        changed.assert_called_once_with()

    def test_fdm_connection_page_has_no_admin_default_and_uses_vault_placeholders(self) -> None:
        QApplication.instance() or QApplication([])
        stored = SimpleNamespace(
            host="fdm.example.com", port=8443,
            username="operator", password="secret",
        )
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=1, only_host="stored.example.com"
        )
        manager.get_fdm_credentials.return_value = stored
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = FdmConnectionPage()
        self.assertEqual(page._host.text(), "")
        self.assertEqual(page._username.text(), "")
        self.assertEqual(page._password.text(), "")
        self.assertEqual(page._port.value(), 8443)
        for field in (page._host, page._username, page._password):
            self.assertEqual(field.placeholderText(), "Using Keychain")
            self.assertEqual(field.property("credentialState"), "keychain")

    def test_workflow_user_fields_override_vault_and_clear_back_to_vault(self) -> None:
        QApplication.instance() or QApplication([])
        stored = SimpleNamespace(
            host="stored.example.com", port=443,
            username="stored-user", password="stored-password",
        )
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=1, only_host="stored.example.com"
        )
        manager.get_fdm_credentials.return_value = stored
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()

            page._host.setText("override.example.com")
            page._host.textEdited.emit("override.example.com")
            page._port.setValue(8443)
            page._port.lineEdit().textEdited.emit("8443")
            page._username.setText("override-user")
            page._username.textEdited.emit("override-user")
            page._password.setText("override-password")
            page._password.textEdited.emit("override-password")
            overridden = page._connection_command()
            self.assertEqual(overridden.host, "override.example.com")
            self.assertEqual(overridden.port, 8443)
            self.assertEqual(overridden.username, "override-user")
            self.assertEqual(overridden.password, "override-password")

            page._host.setText("")
            page._host.textEdited.emit("")
            page._port.lineEdit().clear()
            page._port.lineEdit().textEdited.emit("")
            page._username.setText("")
            page._username.textEdited.emit("")
            page._password.setText("")
            page._password.textEdited.emit("")
            restored = page._connection_command()
        self.assertEqual(restored.host, "stored.example.com")
        self.assertEqual(restored.port, 443)
        self.assertEqual(restored.username, "stored-user")
        self.assertEqual(restored.password, "stored-password")
        page._workflow.close()

    def test_handoff_code_can_be_copied_without_exposing_it_in_status(self) -> None:
        QApplication.instance() or QApplication([])
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=0, only_host=None
        )
        manager.get_fdm_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()
        page._authorization.setText("sensitive-handoff-code")
        clipboard = Mock()
        with patch(
            "fdm_licensing.gui.pages.QApplication.clipboard", return_value=clipboard
        ):
            page._copy_code()
        clipboard.setText.assert_called_once_with("sensitive-handoff-code")
        self.assertNotIn("sensitive-handoff-code", page._status.text())
        self.assertTrue(page._copy_code_button.isEnabled())
        self.assertTrue(page._save_code_button.isEnabled())
        page._workflow.close()

    def test_handoff_code_file_is_written_atomically(self) -> None:
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "return-code.txt"
            result = _save_code_file(str(destination), "return-code")
            self.assertEqual(result, destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), "return-code\n")
            self.assertFalse(tuple(destination.parent.glob(".return-code.txt.*.tmp")))
            if os.name != "nt":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_generated_return_code_waits_for_explicit_submit_button(self) -> None:
        QApplication.instance() or QApplication([])
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=0, only_host=None
        )
        manager.get_fdm_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()
        handoff = SimpleNamespace(
            return_code="return-code", instance=SimpleNamespace(product_id="FPR-1010")
        )
        with patch("fdm_licensing.gui.pages.QMessageBox.question") as question:
            page._return_generated(page._operation_buttons["return"], handoff)
        question.assert_not_called()
        self.assertIs(page._return_handoff, handoff)
        self.assertEqual(page._authorization.text(), "return-code")
        self.assertEqual(page._code_action_button.text(), "Submit Return Code")
        self.assertTrue(page._copy_code_button.isEnabled())
        self.assertTrue(page._save_code_button.isEnabled())
        self.assertIn("Copy or save it now", page._status.text())
        page._workflow.close()

    def test_request_code_result_unlocks_reservation_without_starting_it(self) -> None:
        QApplication.instance() or QApplication([])
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=0, only_host=None
        )
        manager.get_fdm_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()
        page._command = object()
        page._request_code_generated(
            page._operation_buttons["request_code"],
            SimpleNamespace(request_codes=(SimpleNamespace(code="request-code"),)),
        )
        self.assertEqual(page._request_code, "request-code")
        self.assertTrue(page._operation_buttons["reserve"].isEnabled())
        self.assertIn("Select an account", page._status.text())
        page._workflow.close()

    def test_generate_request_code_requires_mutation_confirmation(self) -> None:
        QApplication.instance() or QApplication([])
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=0, only_host=None
        )
        manager.get_fdm_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()
        page._command = object()
        with patch(
            "fdm_licensing.gui.pages.QMessageBox.question",
            return_value=QMessageBox.StandardButton.No,
        ), patch("fdm_licensing.gui.pages.QThreadPool.globalInstance") as pool:
            page._generate_request_code(page._operation_buttons["request_code"])
        pool.assert_not_called()
        self.assertIn("cancelled", page._status.text())
        page._workflow.close()

    def test_background_completion_is_marshaled_to_gui_thread(self) -> None:
        QApplication.instance() or QApplication([])
        page = CapabilityPage("Test", "Test")
        loop = QEventLoop()
        main_thread = threading.get_ident()
        observed: dict[str, int] = {}

        def operation() -> str:
            observed["worker"] = threading.get_ident()
            return "ready"

        def succeeded(_result: object) -> None:
            observed["callback"] = threading.get_ident()
            QTimer.singleShot(0, loop.quit)

        page._start_background(
            operation,
            succeeded,
            self.fail,
            activity_title="Testing background work",
            timeout_seconds=10,
        )
        QTimer.singleShot(2000, loop.quit)
        loop.exec()
        QApplication.processEvents()
        self.assertNotEqual(observed["worker"], main_thread)
        self.assertEqual(observed["callback"], main_thread)
        self.assertFalse(page._active_jobs)
        self.assertEqual(page._activity._title.text(), "Testing background work")
        self.assertIn("Completed after", page._activity._detail.text())
        self.assertFalse(page._activity.active)

    def test_activity_panel_animates_and_reports_timeout_window(self) -> None:
        QApplication.instance() or QApplication([])
        panel = ActivityPanel()
        with patch("fdm_licensing.gui.progress.time.monotonic", return_value=100.0):
            panel.start("Generating request code", timeout_seconds=60)
        self.assertFalse(panel.isHidden())
        self.assertTrue(panel.active)
        self.assertEqual((panel._bar.minimum(), panel._bar.maximum()), (0, 0))
        panel._refresh(now=118.5)
        self.assertIn("18.5s elapsed", panel._detail.text())
        self.assertIn("41.5s remaining", panel._detail.text())
        with patch("fdm_licensing.gui.progress.time.monotonic", return_value=120.0):
            panel.succeed()
        self.assertFalse(panel.active)
        self.assertEqual(panel._bar.value(), 100)
        self.assertEqual(panel.property("activityState"), "success")

    def test_activity_panel_failure_is_durable_and_stops_animation(self) -> None:
        QApplication.instance() or QApplication([])
        panel = ActivityPanel()
        with patch("fdm_licensing.gui.progress.time.monotonic", side_effect=[10.0, 10.0, 12.0]):
            panel.start("Fetching accounts")
            panel.fail()
        self.assertFalse(panel.active)
        self.assertIn("Failed after 2.0s", panel._detail.text())
        self.assertEqual(panel.property("activityState"), "failure")

    def test_certificate_confirmation_reports_yes_and_no_outcomes(self) -> None:
        QApplication.instance() or QApplication([])
        manager = Mock()
        manager.fdm_credential_summary.return_value = SimpleNamespace(
            count=0, only_host=None
        )
        manager.get_fdm_credentials.side_effect = CredentialsNotFoundError("missing")
        with patch("fdm_licensing.gui.pages.KeyManager", return_value=manager):
            page = WorkflowPage()
        button = page._operation_buttons["bootstrap"]
        result = SimpleNamespace(message="Certificate saved. Fingerprint AA:BB.")
        with patch(
            "fdm_licensing.gui.pages.QMessageBox.question",
            return_value=QMessageBox.StandardButton.No,
        ):
            page._confirm_explicit_bootstrap(button, result)
        self.assertIn("not confirmed", page._status.text())
        with patch(
            "fdm_licensing.gui.pages.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ), patch.object(page, "_update_certificate_status") as update:
            page._confirm_explicit_bootstrap(button, result)
        update.assert_called_once_with()
        self.assertIn("trust is ready", page._status.text())
        self.assertTrue(button.isEnabled())
        page._workflow.close()

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
    def test_fdm_credential_service_stores_status_and_deletes_without_values(self) -> None:
        manager = Mock()
        manager.fdm_credential_status.return_value = SimpleNamespace(complete=True)
        service = FdmCredentialService(manager_factory=lambda: manager)
        command = FdmCredentialsCommand.from_untrusted(
            host="fdm.example.com", port=443,
            username="operator", password="secret",
        )
        stored = service.store(command)
        manager.store_fdm_credentials.assert_called_once_with(
            host="fdm.example.com", port=443,
            username="operator", password="secret",
        )
        self.assertNotIn("secret", stored.message)
        self.assertIn("complete", service.status().message)
        service.delete()
        manager.delete_fdm_credentials.assert_called_once_with()
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
