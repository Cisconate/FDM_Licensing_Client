"""Capability pages for the desktop application."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QThreadPool, QTimer
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from fdm_licensing.models import (
    CiscoCredentialsCommand,
    FdmBootstrapCommand,
    FdmConnectionCommand,
    OperationResult,
)
from cisco_support_api_client import AccountSelection
from fdm_certificate_store import certificate_bundle_path
from key_manager import CiscoClientCredentials, CredentialsNotFoundError, KeyManager
from fdm_licensing.plr_workflow import (
    FdmPlrState,
    UniversalPlrWorkflowService,
)
from fdm_licensing.services import (
    CiscoAccountService,
    CiscoAuthenticationService,
    CredentialService,
    FdmAuthenticationService,
    FdmCertificateService,
)

from .workers import ServiceWorker


def _prompt_cisco_credentials(parent: QWidget) -> CiscoClientCredentials | None:
    """Return stored credentials or offer session-only/OS-vault use when absent."""
    manager = KeyManager()
    try:
        return manager.get_cisco_credentials()
    except CredentialsNotFoundError:
        client_id, accepted = QInputDialog.getText(
            parent, "Cisco credentials", "Cisco Client ID"
        )
        if not accepted:
            return None
        secret, accepted = QInputDialog.getText(
            parent,
            "Cisco credentials",
            "Cisco Client Secret",
            QLineEdit.EchoMode.Password,
        )
        if not accepted:
            return None
        command = CiscoCredentialsCommand.from_untrusted(client_id, secret)
        choice = QMessageBox.question(
            parent,
            "Credential storage",
            "Save these credentials in the operating-system vault?\n\n"
            "Choose No to use them for this application session only.",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No
            | QMessageBox.StandardButton.Cancel,
        )
        if choice == QMessageBox.StandardButton.Cancel:
            return None
        if choice == QMessageBox.StandardButton.Yes:
            manager.store_cisco_credentials(command.client_id, command.client_secret)
        return CiscoClientCredentials(command.client_id, command.client_secret)


class CapabilityPage(QWidget):
    def __init__(self, title: str, description: str) -> None:
        super().__init__()
        self._layout = QVBoxLayout(self)
        heading = QLabel(title)
        heading.setObjectName("pageHeading")
        self._layout.addWidget(heading)
        summary = QLabel(description)
        summary.setWordWrap(True)
        summary.setObjectName("pageSummary")
        self._layout.addWidget(summary)
        self._status = QLabel("")
        self._status.setWordWrap(True)

    def _complete_layout(self) -> None:
        self._layout.addStretch()
        self._layout.addWidget(self._status)

    def _show_result(self, result: OperationResult) -> None:
        self._status.setText(result.message)

    def _show_error(self, message: str) -> None:
        self._status.setText(f"Operation failed: {message}")

    def _run(self, button: QPushButton, operation: Callable[[], OperationResult]) -> None:
        button.setEnabled(False)
        self._status.setText("Working…")
        worker = ServiceWorker(operation)
        worker.signals.succeeded.connect(self._show_result)
        worker.signals.failed.connect(self._show_error)
        worker.signals.succeeded.connect(lambda _result: button.setEnabled(True))
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)


class _SearchableSelectionDialog(QDialog):
    """Debounced account selector suitable for large account collections."""

    def __init__(self, parent, title: str, label: str, values: tuple, display) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self._values = values
        self._display = display
        self._visible_values = list(values)
        self._search = QLineEdit()
        self._search.setPlaceholderText(f"Type to filter {label.lower()}s")
        self._list = QListWidget()
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        layout = QVBoxLayout(self)
        layout.addWidget(self._search)
        layout.addWidget(self._list)
        layout.addWidget(buttons)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._apply_filter)
        self._search.textChanged.connect(lambda _text: self._timer.start())
        self._list.itemDoubleClicked.connect(lambda _item: self.accept())
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self._apply_filter()

    def _apply_filter(self) -> None:
        query = self._search.text().strip().casefold()
        self._visible_values = [
            value for value in self._values
            if query in self._display(value).casefold()
        ]
        self._list.clear()
        self._list.addItems([self._display(value) for value in self._visible_values])
        if self._visible_values:
            self._list.setCurrentRow(0)

    def selected_value(self):
        row = self._list.currentRow()
        return self._visible_values[row] if 0 <= row < len(self._visible_values) else None


class WorkflowPage(CapabilityPage):
    def __init__(self) -> None:
        super().__init__(
            "FTD Licensing Workflow",
            "The application is organized around the complete device-to-Cisco-to-device licensing flow.",
        )
        self._workflow = UniversalPlrWorkflowService()
        self._workflow.start_reuse()
        self.destroyed.connect(lambda _object=None: self._workflow.close())
        self._command = None
        self._request_code = None
        self._selection = None
        self._account_action = "reserve"

        self._host = QLineEdit()
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._username = QLineEdit("admin")
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_version = QLineEdit("latest")
        self._certificate_dir = QLineEdit("certificates")
        form = QFormLayout()
        form.addRow("Host", self._host)
        form.addRow("Port", self._port)
        form.addRow("Username", self._username)
        form.addRow("Password", self._password)
        form.addRow("API version", self._api_version)
        form.addRow("Certificate directory", self._certificate_dir)
        self._layout.addLayout(form)

        controls = QHBoxLayout()
        inspect = QPushButton("1. Inspect FDM")
        reserve = QPushButton("2. Select account and reserve")
        return_plr = QPushButton("Return PLR")
        controls.addWidget(inspect)
        controls.addWidget(reserve)
        controls.addWidget(return_plr)
        self._layout.addLayout(controls)
        inspect.clicked.connect(lambda: self._inspect(inspect))
        reserve.clicked.connect(lambda: self._start_reservation(reserve))
        return_plr.clicked.connect(lambda: self._start_return(return_plr))

        self._authorization = QLineEdit()
        self._authorization.setEchoMode(QLineEdit.EchoMode.Password)
        self._authorization.setPlaceholderText("Authorization code (returned or pasted)")
        install = QPushButton("3. Install on FDM")
        install.clicked.connect(lambda: self._install(install))
        install_row = QHBoxLayout()
        install_row.addWidget(self._authorization, 1)
        install_row.addWidget(install)
        self._layout.addLayout(install_row)
        self._complete_layout()

    def _connection_command(self) -> FdmConnectionCommand:
        try:
            stored = KeyManager().get_fdm_credentials()
        except CredentialsNotFoundError:
            stored = None
        host = self._host.text() or (stored.host if stored is not None else "")
        port = self._port.value()
        username = self._username.text()
        password = self._password.text()
        if (
            not password
            and stored is not None
            and stored.host == host
            and stored.port == port
            and stored.username == username
        ):
            password = stored.password
        command = FdmConnectionCommand.from_untrusted(
            host=host, port=port,
            username=username, password=password,
            api_version=self._api_version.text(),
            certificate_store_dir=self._certificate_dir.text(),
        )
        self._command = command
        self._password.clear()
        return command

    def _inspect(self, button: QPushButton) -> None:
        try:
            command = self._connection_command()
        except ValueError as exc:
            self._show_error(str(exc))
            return
        bundle = certificate_bundle_path(command.certificate_store_dir)
        if not bundle.is_file():
            answer = QMessageBox.question(
                self,
                "Trust FDM certificate",
                f"No trusted certificate bundle is available. Fetch the certificate "
                f"currently presented by {command.host}:{command.port}?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                self._status.setText("Certificate bootstrap cancelled.")
                return
            button.setEnabled(False)
            bootstrap = FdmBootstrapCommand.from_untrusted(
                host=command.host,
                port=command.port,
                certificate_store_dir=command.certificate_store_dir,
            )
            worker = ServiceWorker(lambda: FdmCertificateService().bootstrap(bootstrap))
            worker.signals.succeeded.connect(
                lambda value: self._confirm_bootstrap(button, command, value)
            )
            worker.signals.failed.connect(self._show_error)
            worker.signals.failed.connect(lambda _message: button.setEnabled(True))
            QThreadPool.globalInstance().start(worker)
            return
        self._run_inspection(button, command)

    def _confirm_bootstrap(
        self,
        button: QPushButton,
        command: FdmConnectionCommand,
        result: OperationResult,
    ) -> None:
        answer = QMessageBox.question(
            self,
            "Verify FDM certificate",
            f"{result.message}\n\nHave you verified this fingerprint through a "
            "trusted channel?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._status.setText("Certificate fingerprint was not confirmed.")
            button.setEnabled(True)
            return
        self._run_inspection(button, command)

    def _run_inspection(
        self, button: QPushButton, command: FdmConnectionCommand
    ) -> None:
        button.setEnabled(False)
        worker = ServiceWorker(lambda: self._workflow.inspect_fdm(command))
        worker.signals.succeeded.connect(lambda value: self._inspection_done(button, value))
        worker.signals.failed.connect(
            lambda message: self._inspection_failed(button, command, message)
        )
        QThreadPool.globalInstance().start(worker)

    def _inspection_failed(
        self, button: QPushButton, command: FdmConnectionCommand, message: str
    ) -> None:
        if "TLS validation failed" not in message:
            self._show_error(message)
            button.setEnabled(True)
            return
        answer = QMessageBox.question(
            self,
            "Refresh FDM certificate trust",
            "The existing certificate bundle did not validate this FDM endpoint. "
            "Fetch its currently presented certificate and verify the new fingerprint?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._show_error(message)
            button.setEnabled(True)
            return
        bootstrap = FdmBootstrapCommand.from_untrusted(
            host=command.host,
            port=command.port,
            certificate_store_dir=command.certificate_store_dir,
        )
        worker = ServiceWorker(lambda: FdmCertificateService().bootstrap(bootstrap))
        worker.signals.succeeded.connect(
            lambda value: self._confirm_bootstrap(button, command, value)
        )
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _inspection_done(self, button: QPushButton, inspection) -> None:
        button.setEnabled(True)
        if inspection.state is FdmPlrState.REQUEST_CODE_AVAILABLE:
            self._request_code = inspection.request_codes[0].code
        self._status.setText(f"FDM Universal PLR state: {inspection.state.value}.")

    def _start_reservation(self, button: QPushButton) -> None:
        self._account_action = "reserve"
        if self._command is None:
            self._show_error("Inspect FDM first")
            return
        if self._request_code is None:
            answer = QMessageBox.question(
                self, "Configure Universal PLR",
                "FDM does not have one request code. Configure Universal PLR now?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            button.setEnabled(False)
            worker = ServiceWorker(lambda: self._workflow.configure_universal_plr(self._command))
            worker.signals.succeeded.connect(lambda value: self._configured(button, value))
            worker.signals.failed.connect(self._show_error)
            worker.signals.failed.connect(lambda _message: button.setEnabled(True))
            QThreadPool.globalInstance().start(worker)
            return
        try:
            credentials = _prompt_cisco_credentials(self)
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))
            return
        if credentials is None:
            self._status.setText("Credential entry cancelled.")
            return
        self._workflow.close()
        self._workflow = UniversalPlrWorkflowService(credentials=credentials)
        self._workflow.start_reuse()
        self._discover_smart(button)

    def _start_return(self, button: QPushButton) -> None:
        if self._command is None:
            self._show_error("Inspect FDM first")
            return
        try:
            credentials = _prompt_cisco_credentials(self)
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))
            return
        if credentials is None:
            self._status.setText("Credential entry cancelled.")
            return
        self._account_action = "return"
        self._workflow.close()
        self._workflow = UniversalPlrWorkflowService(credentials=credentials)
        self._workflow.start_reuse()
        button.setEnabled(False)
        worker = ServiceWorker(lambda: self._workflow.locate_return(self._command))
        worker.signals.succeeded.connect(
            lambda location: self._return_location_done(button, location)
        )
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _return_location_done(self, button: QPushButton, location) -> None:
        self._selection = location.selection
        self._return_preflight_done(button, location.instance)

    def _configured(self, button: QPushButton, inspection) -> None:
        self._request_code = inspection.request_codes[0].code
        button.setEnabled(True)
        self._start_reservation(button)

    def _discover_smart(self, button: QPushButton) -> None:
        button.setEnabled(False)
        worker = ServiceWorker(self._workflow.list_smart_accounts)
        worker.signals.succeeded.connect(lambda values: self._choose_smart(button, values))
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _choose(self, title: str, label: str, values: tuple, display) -> object | None:
        if not values:
            self._show_error(f"No accessible {label.lower()}s were returned")
            return None
        if len(values) == 1:
            return values[0]
        dialog = _SearchableSelectionDialog(self, title, label, values, display)
        return (
            dialog.selected_value()
            if dialog.exec() == QDialog.DialogCode.Accepted
            else None
        )

    def _choose_smart(self, button: QPushButton, values: tuple) -> None:
        smart = self._choose(
            "Select smart account", "Smart account", values,
            lambda value: f"{value.name} ({value.domain})",
        )
        if smart is None:
            button.setEnabled(True)
            return
        worker = ServiceWorker(lambda: self._workflow.list_virtual_accounts(smart))
        worker.signals.succeeded.connect(
            lambda accounts: self._choose_virtual(button, smart, accounts)
        )
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _choose_virtual(self, button: QPushButton, smart, values: tuple) -> None:
        virtual = self._choose(
            "Select virtual account", "Virtual account", values,
            lambda value: value.name,
        )
        if virtual is None:
            button.setEnabled(True)
            return
        self._selection = AccountSelection(smart, virtual)
        if self._account_action == "return":
            worker = ServiceWorker(
                lambda: self._workflow.return_preflight(
                    self._command, self._selection
                )
            )
            worker.signals.succeeded.connect(
                lambda instance: self._return_preflight_done(button, instance)
            )
            worker.signals.failed.connect(self._show_error)
            worker.signals.failed.connect(lambda _message: button.setEnabled(True))
            QThreadPool.globalInstance().start(worker)
            return
        worker = ServiceWorker(
            lambda: self._workflow.reservation_preview(
                self._selection, self._request_code
            )
        )
        worker.signals.succeeded.connect(lambda value: self._preflight_done(button, value))
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _return_preflight_done(self, button: QPushButton, instance) -> None:
        answer = QMessageBox.question(
            self, "Return Universal PLR",
            f"Return PLR from FDM for {instance.product_id}/{instance.serial_number}? "
            "The return code must then be submitted to Cisco.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            button.setEnabled(True)
            return
        worker = ServiceWorker(
            lambda: self._workflow.generate_return(self._command, instance)
        )
        worker.signals.succeeded.connect(
            lambda handoff: self._return_generated(button, handoff)
        )
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _return_generated(self, button: QPushButton, handoff) -> None:
        self._authorization.setText(handoff.return_code)
        self._authorization.setEchoMode(QLineEdit.EchoMode.Normal)
        answer = QMessageBox.question(
            self, "Complete Cisco return",
            "FDM generated the return code shown in the workflow. Submit it to "
            "Cisco using the v3 product-instance removal API now?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            button.setEnabled(True)
            self._status.setText(
                "FDM return completed. Preserve the displayed code until Cisco completion."
            )
            return
        worker = ServiceWorker(
            lambda: self._workflow.complete_return(
                self._selection, handoff.instance, handoff.return_code
            )
        )
        worker.signals.succeeded.connect(lambda result: self._return_done(button, result))
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _return_done(self, button: QPushButton, result) -> None:
        answer = QMessageBox.question(
            self, "Complete FDM unregister",
            "Cisco accepted the return. Complete the final unregister on FDM?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            button.setEnabled(True)
            self._status.setText(
                "Cisco completed the return; final FDM unregister remains pending."
            )
            return
        worker = ServiceWorker(lambda: self._workflow.finalize_return(self._command))
        worker.signals.succeeded.connect(lambda _value: self._return_finalized(button, result))
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _return_finalized(self, button: QPushButton, result) -> None:
        button.setEnabled(True)
        self._authorization.clear()
        self._status.setText(
            f"Cisco completed the PLR return and FDM unregistered: {result.message}"
        )

    def _preflight_done(self, button: QPushButton, result) -> None:
        summary, preflight = result
        if not preflight.may_reserve:
            self._show_error(
                "Cisco already tracks this product instance. Retrieve its code in "
                "Cisco License Central or contact TAC for a poisoned product instance."
            )
            button.setEnabled(True)
            return
        answer = QMessageBox.question(
            self, "Reserve Universal PLR",
            self._reservation_inventory_message(summary, preflight.identity.product_id),
        )
        if answer != QMessageBox.StandardButton.Yes:
            button.setEnabled(True)
            return
        worker = ServiceWorker(
            lambda: self._workflow.reserve(self._selection, self._request_code)
        )
        worker.signals.succeeded.connect(lambda value: self._reservation_done(button, value))
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _reservation_inventory_message(self, summary, product_id: str) -> str:
        compatible = self._workflow.compatible_licenses(product_id, summary)
        if not compatible:
            return (
                f"No explicit license-summary mapping is defined for {product_id}. "
                "Cisco will validate compatibility during reservation. Continue?"
            )
        inventory = "\n".join(
            f"{item.display_name}: {item.available} available "
            f"({item.entitled} entitled, {item.in_use} in use)"
            for item in compatible
        )
        return f"Compatible Universal PLR inventory:\n\n{inventory}\n\nContinue?"

    def _reservation_done(self, button: QPushButton, handoff) -> None:
        button.setEnabled(True)
        self._authorization.setText(handoff.authorization_code)
        self._authorization.setEchoMode(QLineEdit.EchoMode.Normal)
        self._status.setText(
            "Reservation completed. Copy the authorization code or install it now."
        )

    def _install(self, button: QPushButton) -> None:
        if self._command is None:
            self._show_error("Inspect FDM first")
            return
        code = self._authorization.text()
        answer = QMessageBox.question(
            self, "Install authorization", "Install this authorization code on FDM?"
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        button.setEnabled(False)
        worker = ServiceWorker(lambda: self._workflow.install(self._command, code))
        worker.signals.succeeded.connect(lambda _value: self._installed(button))
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _installed(self, button: QPushButton) -> None:
        button.setEnabled(True)
        self._authorization.clear()
        self._status.setText("FDM accepted the authorization-code installation request.")


class CredentialPage(CapabilityPage):
    def __init__(self) -> None:
        super().__init__(
            "Cisco Credentials",
            "Store Cisco API credentials in the current user's operating-system credential vault.",
        )
        self._service = CredentialService()
        self._client_id = QLineEdit()
        self._client_secret = QLineEdit()
        self._client_secret.setEchoMode(QLineEdit.EchoMode.Password)
        form = QFormLayout()
        form.addRow("Client ID", self._client_id)
        form.addRow("Client secret", self._client_secret)
        self._layout.addLayout(form)

        controls = QHBoxLayout()
        store = QPushButton("Store credentials")
        status = QPushButton("Check status")
        delete = QPushButton("Delete credentials")
        controls.addWidget(store)
        controls.addWidget(status)
        controls.addWidget(delete)
        self._layout.addLayout(controls)
        store.clicked.connect(self._store)
        status.clicked.connect(self._status_check)
        delete.clicked.connect(self._delete)
        self._complete_layout()

    def _store(self) -> None:
        try:
            command = CiscoCredentialsCommand.from_untrusted(
                self._client_id.text(), self._client_secret.text()
            )
            self._show_result(self._service.store(command))
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))
        finally:
            self._client_secret.clear()

    def _status_check(self) -> None:
        try:
            self._show_result(self._service.status())
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))

    def _delete(self) -> None:
        answer = QMessageBox.question(
            self,
            "Delete Cisco credentials",
            "Remove the stored Cisco Client ID and Client Secret?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self._show_result(self._service.delete())
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))


class CiscoAuthenticationPage(CapabilityPage):
    def __init__(self) -> None:
        super().__init__(
            "Cisco Authentication",
            "Request a real OAuth token using credentials from the operating-system vault. The token is never displayed.",
        )
        button = QPushButton("Validate Cisco authentication")
        button.clicked.connect(lambda: self._validate(button))
        self._layout.addWidget(button)
        self._complete_layout()

    def _validate(self, button: QPushButton) -> None:
        try:
            credentials = _prompt_cisco_credentials(self)
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))
            return
        if credentials is not None:
            self._run(
                button, CiscoAuthenticationService(credentials=credentials).validate
            )


class CiscoAccountPage(CapabilityPage):
    def __init__(self) -> None:
        super().__init__(
            "Cisco Account Selection",
            "Discover accessible accounts. A choice is requested only when more than one account is returned.",
        )
        self._service = CiscoAccountService()
        self._smart_account = None
        button = QPushButton("Discover accounts")
        button.clicked.connect(lambda: self._discover_smart_accounts(button))
        self._layout.addWidget(button)
        self._complete_layout()

    def _discover_smart_accounts(self, button: QPushButton) -> None:
        try:
            credentials = _prompt_cisco_credentials(self)
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))
            return
        if credentials is None:
            self._status.setText("Credential entry cancelled.")
            return
        self._service = CiscoAccountService(credentials=credentials)
        button.setEnabled(False)
        self._status.setText("Discovering smart accounts…")
        worker = ServiceWorker(self._service.list_smart_accounts)
        worker.signals.succeeded.connect(
            lambda accounts: self._choose_smart_account(button, accounts)
        )
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _choose_smart_account(self, button: QPushButton, accounts: tuple) -> None:
        if not accounts:
            self._show_error("No accessible smart accounts were returned")
            button.setEnabled(True)
            return
        if len(accounts) == 1:
            selected = accounts[0]
        else:
            labels = [f"{item.name} ({item.domain})" for item in accounts]
            label, accepted = QInputDialog.getItem(
                self, "Select smart account", "Smart account", labels, 0, False
            )
            if not accepted:
                self._status.setText("Account selection cancelled.")
                button.setEnabled(True)
                return
            selected = accounts[labels.index(label)]
        self._smart_account = selected
        self._status.setText("Discovering virtual accounts…")
        worker = ServiceWorker(lambda: self._service.list_virtual_accounts(selected))
        worker.signals.succeeded.connect(
            lambda accounts: self._choose_virtual_account(button, accounts)
        )
        worker.signals.failed.connect(self._show_error)
        worker.signals.failed.connect(lambda _message: button.setEnabled(True))
        QThreadPool.globalInstance().start(worker)

    def _choose_virtual_account(self, button: QPushButton, accounts: tuple) -> None:
        button.setEnabled(True)
        if not accounts:
            self._show_error("No accessible virtual accounts were returned")
            return
        if len(accounts) == 1:
            selected = accounts[0]
        else:
            labels = [item.name for item in accounts]
            label, accepted = QInputDialog.getItem(
                self, "Select virtual account", "Virtual account", labels, 0, False
            )
            if not accepted:
                self._status.setText("Account selection cancelled.")
                return
            selected = accounts[labels.index(label)]
        self._status.setText(
            f"Selected {self._smart_account.name} / {selected.name}."
        )


class FdmConnectionPage(CapabilityPage):
    def __init__(self) -> None:
        super().__init__(
            "FDM Connection",
            "Establish certificate trust, then validate authentication to the selected FTD device.",
        )
        self._host = QLineEdit()
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._username = QLineEdit("admin")
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_version = QLineEdit("latest")
        self._certificate_dir = QLineEdit("certificates")
        form = QFormLayout()
        form.addRow("Host", self._host)
        form.addRow("Port", self._port)
        form.addRow("Username", self._username)
        form.addRow("Password", self._password)
        form.addRow("API version", self._api_version)
        form.addRow("Certificate directory", self._certificate_dir)
        self._layout.addLayout(form)

        controls = QHBoxLayout()
        bootstrap = QPushButton("Bootstrap certificate")
        authenticate = QPushButton("Validate FDM authentication")
        controls.addWidget(bootstrap)
        controls.addWidget(authenticate)
        self._layout.addLayout(controls)
        bootstrap.clicked.connect(lambda: self._bootstrap(bootstrap))
        authenticate.clicked.connect(lambda: self._authenticate(authenticate))
        self._complete_layout()

    def _bootstrap(self, button: QPushButton) -> None:
        try:
            command = FdmBootstrapCommand.from_untrusted(
                host=self._host.text(),
                port=self._port.value(),
                certificate_store_dir=self._certificate_dir.text(),
            )
        except ValueError as exc:
            self._show_error(str(exc))
            return
        self._run(button, lambda: FdmCertificateService().bootstrap(command))

    def _authenticate(self, button: QPushButton) -> None:
        try:
            command = FdmConnectionCommand.from_untrusted(
                host=self._host.text(),
                port=self._port.value(),
                username=self._username.text(),
                password=self._password.text(),
                api_version=self._api_version.text(),
                certificate_store_dir=self._certificate_dir.text(),
            )
        except ValueError as exc:
            self._show_error(str(exc))
            return
        finally:
            self._password.clear()
        self._run(button, lambda: FdmAuthenticationService().validate(command))


PAGE_FACTORIES: dict[str, Callable[[], QWidget]] = {
    "workflow": WorkflowPage,
    "fdm": FdmConnectionPage,
    "credentials": CredentialPage,
    "cisco_auth": CiscoAuthenticationPage,
    "cisco_accounts": CiscoAccountPage,
}
