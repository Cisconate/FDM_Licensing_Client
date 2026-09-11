"""Capability pages for the desktop application."""

from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
import tempfile

from PySide6.QtCore import QThreadPool, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from fdm_licensing.models import (
    CiscoCredentialsCommand,
    FdmBootstrapCommand,
    FdmConnectionCommand,
    FdmCredentialsCommand,
    OperationResult,
)
from fdm_licensing.capabilities import FTD_LICENSING_OPERATIONS
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
    FdmCredentialService,
    FdmAuthenticationService,
    FdmCertificateService,
)

from .workers import GuiThreadRelay, ServiceWorker
from .progress import ActivityPanel


def _clipboard_icon() -> QIcon:
    """Return a small code-drawn clipboard icon with no platform asset dependency."""
    pixmap = QPixmap(18, 18)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor("#172235"), 1.5))
    painter.setBrush(QColor("#ffffff"))
    painter.drawRoundedRect(4, 3, 11, 13, 2, 2)
    painter.drawRoundedRect(7, 1, 5, 4, 1, 1)
    painter.drawLine(7, 8, 12, 8)
    painter.drawLine(7, 11, 12, 11)
    painter.end()
    return QIcon(pixmap)


def _save_code_file(path_text: str, code: str) -> Path:
    """Atomically save one handoff code without following a destination symlink."""
    if not path_text or "\x00" in path_text:
        raise ValueError("a valid destination file is required")
    if not code:
        raise ValueError("there is no authorization or return code to save")
    destination = Path(path_text).expanduser()
    if destination.exists() and destination.is_symlink():
        raise ValueError("code destination must not be a symbolic link")
    parent = destination.parent
    if not parent.is_dir():
        raise ValueError("code destination directory does not exist")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=parent,
            prefix=f".{destination.name}.", suffix=".tmp",
        ) as temporary:
            temporary.write(f"{code}\n")
            temporary_path = Path(temporary.name)
        if os.name != "nt":
            temporary_path.chmod(0o600)
        temporary_path.replace(destination)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return destination


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
        self._active_jobs: dict[ServiceWorker, GuiThreadRelay] = {}
        self._activity = ActivityPanel(self)
        self._activity_job: ServiceWorker | None = None

    def _complete_layout(self) -> None:
        self._layout.addStretch()
        self._layout.addWidget(self._activity)
        self._layout.addWidget(self._status)

    def _show_result(self, result: OperationResult) -> None:
        self._status.setText(result.message)

    def _show_error(self, message: str) -> None:
        self._status.setText(f"Operation failed: {message}")

    def _run(
        self,
        button: QPushButton,
        operation: Callable[[], OperationResult],
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        button.setEnabled(False)
        self._status.setText("Working…")
        self._start_background(
            operation,
            lambda result: (self._show_result(result), button.setEnabled(True)),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title=button.text(),
            timeout_seconds=timeout_seconds,
        )

    def _start_background(
        self,
        operation: Callable[[], object],
        succeeded: Callable[[object], None],
        failed: Callable[[str], None],
        *,
        activity_title: str = "Working",
        timeout_seconds: float | None = None,
    ) -> None:
        """Run work off-thread while universally reporting visible GUI activity."""
        worker = ServiceWorker(operation)

        def report_success(result: object) -> None:
            if self._activity_job is worker:
                self._activity.succeed()
            succeeded(result)

        def report_failure(message: str) -> None:
            if self._activity_job is worker:
                self._activity.fail()
            failed(message)

        def finished() -> None:
            relay = self._active_jobs.pop(worker, None)
            if relay is not None:
                relay.deleteLater()
            if self._activity_job is worker:
                self._activity_job = None

        relay = GuiThreadRelay(report_success, report_failure, finished, self)
        self._active_jobs[worker] = relay
        self._activity_job = worker
        self._activity.start(activity_title, timeout_seconds=timeout_seconds)
        worker.signals.succeeded.connect(relay.success)
        worker.signals.failed.connect(relay.failure)
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
        self._code_mode = "authorization"
        self._return_handoff = None
        self._stored_fdm_credentials = None
        self._field_overrides = {
            "host": False,
            "port": False,
            "username": False,
            "password": False,
        }

        self._host = QLineEdit()
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._username = QLineEdit()
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_version = QLineEdit("latest")
        self._certificate_dir = QLineEdit("certificates")
        self._certificate_dir.textChanged.connect(
            lambda _text: self._update_certificate_status()
        )
        self._host_lookup_timer = QTimer(self)
        self._host_lookup_timer.setSingleShot(True)
        self._host_lookup_timer.setInterval(350)
        self._host_lookup_timer.timeout.connect(self._lookup_typed_host)
        self._host.textEdited.connect(self._host_edited)
        self._port.lineEdit().textEdited.connect(
            lambda value: self._record_field_override("port", value)
        )
        self._username.textEdited.connect(
            lambda value: self._record_field_override("username", value)
        )
        self._password.textEdited.connect(
            lambda value: self._record_field_override("password", value)
        )
        form = QFormLayout()
        form.addRow("Host", self._host)
        form.addRow("Port", self._port)
        form.addRow("Username", self._username)
        form.addRow("Password", self._password)
        form.addRow("API version", self._api_version)
        form.addRow("Certificate directory", self._certificate_dir)
        self._layout.addLayout(form)

        self._credential_status = QLabel("")
        self._certificate_status = QLabel("")
        self._layout.addWidget(self._credential_status)
        self._layout.addWidget(self._certificate_status)

        controls = QHBoxLayout()
        self._operation_buttons: dict[str, QPushButton] = {}
        for operation in FTD_LICENSING_OPERATIONS:
            if operation.id == "install":
                continue
            button = QPushButton(operation.title)
            button.setObjectName(f"workflow_{operation.id}")
            button.setProperty("workflowAction", True)
            button.clicked.connect(
                lambda _checked=False, op=operation, control=button:
                getattr(self, op.handler)(control)
            )
            controls.addWidget(button)
            self._operation_buttons[operation.id] = button
        self._layout.addLayout(controls)

        self._authorization = QLineEdit()
        self._authorization.setEchoMode(QLineEdit.EchoMode.Password)
        code_label = QLabel("Authorization or Return code (generated or pasted)")
        self._layout.addWidget(code_label)
        self._authorization.setPlaceholderText(
            "Authorization or Return code (generated or pasted)"
        )
        self._authorization.textChanged.connect(
            lambda _text: self._update_workflow_controls()
        )
        install_operation = next(
            item for item in FTD_LICENSING_OPERATIONS if item.id == "install"
        )
        install = QPushButton(install_operation.title)
        install.setObjectName("workflow_install")
        install.setProperty("workflowAction", True)
        install.clicked.connect(lambda: self._perform_code_action(install))
        self._code_action_button = install
        copy_code = QPushButton()
        copy_code.setObjectName("copy_handoff_code")
        copy_code.setIcon(_clipboard_icon())
        copy_code.setToolTip("Copy code to clipboard")
        copy_code.setAccessibleName("Copy authorization or return code to clipboard")
        copy_code.setFixedSize(30, 30)
        copy_code.clicked.connect(self._copy_code)
        save_code = QPushButton()
        save_code.setObjectName("save_handoff_code")
        save_code.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        save_code.setToolTip("Save code to file")
        save_code.setAccessibleName("Save authorization or return code to file")
        save_code.setFixedSize(30, 30)
        save_code.clicked.connect(self._save_code)
        self._copy_code_button = copy_code
        self._save_code_button = save_code
        install_row = QHBoxLayout()
        install_row.addWidget(self._authorization, 1)
        install_row.addWidget(copy_code)
        install_row.addWidget(save_code)
        install_row.addWidget(install)
        self._layout.addLayout(install_row)
        self._operation_buttons["install"] = install
        self._load_stored_fdm_identity()
        self._update_certificate_status()
        self._update_workflow_controls()
        self._complete_layout()

    def _record_field_override(self, field: str, value: str) -> None:
        """Track only direct user edits; clearing reactivates vault fallback."""
        self._field_overrides[field] = bool(value.strip())
        self._refresh_credential_field_states()

    def _host_edited(self, value: str) -> None:
        self._record_field_override("host", value)
        if value.strip():
            self._host_lookup_timer.start()
        else:
            self._host_lookup_timer.stop()
            self.reload_fdm_credentials()

    def _lookup_typed_host(self) -> None:
        host = self._host.text().strip()
        if not host:
            return
        try:
            stored = KeyManager().get_fdm_credentials(host=host)
        except CredentialsNotFoundError:
            self._stored_fdm_credentials = None
        except (OSError, RuntimeError, ValueError) as exc:
            self._stored_fdm_credentials = None
            self._credential_status.setText(f"FDM credential vault unavailable: {exc}")
        else:
            self._stored_fdm_credentials = stored
            if not self._field_overrides["port"]:
                self._port.setValue(stored.port)
            self._credential_status.setText(
                "A matching FDM credential record is available in the OS vault."
            )
        self._refresh_credential_field_states()

    def reload_fdm_credentials(self) -> None:
        """Refresh workflow vault defaults after GUI credential management changes."""
        self._stored_fdm_credentials = None
        self._load_stored_fdm_identity()
        self._refresh_credential_field_states()

    def _load_stored_fdm_identity(self) -> None:
        """Hydrate non-secret device identity while keeping its password concealed."""
        try:
            manager = KeyManager()
            summary = manager.fdm_credential_summary()
            stored = (
                manager.get_fdm_credentials(host=summary.only_host)
                if summary.count == 1 and summary.only_host
                else None
            )
        except CredentialsNotFoundError:
            if not self._field_overrides["port"]:
                self._port.setValue(443)
            self._credential_status.setText("No complete FDM credential record is stored.")
            self._refresh_credential_field_states()
            return
        except (OSError, RuntimeError, ValueError) as exc:
            self._credential_status.setText(f"FDM credential vault unavailable: {exc}")
            self._refresh_credential_field_states()
            return
        if summary.count > 1:
            self._stored_fdm_credentials = None
            if not self._field_overrides["host"]:
                self._host.clear()
            self._credential_status.setText(
                "Multiple FDM records are stored. Enter the host to select one."
            )
            self._refresh_credential_field_states()
            return
        if stored is None:
            self._credential_status.setText("No complete FDM credential record is stored.")
            self._refresh_credential_field_states()
            return
        self._stored_fdm_credentials = stored
        if not self._field_overrides["host"]:
            self._host.setText(stored.host)
        if not self._field_overrides["port"]:
            self._port.setValue(stored.port)
        self._credential_status.setText(
            "A default FDM credential record is available in the OS vault."
        )
        self._refresh_credential_field_states()
        self._update_certificate_status()

    def _refresh_credential_field_states(self) -> None:
        stored = self._stored_fdm_credentials
        effective_host = (
            self._host.text() if self._field_overrides["host"]
            else stored.host if stored is not None else self._host.text()
        )
        effective_port = (
            self._port.value() if self._field_overrides["port"]
            else stored.port if stored is not None else self._port.value()
        )
        effective_username = (
            self._username.text() if self._field_overrides["username"]
            else stored.username if stored is not None else self._username.text()
        )
        password_from_vault = bool(
            stored is not None
            and stored.host == effective_host
            and stored.port == effective_port
            and stored.username == effective_username
        )
        availability = (
            ("host", self._host, stored is not None),
            ("username", self._username, stored is not None),
            ("password", self._password, password_from_vault),
        )
        for name, field, vault_available in availability:
            if field.text() and self._field_overrides[name]:
                state, placeholder = "provided", ""
            elif vault_available:
                state = "keychain"
                placeholder = "" if field.text() else "Using Keychain"
            elif field.text():
                state, placeholder = "provided", ""
            else:
                state, placeholder = "missing", "Required"
            field.setPlaceholderText(placeholder)
            field.setProperty("credentialState", state)
            field.style().unpolish(field)
            field.style().polish(field)

    def _update_certificate_status(self) -> None:
        bundle = certificate_bundle_path(self._certificate_dir.text())
        self._certificate_status.setText(
            "Trusted FDM certificate bundle is available."
            if bundle.is_file()
            else "No trusted FDM certificate bundle is available."
        )

    def _update_workflow_controls(self) -> None:
        inspected = self._command is not None
        has_code = self._request_code is not None
        has_authorization = (
            bool(self._authorization.text().strip())
            if hasattr(self, "_authorization")
            else False
        )
        available = {"connection"}
        if inspected:
            available.add("inspection")
        if has_code:
            available.add("request_code")
        if has_authorization:
            available.add("authorization_code")
        for operation in FTD_LICENSING_OPERATIONS:
            enabled = all(requirement in available for requirement in operation.requires)
            if operation.id == "request_code" and has_code:
                enabled = False
            button = self._operation_buttons.get(operation.id)
            if button is not None:
                button.setEnabled(enabled)
        if self._code_mode == "return" and self._return_handoff is None:
            self._code_action_button.setEnabled(False)
        self._copy_code_button.setEnabled(has_authorization)
        self._save_code_button.setEnabled(has_authorization)

    def _set_code_mode(self, mode: str) -> None:
        self._code_mode = mode
        self._code_action_button.setText(
            "Submit Return Code" if mode == "return" else "Install Authorization Code"
        )
        self._update_workflow_controls()

    def _copy_code(self) -> None:
        code = self._authorization.text()
        if not code:
            self._show_error("There is no authorization or return code to copy")
            return
        QApplication.clipboard().setText(code)
        self._status.setText(
            "Code copied to the clipboard. Clear clipboard history after use if required."
        )

    def _save_code(self) -> None:
        code = self._authorization.text()
        if not code:
            self._show_error("There is no authorization or return code to save")
            return
        filename, _selected_filter = QFileDialog.getSaveFileName(
            self, "Save authorization or return code", "licensing-code.txt",
            "Text files (*.txt);;All files (*)",
        )
        if not filename:
            self._status.setText("Code file save cancelled.")
            return
        try:
            destination = _save_code_file(filename, code)
        except (OSError, ValueError) as exc:
            self._show_error(str(exc))
            return
        self._status.setText(f"Code saved to {destination}.")

    def _connection_command(self) -> FdmConnectionCommand:
        if self._field_overrides["host"]:
            self._lookup_typed_host()
        try:
            stored = self._stored_fdm_credentials
        except CredentialsNotFoundError:
            stored = None
        host = (
            self._host.text()
            if self._field_overrides["host"] or stored is None
            else stored.host
        )
        port = (
            self._port.value()
            if self._field_overrides["port"] or stored is None
            else stored.port
        )
        username = (
            self._username.text()
            if self._field_overrides["username"] or stored is None
            else stored.username
        )
        password = self._password.text() if self._field_overrides["password"] else ""
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
        self._field_overrides["password"] = False
        self._refresh_credential_field_states()
        return command

    def _bootstrap_certificate(self, button: QPushButton) -> None:
        try:
            command = self._connection_command()
            bootstrap = FdmBootstrapCommand.from_untrusted(
                host=command.host, port=command.port,
                certificate_store_dir=command.certificate_store_dir,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))
            return
        answer = QMessageBox.question(
            self, "Trust FDM certificate",
            f"Fetch the certificate currently presented by {command.host}:{command.port}?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._status.setText("Certificate bootstrap cancelled.")
            return
        button.setEnabled(False)
        self._start_background(
            lambda: FdmCertificateService().bootstrap(bootstrap),
            lambda value: self._confirm_explicit_bootstrap(button, value),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Fetching FDM certificate",
            timeout_seconds=5,
        )

    def _confirm_explicit_bootstrap(
        self, button: QPushButton, result: OperationResult
    ) -> None:
        answer = QMessageBox.question(
            self, "Verify FDM certificate",
            f"{result.message}\n\nHave you verified this fingerprint through a "
            "trusted channel?",
        )
        button.setEnabled(True)
        if answer != QMessageBox.StandardButton.Yes:
            self._status.setText("Certificate fingerprint was not confirmed.")
            return
        self._update_certificate_status()
        self._status.setText("FDM certificate trust is ready. Inspect FDM to continue.")

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
            self._start_background(
                lambda: FdmCertificateService().bootstrap(bootstrap),
                lambda value: self._confirm_bootstrap(button, command, value),
                lambda message: (self._show_error(message), button.setEnabled(True)),
                activity_title="Fetching FDM certificate",
                timeout_seconds=5,
            )
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
        self._start_background(
            lambda: self._workflow.inspect_fdm(command),
            lambda value: self._inspection_done(button, value),
            lambda message: self._inspection_failed(button, command, message),
            activity_title="Inspecting FDM",
        )

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
        self._start_background(
            lambda: FdmCertificateService().bootstrap(bootstrap),
            lambda value: self._confirm_bootstrap(button, command, value),
            lambda error: (self._show_error(error), button.setEnabled(True)),
            activity_title="Refreshing FDM certificate trust",
            timeout_seconds=5,
        )

    def _inspection_done(self, button: QPushButton, inspection) -> None:
        button.setEnabled(True)
        if inspection.state is FdmPlrState.REQUEST_CODE_AVAILABLE:
            self._request_code = inspection.request_codes[0].code
        self._status.setText(f"FDM Universal PLR state: {inspection.state.value}.")
        self._update_workflow_controls()

    def _generate_request_code(self, button: QPushButton) -> None:
        if self._command is None:
            self._show_error("Inspect FDM first")
            return
        answer = QMessageBox.question(
            self,
            "Configure Universal PLR",
            "Enable Universal PLR on FDM and wait for a request code?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._status.setText("Request-code generation cancelled.")
            return
        button.setEnabled(False)
        self._start_background(
            lambda: self._workflow.configure_universal_plr(self._command),
            lambda value: self._request_code_generated(button, value),
            lambda message: (self._show_error(message), self._generation_failed(button)),
            activity_title="Generating Universal PLR request code",
            timeout_seconds=60,
        )

    def _generation_failed(self, button: QPushButton) -> None:
        button.setEnabled(True)
        self._update_workflow_controls()

    def _request_code_generated(self, button: QPushButton, inspection) -> None:
        try:
            self._request_code = inspection.request_codes[0].code
        except (AttributeError, IndexError):
            self._show_error("FDM did not return a Universal PLR request code")
            button.setEnabled(True)
            return
        self._status.setText(
            "Universal PLR request code is ready. Select an account and reserve."
        )
        self._update_workflow_controls()

    def _start_reservation(self, button: QPushButton) -> None:
        self._account_action = "reserve"
        self._return_handoff = None
        self._set_code_mode("authorization")
        if self._command is None:
            self._show_error("Inspect FDM first")
            return
        if self._request_code is None:
            self._show_error("Generate a request code first")
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
        self._return_handoff = None
        self._set_code_mode("return")
        self._workflow.close()
        self._workflow = UniversalPlrWorkflowService(credentials=credentials)
        self._workflow.start_reuse()
        button.setEnabled(False)
        self._start_background(
            lambda: self._workflow.locate_return(self._command),
            lambda location: self._return_location_done(button, location),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Locating the licensed product instance",
        )

    def _return_location_done(self, button: QPushButton, location) -> None:
        self._selection = location.selection
        self._return_preflight_done(button, location.instance)

    def _configured(self, button: QPushButton, inspection) -> None:
        self._request_code = inspection.request_codes[0].code
        button.setEnabled(True)
        self._start_reservation(button)

    def _discover_smart(self, button: QPushButton) -> None:
        button.setEnabled(False)
        self._start_background(
            self._workflow.list_smart_accounts,
            lambda values: self._choose_smart(button, values),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Fetching Smart Accounts",
        )

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
        self._start_background(
            lambda: self._workflow.list_virtual_accounts(smart),
            lambda accounts: self._choose_virtual(button, smart, accounts),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Fetching Virtual Accounts",
        )

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
            self._start_background(
                lambda: self._workflow.return_preflight(
                    self._command, self._selection
                ),
                lambda instance: self._return_preflight_done(button, instance),
                lambda message: (self._show_error(message), button.setEnabled(True)),
                activity_title="Verifying the PLR return target",
            )
            return
        self._start_background(
            lambda: self._workflow.reservation_preview(
                self._selection, self._request_code
            ),
            lambda value: self._preflight_done(button, value),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Checking compatible licenses and product registration",
        )

    def _return_preflight_done(self, button: QPushButton, instance) -> None:
        answer = QMessageBox.question(
            self, "Return Universal PLR",
            f"Return PLR from FDM for {instance.product_id}/{instance.serial_number}? "
            "The return code must then be submitted to Cisco.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            button.setEnabled(True)
            return
        self._start_background(
            lambda: self._workflow.generate_return(self._command, instance),
            lambda handoff: self._return_generated(button, handoff),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Generating the FDM PLR return code",
        )

    def _return_generated(self, button: QPushButton, handoff) -> None:
        self._return_handoff = handoff
        self._authorization.setText(handoff.return_code)
        self._authorization.setEchoMode(QLineEdit.EchoMode.Normal)
        self._set_code_mode("return")
        button.setEnabled(True)
        self._status.setText(
            "FDM generated the one-time return code. Copy or save it now, then click "
            "Submit Return Code to complete the Cisco return."
        )

    def _submit_return_code(self, button: QPushButton) -> None:
        handoff = self._return_handoff
        if handoff is None or self._selection is None:
            self._show_error("Generate and preserve an FDM return code first")
            return
        return_code = self._authorization.text()
        button.setEnabled(False)
        self._start_background(
            lambda: self._workflow.complete_return(
                self._selection, handoff.instance, return_code
            ),
            lambda result: self._return_done(button, result),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Submitting the PLR return to Cisco",
            timeout_seconds=60,
        )

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
        self._start_background(
            lambda: self._workflow.finalize_return(self._command),
            lambda _value: self._return_finalized(button, result),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Finalizing PLR unregister on FDM",
        )

    def _return_finalized(self, button: QPushButton, result) -> None:
        button.setEnabled(True)
        self._authorization.clear()
        self._return_handoff = None
        self._set_code_mode("authorization")
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
        self._start_background(
            lambda: self._workflow.reserve(self._selection, self._request_code),
            lambda value: self._reservation_done(button, value),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Reserving Universal PLR with Cisco",
        )

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
        self._return_handoff = None
        self._set_code_mode("authorization")
        self._authorization.setText(handoff.authorization_code)
        self._authorization.setEchoMode(QLineEdit.EchoMode.Normal)
        self._status.setText(
            "Reservation completed. Copy the authorization code or install it now."
        )
        self._update_workflow_controls()

    def _perform_code_action(self, button: QPushButton) -> None:
        if self._code_mode == "return":
            self._submit_return_code(button)
            return
        self._install(button)

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
        self._start_background(
            lambda: self._workflow.install(self._command, code),
            lambda _value: self._installed(button),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Installing the authorization code on FDM",
        )

    def _installed(self, button: QPushButton) -> None:
        button.setEnabled(True)
        self._authorization.clear()
        self._status.setText("FDM accepted the authorization-code installation request.")
        self._update_workflow_controls()


class CredentialPage(CapabilityPage):
    fdm_credentials_changed = Signal()

    def __init__(self) -> None:
        super().__init__(
            "Credential Management",
            "Store Cisco API and default FDM credentials in the current user's operating-system credential vault.",
        )
        self._service = CredentialService()
        self._fdm_service = FdmCredentialService()
        self._client_id = QLineEdit()
        self._client_secret = QLineEdit()
        self._client_secret.setEchoMode(QLineEdit.EchoMode.Password)
        cisco_group = QGroupBox("Cisco API credentials")
        cisco_layout = QVBoxLayout(cisco_group)
        form = QFormLayout()
        form.addRow("Client ID", self._client_id)
        form.addRow("Client secret", self._client_secret)
        cisco_layout.addLayout(form)

        controls = QHBoxLayout()
        store = QPushButton("Store Cisco credentials")
        status = QPushButton("Check Cisco status")
        delete = QPushButton("Delete Cisco credentials")
        controls.addWidget(store)
        controls.addWidget(status)
        controls.addWidget(delete)
        cisco_layout.addLayout(controls)
        self._layout.addWidget(cisco_group)
        store.clicked.connect(self._store)
        status.clicked.connect(self._status_check)
        delete.clicked.connect(self._delete)

        fdm_group = QGroupBox("Default FDM credentials")
        fdm_layout = QVBoxLayout(fdm_group)
        self._fdm_host = QLineEdit()
        self._fdm_port = QSpinBox()
        self._fdm_port.setRange(1, 65535)
        self._fdm_port.setValue(443)
        self._fdm_username = QLineEdit()
        self._fdm_password = QLineEdit()
        self._fdm_password.setEchoMode(QLineEdit.EchoMode.Password)
        fdm_form = QFormLayout()
        fdm_form.addRow("Host", self._fdm_host)
        fdm_form.addRow("Port", self._fdm_port)
        fdm_form.addRow("Username", self._fdm_username)
        fdm_form.addRow("Password", self._fdm_password)
        fdm_layout.addLayout(fdm_form)
        fdm_controls = QHBoxLayout()
        store_fdm = QPushButton("Store FDM credentials")
        status_fdm = QPushButton("Check FDM status")
        delete_fdm = QPushButton("Delete FDM credentials")
        fdm_controls.addWidget(store_fdm)
        fdm_controls.addWidget(status_fdm)
        fdm_controls.addWidget(delete_fdm)
        fdm_layout.addLayout(fdm_controls)
        self._layout.addWidget(fdm_group)
        store_fdm.clicked.connect(self._store_fdm)
        status_fdm.clicked.connect(self._status_fdm)
        delete_fdm.clicked.connect(self._delete_fdm)
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

    def _store_fdm(self) -> None:
        try:
            command = FdmCredentialsCommand.from_untrusted(
                host=self._fdm_host.text(),
                port=self._fdm_port.value(),
                username=self._fdm_username.text(),
                password=self._fdm_password.text(),
            )
            self._show_result(self._fdm_service.store(command))
            self.fdm_credentials_changed.emit()
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))
        finally:
            self._fdm_password.clear()

    def _status_fdm(self) -> None:
        try:
            self._show_result(self._fdm_service.status())
        except (OSError, RuntimeError, ValueError) as exc:
            self._show_error(str(exc))

    def _delete_fdm(self) -> None:
        answer = QMessageBox.question(
            self,
            "Delete FDM credentials",
            "Remove the stored default FDM host, port, username, and password?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self._show_result(self._fdm_service.delete())
            self.fdm_credentials_changed.emit()
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
        self._start_background(
            self._service.list_smart_accounts,
            lambda accounts: self._choose_smart_account(button, accounts),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Fetching Smart Accounts",
        )

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
        self._start_background(
            lambda: self._service.list_virtual_accounts(selected),
            lambda accounts: self._choose_virtual_account(button, accounts),
            lambda message: (self._show_error(message), button.setEnabled(True)),
            activity_title="Fetching Virtual Accounts",
        )

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
        self._username = QLineEdit()
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_version = QLineEdit("latest")
        self._certificate_dir = QLineEdit("certificates")
        self._stored_fdm_credentials = None
        self._field_overrides = {
            "host": False, "port": False, "username": False, "password": False,
        }
        self._host.textEdited.connect(
            lambda value: self._connection_field_edited("host", value)
        )
        self._port.lineEdit().textEdited.connect(
            lambda value: self._connection_field_edited("port", value)
        )
        self._username.textEdited.connect(
            lambda value: self._connection_field_edited("username", value)
        )
        self._password.textEdited.connect(
            lambda value: self._connection_field_edited("password", value)
        )
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
        self.reload_fdm_credentials()
        self._complete_layout()

    def _connection_field_edited(self, field: str, value: str) -> None:
        self._field_overrides[field] = bool(value.strip())
        self._refresh_connection_fields()

    def reload_fdm_credentials(self) -> None:
        try:
            self._stored_fdm_credentials = KeyManager().get_fdm_credentials()
        except CredentialsNotFoundError:
            self._stored_fdm_credentials = None
            if not self._field_overrides["port"]:
                self._port.setValue(443)
        except (OSError, RuntimeError, ValueError) as exc:
            self._stored_fdm_credentials = None
            self._show_error(str(exc))
        else:
            if not self._field_overrides["port"]:
                self._port.setValue(self._stored_fdm_credentials.port)
        self._refresh_connection_fields()

    def _effective_connection_values(self) -> tuple[str, int, str, str]:
        stored = self._stored_fdm_credentials
        host = self._host.text() if self._field_overrides["host"] or stored is None else stored.host
        port = self._port.value() if self._field_overrides["port"] or stored is None else stored.port
        username = (
            self._username.text()
            if self._field_overrides["username"] or stored is None
            else stored.username
        )
        password = self._password.text() if self._field_overrides["password"] else ""
        if (
            not password and stored is not None and stored.host == host
            and stored.port == port and stored.username == username
        ):
            password = stored.password
        return host, port, username, password

    def _refresh_connection_fields(self) -> None:
        stored = self._stored_fdm_credentials
        host, port, username, _password = self._effective_connection_values()
        password_available = bool(
            stored is not None and stored.host == host and stored.port == port
            and stored.username == username
        )
        for field, available in (
            (self._host, stored is not None),
            (self._username, stored is not None),
            (self._password, password_available),
        ):
            if field.text():
                state, placeholder = "provided", ""
            elif available:
                state, placeholder = "keychain", "Using Keychain"
            else:
                state, placeholder = "missing", "Required"
            field.setProperty("credentialState", state)
            field.setPlaceholderText(placeholder)
            field.style().unpolish(field)
            field.style().polish(field)

    def _bootstrap(self, button: QPushButton) -> None:
        try:
            host, port, _username, _password = self._effective_connection_values()
            command = FdmBootstrapCommand.from_untrusted(
                host=host,
                port=port,
                certificate_store_dir=self._certificate_dir.text(),
            )
        except ValueError as exc:
            self._show_error(str(exc))
            return
        self._run(
            button,
            lambda: FdmCertificateService().bootstrap(command),
            timeout_seconds=5,
        )

    def _authenticate(self, button: QPushButton) -> None:
        try:
            host, port, username, password = self._effective_connection_values()
            command = FdmConnectionCommand.from_untrusted(
                host=host,
                port=port,
                username=username,
                password=password,
                api_version=self._api_version.text(),
                certificate_store_dir=self._certificate_dir.text(),
            )
        except ValueError as exc:
            self._show_error(str(exc))
            return
        finally:
            self._password.clear()
            self._field_overrides["password"] = False
            self._refresh_connection_fields()
        self._run(button, lambda: FdmAuthenticationService().validate(command))


PAGE_FACTORIES: dict[str, Callable[[], QWidget]] = {
    "workflow": WorkflowPage,
    "fdm": FdmConnectionPage,
    "credentials": CredentialPage,
    "cisco_auth": CiscoAuthenticationPage,
    "cisco_accounts": CiscoAccountPage,
}
