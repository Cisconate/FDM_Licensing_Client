"""Capability pages for the desktop application."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
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
from fdm_licensing.services import (
    CiscoAuthenticationService,
    CredentialService,
    FdmAuthenticationService,
    FdmCertificateService,
)

from .workers import ServiceWorker


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


class WorkflowPage(CapabilityPage):
    def __init__(self) -> None:
        super().__init__(
            "FTD Licensing Workflow",
            "The application is organized around the complete device-to-Cisco-to-device licensing flow.",
        )
        steps = (
            ("1. Connect to FTD / FDM", "Certificate trust and authentication are available."),
            ("2. Generate reservation request", "Capability will be added with the approved FDM endpoint contract."),
            ("3. Authenticate to Cisco", "Credential storage and OAuth validation are available."),
            ("4. Generate authorization code", "Capability will be added with the approved Cisco licensing contract."),
            ("5. Install authorization on FTD", "Capability will be added with the approved FDM endpoint contract."),
        )
        for title, detail in steps:
            card = QFrame()
            card.setFrameShape(QFrame.Shape.StyledPanel)
            card_layout = QVBoxLayout(card)
            label = QLabel(title)
            label.setObjectName("stepHeading")
            card_layout.addWidget(label)
            description = QLabel(detail)
            description.setWordWrap(True)
            card_layout.addWidget(description)
            self._layout.addWidget(card)
        self._complete_layout()


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
        button.clicked.connect(
            lambda: self._run(button, CiscoAuthenticationService().validate)
        )
        self._layout.addWidget(button)
        self._complete_layout()


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
}
