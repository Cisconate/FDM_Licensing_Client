"""Use-case services shared by every presentation layer."""

from __future__ import annotations

from collections.abc import Callable

from cisco_support_token_client import CiscoSupportTokenClient
from fdm_certificate_store import bootstrap_certificate_store
from fdm_client import FDMClient
from key_manager import KeyManager

from .models import (
    CiscoCredentialsCommand,
    FdmBootstrapCommand,
    FdmConnectionCommand,
    OperationResult,
)


class CredentialService:
    def __init__(self, manager_factory: Callable[[], KeyManager] = KeyManager) -> None:
        self._manager_factory = manager_factory

    def status(self) -> OperationResult:
        status = self._manager_factory().credential_status()
        state = "complete" if status.complete else "incomplete"
        return OperationResult(
            "Cisco credential status",
            f"{state.capitalize()} on {status.platform} using {status.backend}.",
        )

    def store(self, command: CiscoCredentialsCommand) -> OperationResult:
        self._manager_factory().store_cisco_credentials(
            command.client_id, command.client_secret
        )
        return OperationResult(
            "Cisco credentials", "Credentials stored in the operating-system vault."
        )

    def delete(self) -> OperationResult:
        self._manager_factory().delete_cisco_credentials()
        return OperationResult(
            "Cisco credentials", "Stored Cisco credentials were removed."
        )


class CiscoAuthenticationService:
    def __init__(
        self,
        manager_factory: Callable[[], KeyManager] = KeyManager,
        client_factory: Callable[..., CiscoSupportTokenClient] = CiscoSupportTokenClient,
    ) -> None:
        self._manager_factory = manager_factory
        self._client_factory = client_factory

    def validate(self) -> OperationResult:
        credentials = self._manager_factory().get_cisco_credentials()
        client = self._client_factory(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
        )
        try:
            token = client.authenticate()
            scope_state = "present" if token.scope else "not returned"
            return OperationResult(
                "Cisco authentication",
                f"Authentication succeeded. Token type: {token.token_type}; scope: {scope_state}.",
            )
        finally:
            client.close()


class FdmCertificateService:
    def __init__(
        self, bootstrap: Callable[..., object] = bootstrap_certificate_store
    ) -> None:
        self._bootstrap = bootstrap

    def bootstrap(self, command: FdmBootstrapCommand) -> OperationResult:
        path = self._bootstrap(
            host=command.host,
            port=command.port,
            certificate_store_dir=command.certificate_store_dir,
        )
        return OperationResult(
            "FDM certificate",
            f"Certificate saved to {path}. Verify its fingerprint through a trusted channel.",
        )


class FdmAuthenticationService:
    def __init__(self, client_factory: Callable[..., FDMClient] = FDMClient) -> None:
        self._client_factory = client_factory

    def validate(self, command: FdmConnectionCommand) -> OperationResult:
        with self._client_factory(
            host=command.host,
            port=command.port,
            username=command.username,
            password=command.password,
            api_version=command.api_version,
            certificate_store_dir=command.certificate_store_dir,
        ):
            return OperationResult(
                "FDM authentication", "Authentication succeeded and the session was closed."
            )
