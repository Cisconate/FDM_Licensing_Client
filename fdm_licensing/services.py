"""Use-case services shared by every presentation layer."""

from __future__ import annotations

from collections.abc import Callable

from cisco_support_token_client import CiscoSupportTokenClient
from cisco_support_api_client import (
    APX_SOFTWARE_API_PROFILE,
    CiscoLicensingApiProfile,
    CiscoPlrReservationClient,
    SmartAccount,
    VirtualAccount,
)
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


class CiscoAccountService:
    """Discover account choices without coupling selection to a presentation."""

    def __init__(
        self,
        manager_factory: Callable[[], KeyManager] = KeyManager,
        token_client_factory: Callable[..., CiscoSupportTokenClient] = CiscoSupportTokenClient,
        licensing_client_factory: Callable[..., CiscoPlrReservationClient] = CiscoPlrReservationClient,
        profile: CiscoLicensingApiProfile = APX_SOFTWARE_API_PROFILE,
    ) -> None:
        self._manager_factory = manager_factory
        self._token_client_factory = token_client_factory
        self._licensing_client_factory = licensing_client_factory
        self._profile = profile

    def _clients(self) -> tuple[CiscoSupportTokenClient, CiscoPlrReservationClient]:
        credentials = self._manager_factory().get_cisco_credentials()
        tokens = self._token_client_factory(
            client_id=credentials.client_id, client_secret=credentials.client_secret
        )
        licensing = self._licensing_client_factory(
            profile=self._profile,
            token_provider=tokens.get_bearer_token,
            token_refresher=tokens.refresh,
        )
        return tokens, licensing

    def list_smart_accounts(self) -> tuple[SmartAccount, ...]:
        tokens, licensing = self._clients()
        try:
            return licensing.list_smart_accounts()
        finally:
            licensing.close()
            tokens.close()

    def list_virtual_accounts(
        self, smart_account: SmartAccount
    ) -> tuple[VirtualAccount, ...]:
        tokens, licensing = self._clients()
        try:
            return licensing.list_virtual_accounts(smart_account)
        finally:
            licensing.close()
            tokens.close()


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
        ) as client:
            return OperationResult(
                "FDM authentication",
                f"Authentication and compatibility validation succeeded for FTD "
                f"{client.software_version}; the session was closed.",
            )
