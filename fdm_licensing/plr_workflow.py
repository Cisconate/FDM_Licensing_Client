"""Shared staged Universal PLR workflow used by CLI and GUI presentations."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
import math
import re
import time
from typing import Any

from cisco_support_api_client import (
    APX_SOFTWARE_API_PROFILE,
    AccountSelection,
    CiscoLicensingApiProfile,
    CiscoPlrReservationClient,
    LicenseSummary,
    PlrAuthorization,
    PlrReturnResult,
    ProductInstanceLocation,
    ProductInstance,
    ReservationPreflight,
    SmartAccount,
    VirtualAccount,
)
from cisco_support_token_client import CiscoSupportTokenClient
from fdm_client import FDMClient, FDMRequestError
from fdm_plr_client import (
    FdmPlrClient,
    FdmPlrError,
    PlrInstallResult,
    PlrRequestCode,
    PlrReturnCode,
)
from key_manager import CiscoClientCredentials, KeyManager

from .models import FdmConnectionCommand


class FdmPlrState(str, Enum):
    NOT_CONFIGURED = "not-configured"
    OTHER_CONFIGURED = "other-smart-agent-configured"
    UNIVERSAL_CONFIGURED = "universal-configured"
    REQUEST_CODE_AVAILABLE = "request-code-available"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class FdmPlrInspection:
    state: FdmPlrState
    connection_count: int
    request_codes: tuple[PlrRequestCode, ...]


@dataclass(frozen=True, slots=True)
class AuthorizationHandoff:
    """Sensitive in-memory handoff. Its repr intentionally omits both codes."""

    authorization_code: str = field(repr=False)
    reservation_code: str = field(repr=False)
    status: str


@dataclass(frozen=True, slots=True)
class ReturnHandoff:
    """Sensitive resumable handoff between FDM cancellation and CSSM removal."""

    return_code: str = field(repr=False)
    instance: ProductInstance


class UniversalPlrWorkflowService:
    """Coordinate cohesive PLR stages while keeping mutation boundaries explicit."""

    def __init__(
        self,
        *,
        fdm_factory: Callable[..., FDMClient] = FDMClient,
        manager_factory: Callable[[], KeyManager] = KeyManager,
        token_client_factory: Callable[..., CiscoSupportTokenClient] = CiscoSupportTokenClient,
        licensing_client_factory: Callable[..., CiscoPlrReservationClient] = CiscoPlrReservationClient,
        profile: CiscoLicensingApiProfile = APX_SOFTWARE_API_PROFILE,
        credentials: CiscoClientCredentials | None = None,
        readiness_timeout: float = 60.0,
        poll_interval: float = 1.0,
    ) -> None:
        self._fdm_factory = fdm_factory
        self._manager_factory = manager_factory
        self._token_client_factory = token_client_factory
        self._licensing_client_factory = licensing_client_factory
        self._profile = profile
        self._credentials = credentials
        self._reuse_sessions = False
        self._cached_fdm_command: FdmConnectionCommand | None = None
        self._cached_fdm: FDMClient | None = None
        self._cached_plr: FdmPlrClient | None = None
        self._cached_tokens: CiscoSupportTokenClient | None = None
        self._cached_licensing: CiscoPlrReservationClient | None = None
        self._smart_accounts_cache: tuple[SmartAccount, ...] | None = None
        self._virtual_accounts_cache: dict[tuple[str, str], tuple[VirtualAccount, ...]] = {}
        for value, name in (
            (readiness_timeout, "readiness_timeout"),
            (poll_interval, "poll_interval"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0 < float(value) <= 300
            ):
                raise ValueError(f"{name} must be finite and between 0 and 300 seconds")
        self._readiness_timeout = float(readiness_timeout)
        self._poll_interval = float(poll_interval)

    def __enter__(self) -> "UniversalPlrWorkflowService":
        self.start_reuse()
        return self

    def start_reuse(self) -> None:
        """Keep lazily opened transports alive until ``close`` is called."""
        self._reuse_sessions = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        """Close cached transports and clear the workflow-scoped session state."""
        try:
            if self._cached_licensing is not None:
                self._cached_licensing.close()
        finally:
            try:
                if self._cached_tokens is not None:
                    self._cached_tokens.close()
            finally:
                if self._cached_fdm is not None:
                    self._cached_fdm.close()
        self._cached_licensing = None
        self._cached_tokens = None
        self._cached_plr = None
        self._cached_fdm = None
        self._cached_fdm_command = None
        self._smart_accounts_cache = None
        self._virtual_accounts_cache.clear()
        self._reuse_sessions = False

    def list_smart_accounts(self) -> tuple[SmartAccount, ...]:
        if self._smart_accounts_cache is None:
            with self._cisco() as licensing:
                self._smart_accounts_cache = licensing.list_smart_accounts()
        return self._smart_accounts_cache

    def list_virtual_accounts(
        self, smart_account: SmartAccount
    ) -> tuple[VirtualAccount, ...]:
        key = (smart_account.domain.casefold(), smart_account.account_id)
        if key not in self._virtual_accounts_cache:
            with self._cisco() as licensing:
                self._virtual_accounts_cache[key] = licensing.list_virtual_accounts(
                    smart_account
                )
        return self._virtual_accounts_cache[key]

    @contextmanager
    def _fdm(self, command: FdmConnectionCommand) -> Iterator[FdmPlrClient]:
        if self._reuse_sessions:
            if self._cached_fdm_command is not None and self._cached_fdm_command != command:
                raise FdmPlrError("one workflow cannot reuse an FDM session for another device")
            if self._cached_plr is None:
                fdm = self._fdm_factory(
                    host=command.host, port=command.port, username=command.username,
                    password=command.password, api_version=command.api_version,
                    certificate_store_dir=command.certificate_store_dir,
                    allow_pinned_certificate_hostname_mismatch=True,
                )
                fdm.__enter__()
                self._cached_fdm = fdm
                self._cached_plr = FdmPlrClient(fdm)
                self._cached_fdm_command = command
            yield self._cached_plr
            return
        with self._fdm_factory(
            host=command.host,
            port=command.port,
            username=command.username,
            password=command.password,
            api_version=command.api_version,
            certificate_store_dir=command.certificate_store_dir,
            allow_pinned_certificate_hostname_mismatch=True,
        ) as fdm:
            yield FdmPlrClient(fdm)

    @contextmanager
    def _cisco(self) -> Iterator[CiscoPlrReservationClient]:
        if self._reuse_sessions:
            if self._cached_licensing is None:
                credentials = self._credentials or self._manager_factory().get_cisco_credentials()
                self._cached_tokens = self._token_client_factory(
                    client_id=credentials.client_id, client_secret=credentials.client_secret
                )
                self._cached_licensing = self._licensing_client_factory(
                    profile=self._profile,
                    token_provider=self._cached_tokens.get_bearer_token,
                    token_refresher=self._cached_tokens.refresh,
                )
            yield self._cached_licensing
            return
        credentials = self._credentials or self._manager_factory().get_cisco_credentials()
        tokens = self._token_client_factory(
            client_id=credentials.client_id, client_secret=credentials.client_secret
        )
        licensing = self._licensing_client_factory(
            profile=self._profile,
            token_provider=tokens.get_bearer_token,
            token_refresher=tokens.refresh,
        )
        try:
            yield licensing
        finally:
            licensing.close()
            tokens.close()

    def inspect_fdm(self, command: FdmConnectionCommand) -> FdmPlrInspection:
        """Read FDM licensing state without changing it."""
        with self._fdm(command) as plr:
            connections = plr.list_smart_agent_connections()
            codes: tuple[PlrRequestCode, ...] = ()
            if self._request_codes_applicable(connections):
                try:
                    codes = plr.list_plr_request_codes()
                except FDMRequestError as exc:
                    if "unableToGeneratePLRRequestCode" not in str(exc):
                        raise
        return self._inspection(connections, codes)

    @staticmethod
    def _request_codes_applicable(
        connections: tuple[Mapping[str, Any], ...]
    ) -> bool:
        """FDM exposes request codes only after the sole connection enables UPLR."""
        return (
            len(connections) == 1
            and connections[0].get("connectionType") == "UNIVERSAL_PLR"
        )

    @staticmethod
    def _inspection(
        connections: tuple[Mapping[str, Any], ...],
        codes: tuple[PlrRequestCode, ...],
    ) -> FdmPlrInspection:
        if len(connections) > 1 or len(codes) > 1:
            state = FdmPlrState.AMBIGUOUS
        elif not connections:
            state = FdmPlrState.AMBIGUOUS if codes else FdmPlrState.NOT_CONFIGURED
        elif connections[0].get("connectionType") != "UNIVERSAL_PLR":
            state = FdmPlrState.OTHER_CONFIGURED
        elif codes:
            state = FdmPlrState.REQUEST_CODE_AVAILABLE
        else:
            state = FdmPlrState.UNIVERSAL_CONFIGURED
        return FdmPlrInspection(state, len(connections), codes)

    def configure_universal_plr(
        self, command: FdmConnectionCommand
    ) -> FdmPlrInspection:
        """Create or convert the sole Smart Agent connection, then read its code.

        This is a mutating operation and callers must obtain explicit confirmation.
        """
        with self._fdm(command) as plr:
            connections = plr.list_smart_agent_connections()
            if len(connections) > 1:
                raise FdmPlrError(
                    "FDM returned multiple Smart Agent connections; configuration is ambiguous"
                )
            if not connections:
                plr.create_universal_plr_connection()
            elif connections[0].get("connectionType") != "UNIVERSAL_PLR":
                connection = connections[0]
                connection_id = connection.get("id")
                version = connection.get("version")
                if not isinstance(connection_id, str) or not isinstance(version, str):
                    raise FdmPlrError(
                        "Existing Smart Agent connection lacks an id or version"
                    )
                performance = connection.get("performanceTier")
                if performance is not None and not isinstance(performance, str):
                    raise FdmPlrError(
                        "Existing Smart Agent connection has an invalid performance tier"
                    )
                plr.update_connection_to_universal_plr(
                    connection_id=connection_id,
                    version=version,
                    performance_tier=performance,
                )
            return self._wait_for_request_code(plr)

    def _wait_for_request_code(self, plr: FdmPlrClient) -> FdmPlrInspection:
        """Poll read-only state while FDM applies a previously submitted mutation."""
        deadline = time.monotonic() + self._readiness_timeout
        while True:
            connections = plr.list_smart_agent_connections()
            if len(connections) > 1:
                raise FdmPlrError(
                    "FDM returned multiple Smart Agent connections while enabling PLR"
                )
            codes: tuple[PlrRequestCode, ...] = ()
            if self._request_codes_applicable(connections):
                try:
                    codes = plr.list_plr_request_codes()
                except FDMRequestError as exc:
                    if "unableToGeneratePLRRequestCode" not in str(exc):
                        raise
            inspection = self._inspection(connections, codes)
            if inspection.state is FdmPlrState.REQUEST_CODE_AVAILABLE:
                return inspection
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FdmPlrError(
                    "FDM enabled Universal PLR but its request code did not become "
                    f"available within {self._readiness_timeout:g} seconds; rerun the "
                    "workflow to resume without repeating the configuration mutation"
                )
            time.sleep(min(self._poll_interval, remaining))

    def license_summary(self, selection: AccountSelection) -> LicenseSummary:
        with self._cisco() as licensing:
            return licensing.get_license_summary(selection)

    def reservation_preview(
        self, selection: AccountSelection, reservation_code: str
    ) -> tuple[LicenseSummary, ReservationPreflight]:
        """Fetch independent read-only inventory and preflight data concurrently."""
        with self._cisco() as licensing:
            with ThreadPoolExecutor(max_workers=2) as executor:
                summary = executor.submit(licensing.get_license_summary, selection)
                preflight = executor.submit(
                    licensing.preflight_universal_plr, selection, reservation_code
                )
                return summary.result(), preflight.result()

    @staticmethod
    def compatible_licenses(
        product_id: str, summary: LicenseSummary
    ) -> tuple[Any, ...]:
        """Return only explicitly mapped Universal PLR licenses for a device PID."""
        rules = (
            (r"^FPR-1\d{3}$", ".FPR1K-TD-ULR,"),
            (r"^CSF-2\d{2}$", ".CSF_200_TD_PLR,"),
        )
        marker = next(
            (tag for pattern, tag in rules if re.fullmatch(pattern, product_id)),
            None,
        )
        if marker is None:
            return ()
        return tuple(item for item in summary.items if marker in item.tag)

    def preflight(
        self, selection: AccountSelection, reservation_code: str
    ) -> ReservationPreflight:
        with self._cisco() as licensing:
            return licensing.preflight_universal_plr(selection, reservation_code)

    def reserve(
        self, selection: AccountSelection, reservation_code: str
    ) -> AuthorizationHandoff:
        """Perform the sole CSSM reservation mutation and retain its code in memory."""
        with self._cisco() as licensing:
            result: PlrAuthorization = licensing.reserve_universal_plr(
                selection, reservation_code
            )
        return AuthorizationHandoff(
            authorization_code=result.authorization_code,
            reservation_code=result.reservation_code,
            status=result.status,
        )

    def install(
        self, command: FdmConnectionCommand, authorization_code: str
    ) -> PlrInstallResult:
        """Perform the sole FDM authorization installation mutation."""
        with self._fdm(command) as plr:
            return plr.install_authorization_code(authorization_code)

    def return_preflight(
        self, command: FdmConnectionCommand, selection: AccountSelection
    ) -> ProductInstance:
        """Validate authorized FDM state and locate its exact CSSM instance."""
        with self._fdm(command) as plr:
            identity = plr.get_return_identity(allow_pending=True)
        with self._cisco() as licensing:
            return licensing.preflight_plr_return(
                selection, identity.serial_number
            )

    def locate_return(self, command: FdmConnectionCommand) -> ProductInstanceLocation:
        """Locate the FTD product instance and owning accounts without prompting."""
        with self._fdm(command) as plr:
            identity = plr.get_return_identity(allow_pending=True)
        with self._cisco() as licensing:
            return licensing.locate_product_instance(identity.serial_number)

    def inspect_return(self, command: FdmConnectionCommand):
        """Read-only validation of FDM authorization and return identity."""
        with self._fdm(command) as plr:
            return plr.get_return_identity(allow_pending=True)

    def finalize_return(self, command: FdmConnectionCommand) -> None:
        """Perform the final FDM unregister mutation after Cisco completion."""
        with self._fdm(command) as plr:
            plr.finalize_return()

    def generate_return(
        self, command: FdmConnectionCommand, instance: ProductInstance
    ) -> ReturnHandoff:
        """Perform the sole FDM cancellation mutation and retain its return code."""
        if not isinstance(instance, ProductInstance):
            raise ValueError("instance must be a ProductInstance")
        with self._fdm(command) as plr:
            result: PlrReturnCode = plr.generate_return_code()
        return ReturnHandoff(result.code, instance)

    def complete_return(
        self,
        selection: AccountSelection,
        instance: ProductInstance,
        return_code: str,
    ) -> PlrReturnResult:
        """Perform the sole Cisco v3 product-instance removal mutation."""
        with self._cisco() as licensing:
            result = licensing.return_universal_plr(
                selection, instance, return_code
            )
            deadline = time.monotonic() + self._readiness_timeout
            while licensing.product_instance_exists(selection, instance):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FdmPlrError(
                        "Cisco accepted the PLR return but the product instance is "
                        "still visible; do not resubmit the return code and verify "
                        "again later"
                    )
                time.sleep(min(self._poll_interval, remaining))
            return result
