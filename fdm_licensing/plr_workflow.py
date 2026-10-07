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
from fdm_client import FDMClient, FDMReadTimeoutError, FDMRequestError
from fdm_plr_client import (
    FdmPlrClient,
    FdmPlrError,
    PlrInstallResult,
    PlrRequestCode,
    PlrReturnCode,
)
from key_manager import CiscoClientCredentials, KeyManager

from .models import FdmConnectionCommand
from .run_logging import log_event, log_phase


class FdmPlrState(str, Enum):
    NOT_CONFIGURED = "not-configured"
    OTHER_CONFIGURED = "other-smart-agent-configured"
    UNIVERSAL_CONFIGURED = "universal-configured"
    REQUEST_CODE_AVAILABLE = "request-code-available"
    AMBIGUOUS = "ambiguous"


class UnsupportedPlrDeviceError(FdmPlrError):
    """A parsed device identity is not supported by the FDM workflow."""

    def __init__(
        self, product_id: str, device_identifier: str | None = None
    ) -> None:
        self.product_id = product_id
        self.device_identifier = device_identifier
        super().__init__(
            f"Device PID {product_id!r} is not supported by this FDM licensing "
            "workflow; the platform may not run FDM"
        )


@dataclass(frozen=True, slots=True)
class FdmPlrInspection:
    state: FdmPlrState
    connection_count: int
    request_codes: tuple[PlrRequestCode, ...]
    performance_tier: str | None = None
    performance_tier_present: bool = False
    platform_model: str = ""
    is_ftdv: bool = False


@dataclass(frozen=True, slots=True)
class FtdvPerformanceMode:
    key: str
    label: str
    performance_tier: str | None
    sku_order: int
    tag_marker: str


FTDV_PLATFORM_MODEL = "Cisco Secure Firewall Threat Defense for VMware"
FTDV_PERFORMANCE_MODES = (
    FtdvPerformanceMode("variable", "Variable", None, 1001, ".FPRV-TD-ULR,"),
    FtdvPerformanceMode("100m", "100 Mbps", "FTDv5", 5, ".FPRTD-100M-ULR,"),
    FtdvPerformanceMode("1g", "1 Gbps", "FTDv10", 10, ".FPRTD-1G-ULR,"),
    FtdvPerformanceMode("3g", "3 Gbps", "FTDv20", 20, ".FPRTD-3G-ULR,"),
    FtdvPerformanceMode("5g", "5 Gbps", "FTDv30", 30, ".FPRTD-5G-ULR,"),
    FtdvPerformanceMode("10g", "10 Gbps", "FTDv50", 50, ".FPRTD-10G-ULR,"),
    FtdvPerformanceMode("16g", "16 Gbps", "FTDv100", 100, ".FPRTD-16G-ULR,"),
    FtdvPerformanceMode("unlimited", "Unlimited", "FTDvU", 1000, ".FPRV-TD-ULR,"),
)
FTDV_PERFORMANCE_MODE_BY_KEY = {mode.key: mode for mode in FTDV_PERFORMANCE_MODES}


@dataclass(frozen=True, slots=True)
class PlrInventoryRule:
    """One evidence-backed request PID/tier to license-summary mapping."""

    family: str
    product_pattern: str
    performance_tier: str | None
    tier_field_required: bool
    sku_order: int
    tag_marker: str | None
    display_label: str


PLR_INVENTORY_RULES = (
    PlrInventoryRule(
        "CSF 1200 series",
        r"^CSF-(?:1210CE|1210CP|1220CX|1230|1240|1250)$",
        None, False, 1200, ".FPR1200_TD_ULR,", "CSF 1200 Series FTD PLR",
    ),
    PlrInventoryRule(
        "FPR 1000 series", r"^FPR-1\d{3}$", None, False, 1000,
        ".FPR1K-TD-ULR,", "Cisco Firepower 1000 Threat Defense Universal License",
    ),
    PlrInventoryRule(
        "CSF 200 series", r"^CSF-2\d{2}$", None, False, 200,
        ".CSF_200_TD_PLR,", "CSF200 Series FTD PLR",
    ),
    *(PlrInventoryRule(
        "FTDv" if mode.key != "variable" else "FTDv Variable",
        r"^NGFWv$", mode.performance_tier, True, mode.sku_order,
        mode.tag_marker,
        ("Cisco Firepower Virtual Threat Defense Universal License"
         if mode.key in {"variable", "unlimited"}
         else f"FTDv {mode.label} Universal License"),
    ) for mode in FTDV_PERFORMANCE_MODES),
)


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
    resumed_after_timeout: bool = False


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

    def set_cisco_credentials(self, credentials: CiscoClientCredentials) -> None:
        """Supply validated credentials before the Cisco transport is opened."""
        if not isinstance(credentials, CiscoClientCredentials):
            raise TypeError("credentials must be CiscoClientCredentials")
        if self._cached_licensing is not None or self._cached_tokens is not None:
            raise FdmPlrError(
                "Cisco credentials cannot change after the workflow opens a Cisco session"
            )
        self._credentials = credentials

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
                    allow_unsupported_version=command.allow_unsupported_version,
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
            allow_unsupported_version=command.allow_unsupported_version,
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
            platform_model = plr.get_platform_model()
            connections = plr.list_smart_agent_connections()
            codes: tuple[PlrRequestCode, ...] = ()
            if self._request_codes_applicable(connections):
                try:
                    codes = plr.list_plr_request_codes()
                except FDMRequestError as exc:
                    if "unableToGeneratePLRRequestCode" not in str(exc):
                        raise
        return self._inspection(connections, codes, platform_model=platform_model)

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
        *,
        platform_model: str = "",
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
        performance_tier: str | None = None
        performance_tier_present = False
        if len(connections) == 1:
            connection = connections[0]
            performance_tier_present = "performanceTier" in connection
            performance_tier = connection.get("performanceTier")
            if performance_tier is not None and not isinstance(
                performance_tier, str
            ):
                raise FdmPlrError(
                    "Smart Agent connection contains an invalid performance tier"
                )
        return FdmPlrInspection(
            state,
            len(connections),
            codes,
            performance_tier,
            performance_tier_present,
            platform_model,
            platform_model == FTDV_PLATFORM_MODEL,
        )

    @staticmethod
    def ftdv_mode(mode_key: str) -> FtdvPerformanceMode:
        """Resolve one already-normalized public mode key."""
        try:
            return FTDV_PERFORMANCE_MODE_BY_KEY[mode_key]
        except (KeyError, TypeError) as exc:
            raise ValueError("FTDv mode is unknown") from exc

    @staticmethod
    def validate_ftdv_selection(
        inspection: FdmPlrInspection, mode_key: str | None
    ) -> FtdvPerformanceMode | None:
        """Validate a presentation selection against read-only device state."""
        mode = (
            None
            if mode_key is None
            else UniversalPlrWorkflowService.ftdv_mode(mode_key)
        )
        if inspection.is_ftdv:
            if mode is None:
                return None
            if inspection.state is FdmPlrState.REQUEST_CODE_AVAILABLE and (
                not inspection.performance_tier_present
                or inspection.performance_tier != mode.performance_tier
            ):
                raise FdmPlrError(
                    "FTDv already has a PLR request code for a different performance mode"
                )
            return mode
        if mode is not None:
            raise FdmPlrError("--ftdv-mode can be used only with an FTDv device")
        return None

    def configure_universal_plr(
        self, command: FdmConnectionCommand, *, ftdv_mode: str | None = None
    ) -> FdmPlrInspection:
        """Create or convert the sole Smart Agent connection, then read its code.

        This is a mutating operation and callers must obtain explicit confirmation.
        """
        with self._fdm(command) as plr:
            platform_model = plr.get_platform_model()
            is_ftdv = platform_model == FTDV_PLATFORM_MODEL
            selected_mode = None if ftdv_mode is None else self.ftdv_mode(ftdv_mode)
            if is_ftdv and selected_mode is None:
                raise FdmPlrError(
                    "FTDv performance mode must be selected before Universal PLR is configured"
                )
            if not is_ftdv and selected_mode is not None:
                raise FdmPlrError("FTDv performance mode cannot be applied to this platform")
            selected_tier = selected_mode.performance_tier if selected_mode else None
            connections = plr.list_smart_agent_connections()
            if len(connections) > 1:
                raise FdmPlrError(
                    "FDM returned multiple Smart Agent connections; configuration is ambiguous"
                )
            if not connections:
                plr.create_universal_plr_connection(
                    performance_tier=selected_tier,
                    performance_tier_present=is_ftdv,
                )
            elif (
                connections[0].get("connectionType") != "UNIVERSAL_PLR"
                or is_ftdv
            ):
                connection = connections[0]
                connection_id = connection.get("id")
                version = connection.get("version")
                if not isinstance(connection_id, str) or not isinstance(version, str):
                    raise FdmPlrError(
                        "Existing Smart Agent connection lacks an id or version"
                    )
                performance = selected_tier if is_ftdv else connection.get(
                    "performanceTier"
                )
                if performance is not None and not isinstance(performance, str):
                    raise FdmPlrError(
                        "Existing Smart Agent connection has an invalid performance tier"
                    )
                plr.update_connection_to_universal_plr(
                    connection_id=connection_id,
                    version=version,
                    performance_tier=performance,
                    performance_tier_present=is_ftdv or performance is not None,
                )
            return self._wait_for_request_code(
                plr,
                platform_model=platform_model,
                expected_performance_tier=selected_tier,
                verify_performance_tier=is_ftdv,
            )

    def _wait_for_request_code(
        self,
        plr: FdmPlrClient,
        *,
        platform_model: str = "",
        expected_performance_tier: str | None = None,
        verify_performance_tier: bool = False,
    ) -> FdmPlrInspection:
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
            inspection = self._inspection(
                connections, codes, platform_model=platform_model
            )
            if inspection.state is FdmPlrState.REQUEST_CODE_AVAILABLE:
                if verify_performance_tier and (
                    not inspection.performance_tier_present
                    or inspection.performance_tier != expected_performance_tier
                ):
                    raise FdmPlrError(
                        "FDM did not apply the selected FTDv performance mode"
                    )
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
        product_id: str,
        summary: LicenseSummary,
        *,
        performance_tier: str | None = None,
        performance_tier_present: bool = False,
    ) -> tuple[Any, ...]:
        """Return evidence-backed inventory for a PID and optional FTDv tier."""
        rule = UniversalPlrWorkflowService.inventory_rule(
            product_id,
            performance_tier=performance_tier,
            performance_tier_present=performance_tier_present,
        )
        if rule is None or rule.tag_marker is None:
            return ()
        return tuple(
            item for item in summary.items if rule.tag_marker in item.tag
        )

    @staticmethod
    def inventory_rule(
        product_id: str,
        *,
        performance_tier: str | None = None,
        performance_tier_present: bool = False,
    ) -> PlrInventoryRule | None:
        """Resolve one registry rule or reject an unsupported physical PID."""
        product_pattern_matched = False
        for rule in PLR_INVENTORY_RULES:
            if not re.fullmatch(rule.product_pattern, product_id):
                continue
            product_pattern_matched = True
            if rule.tier_field_required and (
                not performance_tier_present
                or rule.performance_tier != performance_tier
            ):
                continue
            return rule
        if product_pattern_matched:
            return None
        raise UnsupportedPlrDeviceError(product_id)

    @staticmethod
    def ensure_request_code_supported(reservation_code: str) -> str:
        """Block unsupported PIDs before account lookup or reservation preflight."""
        identity = CiscoPlrReservationClient.reservation_request_identity(
            reservation_code
        )
        try:
            UniversalPlrWorkflowService.inventory_rule(identity.product_id)
        except UnsupportedPlrDeviceError as exc:
            raise UnsupportedPlrDeviceError(
                identity.product_id, identity.device_identifier
            ) from exc
        return identity.product_id

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
            with log_phase("reservation.cisco_reserve"):
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
            with log_phase("reservation.fdm_install"):
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

    def finalize_return(
        self,
        command: FdmConnectionCommand,
        *,
        recovery_notice: Callable[[str], None] | None = None,
    ) -> None:
        """Finalize unregister once and reconcile a timed-out response read-only."""
        with self._fdm(command) as plr:
            connection_id = plr.finalization_connection_id()
            try:
                with log_phase("return.fdm_unregister"):
                    plr.delete_smart_agent_connection(connection_id)
            except FDMReadTimeoutError as timeout_error:
                log_event("return.fdm_unregister.read_timeout")
                if recovery_notice is not None:
                    recovery_notice(
                        "FDM did not respond before the timeout. Checking whether "
                        "unregister completed."
                    )
                deadline = time.monotonic() + self._readiness_timeout
                while True:
                    try:
                        connections = plr.list_smart_agent_connections()
                    except FDMReadTimeoutError:
                        connections = None
                    if connections is not None:
                        identifiers = tuple(item.get("id") for item in connections)
                        if connection_id not in identifiers:
                            if identifiers:
                                raise FdmPlrError(
                                    "FDM returned a different Smart Agent connection "
                                    "while reconciling unregister; no delete was repeated"
                                ) from timeout_error
                            log_event("return.fdm_unregister.reconciled")
                            if recovery_notice is not None:
                                recovery_notice(
                                    "FDM completed unregister after the original "
                                    "request timed out."
                                )
                            return
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise FdmPlrError(
                            "Cisco return completed, but FDM unregister could not be "
                            f"confirmed within {self._readiness_timeout:g} seconds. "
                            "The delete was not repeated; inspect FDM before resuming "
                            "finalization."
                        ) from timeout_error
                    time.sleep(min(self._poll_interval, remaining))

    def generate_return(
        self,
        command: FdmConnectionCommand,
        instance: ProductInstance,
        *,
        recovery_notice: Callable[[str], None] | None = None,
    ) -> ReturnHandoff:
        """Generate a return code or recover once after an ambiguous read timeout."""
        if not isinstance(instance, ProductInstance):
            raise ValueError("instance must be a ProductInstance")
        with self._fdm(command) as plr:
            try:
                with log_phase("return.fdm_cancel"):
                    result: PlrReturnCode = plr.generate_return_code()
            except FDMReadTimeoutError as timeout_error:
                log_event("return.fdm_cancel.read_timeout")
                if recovery_notice is not None:
                    recovery_notice(
                        "FDM did not respond before the timeout. Checking whether "
                        "the PLR return started."
                    )
                deadline = time.monotonic() + self._readiness_timeout
                while True:
                    identity = plr.get_return_identity(allow_pending=True)
                    if identity.registration_status == "PLR_DEACTIVATION_IN_PROGRESS":
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise FdmPlrError(
                            "FDM cancellation timed out and a pending PLR return "
                            "could not be confirmed; the operation outcome is unknown "
                            "and the cancellation request was not repeated"
                        ) from timeout_error
                    time.sleep(min(self._poll_interval, remaining))
                if recovery_notice is not None:
                    recovery_notice(
                        "FDM started the PLR return. Resuming with the existing code."
                    )
                try:
                    with log_phase("return.code_recovery"):
                        result = plr.recover_pending_return_code()
                except (FDMRequestError, FdmPlrError, ValueError) as recovery_error:
                    raise FdmPlrError(
                        "FDM started the PLR return, but its return code could not "
                        "be recovered. No further request will be submitted "
                        "automatically; rerun the return command to resume."
                    ) from recovery_error
                return ReturnHandoff(result.code, instance, True)
        return ReturnHandoff(result.code, instance)

    def resume_return(
        self, command: FdmConnectionCommand, instance: ProductInstance
    ) -> ReturnHandoff:
        """Recover one pending FDM return code and retain it only in memory."""
        if not isinstance(instance, ProductInstance):
            raise ValueError("instance must be a ProductInstance")
        with self._fdm(command) as plr:
            result: PlrReturnCode = plr.recover_pending_return_code()
        return ReturnHandoff(result.code, instance)

    def complete_return(
        self,
        selection: AccountSelection,
        instance: ProductInstance,
        return_code: str,
    ) -> PlrReturnResult:
        """Perform the sole Cisco v3 product-instance removal mutation."""
        with self._cisco() as licensing:
            with log_phase("return.cisco_remove"):
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
