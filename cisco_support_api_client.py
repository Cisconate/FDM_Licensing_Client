"""
Cisco Smart Accounts and Licensing reservation client.

This client does not obtain tokens. It accepts a bearer token from
cisco_support_token_client.py and uses that token for reservation requests.

The reservation endpoint is configurable because Cisco's Smart Accounts API
surface is route-specific and the caller may need to target a customer, smart
account, or virtual account path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import re
import secrets
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote, urljoin, urlparse

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter

from security_validation import (
    MAX_TOKEN_LENGTH,
    encode_json_payload,
    resolve_operator_path,
    safe_error_text,
    validate_headers,
    validate_https_base_url,
    validate_bool,
    validate_http_method,
    validate_opaque_value,
    validate_relative_api_path,
    validate_query_params,
    validate_timeout,
    validate_user_agent,
    validate_plr_authorization_code,
)


class CiscoPlrError(RuntimeError):
    """Base exception for PLR reservation failures."""


class CiscoPlrRequestError(CiscoPlrError):
    """The reservation request failed."""


class ExistingProductInstanceError(CiscoPlrError):
    """A reservation was blocked because Cisco already tracks the device."""

    def __init__(self, instance: "ProductInstance") -> None:
        self.instance = instance
        super().__init__(
            "Cisco already has a matching product instance in the selected virtual "
            "account. The published API does not expose its authorization code; "
            "recover the existing code in Cisco License Central. If an FTD return "
            "was started but never completed in CSSM, contact TAC and report a "
            "poisoned product instance."
        )


@dataclass(frozen=True, slots=True)
class CiscoLicensingApiProfile:
    """Approved relative routes for one Cisco Software API deployment."""

    name: str
    base_url: str
    smart_accounts_path: str = "pnp/v2/accounts"
    virtual_accounts_path_template: str = (
        "pnp/v2/accounts/{smart_account_domain}/virtual-accounts"
    )
    slr_details_path: str = "licensing/v1/search-slr-details"
    license_summary_path: str = "licensing/v2/get-summary"
    product_instances_path_template: str = (
        "licensing/v2/accounts/{smart_account_domain}/devices"
    )
    reserve_path_template: str = (
        "licensing/v2/account/{smart_account_domain}/virtual-account/"
        "{virtual_account_name}/licenses/reserve"
    )
    return_path_template: str = "licensing/v3/accounts/{smart_account_domain}/devices/remove"
    device_search_path: str = "licensing/v2/device/search"


APX_SOFTWARE_API_PROFILE = CiscoLicensingApiProfile(
    name="apx", base_url="https://apx.cisco.com/v1/software/apis/"
)
LEGACY_SWAPI_PROFILE = CiscoLicensingApiProfile(
    name="legacy-swapi",
    base_url="https://swapi.cisco.com/services/api/smart-accounts-and-licensing/v3/",
)


@dataclass(frozen=True, slots=True)
class SmartAccount:
    name: str
    domain: str
    account_id: str


@dataclass(frozen=True, slots=True)
class VirtualAccount:
    name: str
    account_id: str
    is_default: bool


@dataclass(frozen=True, slots=True)
class AccountSelection:
    smart_account: SmartAccount
    virtual_account: VirtualAccount


@dataclass(frozen=True, slots=True)
class SlrEntitlement:
    software_tag: str
    entitlement_tag: str
    reservation_type: str


@dataclass(frozen=True, slots=True)
class PlrAuthorization:
    authorization_code: str
    reservation_code: str
    status: str


@dataclass(frozen=True, slots=True)
class ReservationRequestIdentity:
    product_id: str
    device_identifier: str


@dataclass(frozen=True, slots=True)
class ProductInstance:
    instance_name: str
    product_tag: str
    product_id: str
    serial_number: str


@dataclass(frozen=True, slots=True)
class ReservationPreflight:
    identity: ReservationRequestIdentity
    existing_instance: ProductInstance | None

    @property
    def may_reserve(self) -> bool:
        return self.existing_instance is None


@dataclass(frozen=True, slots=True)
class PlrReturnResult:
    status: str
    message: str
    device: str


@dataclass(frozen=True, slots=True)
class ProductInstanceLocation:
    selection: AccountSelection
    instance: ProductInstance


@dataclass(frozen=True, slots=True)
class LicenseDetail:
    quantity: int
    start_date: str | None
    end_date: str | None
    subscription_id: str | None
    license_type: str | None


@dataclass(frozen=True, slots=True)
class LicenseSummaryItem:
    tag: str
    entitled: int
    future_entitled: int
    in_use: int
    reserved: int
    compliance_status: str
    display_name: str
    enforced: bool
    export_restricted: bool
    license_details: tuple[LicenseDetail, ...]

    @property
    def available(self) -> int:
        """Return quantity not currently in use; reserved is already in-use."""
        return max(0, self.entitled - self.in_use)


@dataclass(frozen=True, slots=True)
class LicenseSummary:
    message: str
    outstanding_reports: int
    items: tuple[LicenseSummaryItem, ...]


MAX_DISCOVERY_RECORDS = 10_000
DISCOVERY_PAGE_SIZE = 100
_RESERVATION_REQUEST_CODE = re.compile(
    r"^[A-Za-z0-9]{2}-Z(?P<pid>[A-Za-z0-9][A-Za-z0-9-]{0,127}):"
    r"(?P<device>[A-Za-z0-9]{1,128})-[A-Za-z0-9]{1,128}-[A-Za-z0-9]{2}$"
)


def _bounded_text(value: Any, *, name: str, maximum: int = 1024) -> str:
    try:
        result = validate_opaque_value(value, name=name, maximum=maximum)
    except ValueError as exc:
        raise CiscoPlrRequestError(f"Cisco response contained an invalid {name}") from exc
    if result != result.strip():
        raise CiscoPlrRequestError(f"Cisco response contained an invalid {name}")
    return result


def _path_value(value: str, *, name: str) -> str:
    return quote(_bounded_text(value, name=name), safe="")


def _response_identifier(value: Any, *, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise CiscoPlrRequestError(f"Cisco response contained an invalid {name}")
    return _bounded_text(str(value), name=name)


def _trimmed_response_text(value: Any, *, name: str, maximum: int = 1024) -> str:
    try:
        raw = validate_opaque_value(value, name=name, maximum=maximum)
        return validate_opaque_value(
            raw.strip(), name=name, maximum=maximum
        )
    except ValueError as exc:
        raise CiscoPlrRequestError(
            f"Cisco response contained an invalid {name}"
        ) from exc


class CiscoPlrReservationClient:
    """
    Send PLR reservation requests using a pre-obtained bearer token.

    Args:
        base_url:
            Root of the smart accounts and licensing API.
        bearer_token:
            Static bearer token string. If omitted, token_provider must be set.
        token_provider:
            Callable that returns a bearer token string on demand.
        timeout:
            (connect timeout, read timeout), in seconds.
        verify_certificate:
            Whether to verify TLS certificates.
        user_agent:
            Optional caller identification for requests.
    """

    def __init__(
        self,
        *,
        base_url: str = "https://swapi.cisco.com/services/api/smart-accounts-and-licensing/v3/",
        bearer_token: str | None = None,
        token_provider: Callable[[], str] | None = None,
        token_refresher: Callable[[], Any] | None = None,
        profile: CiscoLicensingApiProfile | None = None,
        timeout: tuple[float, float] = (5.0, 30.0),
        ca_bundle: str | Path | None = None,
        verify_certificate: bool = True,
        user_agent: str = "cisco-plr-reservation-client/1.0",
    ) -> None:
        if bearer_token is None and token_provider is None:
            raise ValueError("bearer_token or token_provider is required")
        if bearer_token is not None:
            bearer_token = validate_opaque_value(
                bearer_token, name="bearer_token", maximum=MAX_TOKEN_LENGTH
            )
        if token_provider is not None and not callable(token_provider):
            raise ValueError("token_provider must be callable")
        verify_certificate = validate_bool(
            verify_certificate, name="verify_certificate"
        )

        if profile is not None:
            if not isinstance(profile, CiscoLicensingApiProfile):
                raise ValueError("profile must be a CiscoLicensingApiProfile")
            base_url = profile.base_url
        self.profile = profile or CiscoLicensingApiProfile(
            name="custom", base_url=base_url
        )
        self.base_url = validate_https_base_url(base_url)
        self._bearer_token = bearer_token
        self._token_provider = token_provider
        if token_refresher is not None and not callable(token_refresher):
            raise ValueError("token_refresher must be callable")
        self._token_refresher = token_refresher
        self._timeout = validate_timeout(timeout)
        self._closed = False

        self.session: Session = requests.Session()
        if ca_bundle is not None:
            ca_path = resolve_operator_path(ca_bundle, name="ca_bundle")
            if not ca_path.is_file():
                raise FileNotFoundError(f"CA bundle not found: {ca_path}")
            self.session.verify = str(ca_path)
        else:
            self.session.verify = verify_certificate
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": validate_user_agent(user_agent),
            }
        )
        self.session.mount("https://", HTTPAdapter(max_retries=0))

    def __enter__(self) -> "CiscoPlrReservationClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _safe_error_text(response: Response, limit: int = 1000) -> str:
        try:
            body = response.json()
            text = repr(body)
        except ValueError:
            text = response.text
        return safe_error_text(text, limit=limit)

    def set_bearer_token(self, bearer_token: str) -> None:
        self._bearer_token = validate_opaque_value(
            bearer_token, name="bearer_token", maximum=MAX_TOKEN_LENGTH
        )

    def _resolve_bearer_token(self) -> str:
        if self._bearer_token:
            return self._bearer_token
        if self._token_provider is None:
            raise CiscoPlrError("No bearer token available")

        token = self._token_provider()
        try:
            return validate_opaque_value(
                token, name="token provider result", maximum=MAX_TOKEN_LENGTH
            )
        except ValueError as exc:
            raise CiscoPlrError("Token provider returned an invalid bearer token") from exc

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        self._ensure_open()
        method = validate_http_method(method)

        url = self._build_url(path)
        request_headers = validate_headers(headers)
        request_params = validate_query_params(params)
        request_body = encode_json_payload(json)
        request_headers["Authorization"] = f"Bearer {self._resolve_bearer_token()}"

        try:
            response = self.session.request(
                method,
                url,
                params=request_params,
                data=request_body,
                headers=request_headers,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            raise CiscoPlrRequestError(
                "TLS validation failed during the PLR reservation request"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise CiscoPlrRequestError(f"PLR reservation request failed: {exc}") from exc

        if response.status_code == 401 and self._token_refresher is not None:
            response.close()
            self._token_refresher()
            request_headers["Authorization"] = f"Bearer {self._resolve_bearer_token()}"
            try:
                response = self.session.request(
                    method,
                    url,
                    params=request_params,
                    data=request_body,
                    headers=request_headers,
                    timeout=self._timeout,
                    allow_redirects=False,
                )
            except requests.exceptions.SSLError as exc:
                raise CiscoPlrRequestError(
                    "TLS validation failed during the PLR reservation request"
                ) from exc
            except requests.exceptions.RequestException as exc:
                raise CiscoPlrRequestError(
                    f"PLR reservation request failed: {exc}"
                ) from exc

        if response.is_redirect:
            raise CiscoPlrRequestError(
                f"Unexpected redirect from reservation endpoint (HTTP {response.status_code})"
            )
        if not response.ok:
            raise CiscoPlrRequestError(
                f"{method} {urlparse(url).path} failed with "
                f"HTTP {response.status_code}: {self._safe_error_text(response)}"
            )
        return response

    def get_json(
        self, path: str, *, params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        response = self.request("GET", path, params=params, headers=headers)
        return self._json_response(response, "GET")

    def post_json(
        self,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        response = self.request("POST", path, params=params, json=json, headers=headers)
        return self._json_response(response, "POST")

    @staticmethod
    def _json_response(response: Response, method: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise CiscoPlrRequestError(
                f"{method} {urlparse(response.url).path} returned invalid JSON"
            ) from exc

    def list_smart_accounts(self) -> tuple[SmartAccount, ...]:
        """Return every PnP smart account visible to the OAuth principal."""
        records = self._paged_data(self.profile.smart_accounts_path)
        accounts: dict[tuple[str, str], SmartAccount] = {}
        for item in records:
            if not isinstance(item, Mapping):
                raise CiscoPlrRequestError("Smart-account response contained a non-object")
            account = SmartAccount(
                name=_bounded_text(item.get("companyName"), name="smart-account name"),
                domain=_bounded_text(item.get("domainIdentifier"), name="smart-account domain"),
                account_id=_response_identifier(
                    item.get("accountIdentifier"), name="smart-account id"
                ),
            )
            accounts[(account.domain.casefold(), account.account_id)] = account
        return tuple(sorted(accounts.values(), key=lambda item: (item.name.casefold(), item.domain.casefold())))

    def list_virtual_accounts(
        self, smart_account: SmartAccount
    ) -> tuple[VirtualAccount, ...]:
        """Return every PnP virtual account visible beneath one smart account."""
        if not isinstance(smart_account, SmartAccount):
            raise ValueError("smart_account must be a SmartAccount")
        path = self.profile.virtual_accounts_path_template.format(
            smart_account_domain=_path_value(
                smart_account.domain, name="smart-account domain"
            )
        )
        records = self._paged_data(path)
        accounts: dict[tuple[str, str], VirtualAccount] = {}
        for item in records:
            if not isinstance(item, Mapping):
                raise CiscoPlrRequestError("Virtual-account response contained a non-object")
            raw_default = item.get("default", "false")
            if isinstance(raw_default, bool):
                is_default = raw_default
            elif isinstance(raw_default, str) and raw_default.lower() in {"true", "false"}:
                is_default = raw_default.lower() == "true"
            else:
                raise CiscoPlrRequestError(
                    "Cisco response contained an invalid virtual-account default flag"
                )
            account = VirtualAccount(
                name=_bounded_text(item.get("virtualAccountName"), name="virtual-account name"),
                account_id=_response_identifier(
                    item.get("virtualAccountId"), name="virtual-account id"
                ),
                is_default=is_default,
            )
            accounts[(account.name.casefold(), account.account_id)] = account
        return tuple(sorted(accounts.values(), key=lambda item: (not item.is_default, item.name.casefold())))

    def _paged_data(self, path: str) -> tuple[Mapping[str, Any], ...]:
        start = 0
        records: list[Mapping[str, Any]] = []
        while True:
            result = self.get_json(
                path,
                params={"startIdx": start, "rowsPerPage": DISCOVERY_PAGE_SIZE},
            )
            if not isinstance(result, Mapping) or not isinstance(result.get("data"), list):
                raise CiscoPlrRequestError("Cisco discovery response must contain a data list")
            page = result["data"]
            if not all(isinstance(item, Mapping) for item in page):
                raise CiscoPlrRequestError("Cisco discovery response contained a non-object")
            records.extend(page)
            if len(records) > MAX_DISCOVERY_RECORDS:
                raise CiscoPlrRequestError("Cisco discovery response exceeded the record limit")
            total = result.get("totalRows")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise CiscoPlrRequestError("Cisco discovery response contained invalid pagination")
            if len(records) >= total:
                return tuple(records)
            if not page:
                raise CiscoPlrRequestError("Cisco discovery pagination ended before totalRows")
            start += len(page)

    def search_slr_entitlements(
        self, software_tags: tuple[str, ...]
    ) -> tuple[SlrEntitlement, ...]:
        """Map software tags to reservation entitlement tags."""
        if not software_tags:
            raise ValueError("software_tags must not be empty")
        tags = [_bounded_text(tag, name="software tag", maximum=4096) for tag in software_tags]
        result = self.post_json(self.profile.slr_details_path, json={"softwareTags": tags})
        if not isinstance(result, Mapping) or result.get("status") != "SUCCESS" or not isinstance(result.get("data"), list):
            raise CiscoPlrRequestError("SLR details response was not successful")
        found: list[SlrEntitlement] = []
        for mapping in result["data"]:
            if not isinstance(mapping, Mapping) or not isinstance(mapping.get("entitlements"), list):
                raise CiscoPlrRequestError("SLR details response contained invalid data")
            software_tag = _bounded_text(mapping.get("softwareTag"), name="software tag", maximum=4096)
            for item in mapping["entitlements"]:
                if not isinstance(item, Mapping):
                    raise CiscoPlrRequestError("SLR details contained an invalid entitlement")
                found.append(SlrEntitlement(
                    software_tag=software_tag,
                    entitlement_tag=_bounded_text(item.get("entitlementTag"), name="entitlement tag", maximum=4096),
                    reservation_type=_bounded_text(item.get("type"), name="reservation type", maximum=32),
                ))
        return tuple(found)

    def get_license_summary(
        self,
        selection: AccountSelection,
        *,
        tags: tuple[str, ...] = (),
        requesting_system: Mapping[str, str] | None = None,
    ) -> LicenseSummary:
        """Return a validated point-in-time license summary for one virtual account."""
        if not isinstance(selection, AccountSelection):
            raise ValueError("selection must be an AccountSelection")
        clean_tags = [
            _bounded_text(tag, name="license tag", maximum=4096) for tag in tags
        ]
        system = dict(requesting_system or {"display_name": "FDM_Client"})
        if not system or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in system.items()
        ):
            raise ValueError("requesting_system must contain string keys and values")
        nonce = secrets.token_urlsafe(18)
        result = self.post_json(
            self.profile.license_summary_path,
            headers={
                "X-CSW-REQUESTING-SYSTEM": json.dumps(
                    system, separators=(",", ":"), sort_keys=True
                ),
                "X-CSW-SMART-ACCOUNT-ID": selection.smart_account.account_id,
                "X-CSW-VIRTUAL-ACCOUNT-ID": selection.virtual_account.account_id,
            },
            json={
                "data": {
                    "timestamp": int(time.time() * 1000),
                    "nonce": nonce,
                    "tags": clean_tags,
                }
            },
        )
        return self._parse_license_summary(result, nonce)

    @staticmethod
    def _parse_license_summary(result: Any, nonce: str) -> LicenseSummary:
        if not isinstance(result, Mapping) or result.get("status") != "SUCCESS":
            raise CiscoPlrRequestError("License-summary response was not successful")
        if result.get("nonce") != nonce:
            raise CiscoPlrRequestError("License-summary response nonce did not match")
        outstanding = result.get("out_standing_reports")
        entries = result.get("summary")
        if (
            isinstance(outstanding, bool)
            or not isinstance(outstanding, int)
            or outstanding < 0
            or not isinstance(entries, list)
        ):
            raise CiscoPlrRequestError("License-summary response contained invalid data")

        def integer(item: Mapping[str, Any], key: str) -> int:
            value = item.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CiscoPlrRequestError(
                    "License-summary response contained an invalid quantity"
                )
            return value

        def optional_text(value: Any, name: str) -> str | None:
            if value is None:
                return None
            return _bounded_text(value, name=name, maximum=1024)

        parsed: list[LicenseSummaryItem] = []
        for entry in entries:
            if not isinstance(entry, Mapping) or not isinstance(
                entry.get("license_details"), list
            ):
                raise CiscoPlrRequestError(
                    "License-summary response contained an invalid item"
                )
            details: list[LicenseDetail] = []
            for detail in entry["license_details"]:
                if not isinstance(detail, Mapping):
                    raise CiscoPlrRequestError(
                        "License-summary response contained an invalid detail"
                    )
                details.append(
                    LicenseDetail(
                        quantity=integer(detail, "quantity"),
                        start_date=optional_text(detail.get("start_date"), "start date"),
                        end_date=optional_text(detail.get("end_date"), "end date"),
                        subscription_id=optional_text(
                            detail.get("subscription_id"), "subscription id"
                        ),
                        license_type=optional_text(
                            detail.get("license_type"), "license type"
                        ),
                    )
                )
            enforced = entry.get("enforced")
            export_restricted = entry.get("export_restricted")
            if not isinstance(enforced, bool) or not isinstance(export_restricted, bool):
                raise CiscoPlrRequestError(
                    "License-summary response contained an invalid restriction flag"
                )
            parsed.append(
                LicenseSummaryItem(
                    tag=_bounded_text(entry.get("tag"), name="license tag", maximum=4096),
                    entitled=integer(entry, "entitled"),
                    future_entitled=integer(entry, "future_entitled"),
                    in_use=integer(entry, "inuse"),
                    reserved=integer(entry, "reserved"),
                    compliance_status=_bounded_text(
                        entry.get("compliance_status"), name="compliance status"
                    ),
                    display_name=_bounded_text(
                        entry.get("display_name"), name="license display name"
                    ),
                    enforced=enforced,
                    export_restricted=export_restricted,
                    license_details=tuple(details),
                )
            )
        message = result.get("message")
        if message is None:
            message = ""
        elif message:
            message = _bounded_text(message, name="license-summary message")
        return LicenseSummary(message, outstanding, tuple(parsed))

    @staticmethod
    def reservation_request_identity(
        reservation_code: str,
    ) -> ReservationRequestIdentity:
        """Extract only the documented visible PID and device identifier."""
        reservation_code = _bounded_text(
            reservation_code, name="PLR reservation code", maximum=16_384
        )
        match = _RESERVATION_REQUEST_CODE.fullmatch(reservation_code)
        if match is None:
            raise ValueError("PLR reservation code has an unsupported format")
        return ReservationRequestIdentity(
            product_id=match.group("pid"),
            device_identifier=match.group("device"),
        )

    def preflight_universal_plr(
        self, selection: AccountSelection, reservation_code: str
    ) -> ReservationPreflight:
        """Check for an existing product instance without creating a reservation."""
        if not isinstance(selection, AccountSelection):
            raise ValueError("selection must be an AccountSelection")
        identity = self.reservation_request_identity(reservation_code)
        path = self.profile.product_instances_path_template.format(
            smart_account_domain=_path_value(
                selection.smart_account.domain, name="smart-account domain"
            )
        )
        result = self.get_json(
            path,
            params={
                "virtualAccountName": selection.virtual_account.name,
                "instanceName": identity.device_identifier,
                "limit": 50,
                "offset": 0,
            },
        )
        instances = self._product_instances(result)
        matches = tuple(
            item
            for item in instances
            if item.product_id == identity.product_id
            and item.serial_number == identity.device_identifier
        )
        if len(matches) > 1:
            raise CiscoPlrRequestError(
                "Cisco returned multiple matching product instances"
            )
        return ReservationPreflight(
            identity=identity,
            existing_instance=matches[0] if matches else None,
        )

    def preflight_plr_return(
        self, selection: AccountSelection, serial_number: str
    ) -> ProductInstance:
        """Find exactly one CSSM product instance by its FTD-reported serial."""
        if not isinstance(selection, AccountSelection):
            raise ValueError("selection must be an AccountSelection")
        serial_number = _bounded_text(
            serial_number, name="device serial number", maximum=128
        )
        path = self.profile.product_instances_path_template.format(
            smart_account_domain=_path_value(
                selection.smart_account.domain, name="smart-account domain"
            )
        )
        result = self.get_json(
            path,
            params={
                "virtualAccountName": selection.virtual_account.name,
                "instanceName": serial_number,
                "limit": 50,
                "offset": 0,
            },
        )
        matches = tuple(
            item for item in self._product_instances(result)
            if item.serial_number == serial_number
        )
        if len(matches) != 1:
            raise CiscoPlrRequestError(
                "Cisco must return exactly one product instance matching the FTD serial number"
            )
        return matches[0]

    def locate_product_instance(self, serial_number: str) -> ProductInstanceLocation:
        """Globally locate one accessible product instance and its owning accounts."""
        serial_number = _bounded_text(
            serial_number, name="device serial number", maximum=128
        )
        result = self.get_json(
            self.profile.device_search_path,
            params={"udi_serial_number": serial_number},
            headers={"X-CSW-REQUESTING-SYSTEM": '{"display_name":"FDM_Client"}'},
        )
        if not isinstance(result, Mapping) or result.get("status") not in {
            "COMPLETE", "OK"
        }:
            raise CiscoPlrRequestError("Global device-search response was not successful")
        raw_data = result.get("data")
        if isinstance(raw_data, Mapping):
            records = [raw_data]
        elif isinstance(raw_data, list):
            records = raw_data
        else:
            raise CiscoPlrRequestError("Global device-search response contained invalid data")
        matches: list[ProductInstanceLocation] = []
        for item in records:
            if not isinstance(item, Mapping) or not isinstance(item.get("sudi"), Mapping) or not isinstance(item.get("account"), Mapping):
                raise CiscoPlrRequestError("Global device search returned invalid data")
            sudi = item["sudi"]
            account = item["account"]
            returned_serial = _bounded_text(
                sudi.get("udiSerialNumber"), name="device serial number", maximum=128
            )
            if returned_serial != serial_number:
                continue
            is_default = account.get("default")
            if not isinstance(is_default, bool):
                raise CiscoPlrRequestError("Global device search returned an invalid default flag")
            smart = SmartAccount(
                name=_bounded_text(account.get("name"), name="smart-account name"),
                domain=_bounded_text(account.get("domain"), name="smart-account domain"),
                account_id=_response_identifier(account.get("account_id"), name="smart-account id"),
            )
            virtual = VirtualAccount(
                name=_bounded_text(account.get("virtual_account_name"), name="virtual-account name"),
                account_id=_response_identifier(account.get("virtual_account_id"), name="virtual-account id"),
                is_default=is_default,
            )
            instance = ProductInstance(
                instance_name=returned_serial,
                product_tag=_bounded_text(item.get("software_tag"), name="product tag", maximum=4096),
                product_id=_bounded_text(sudi.get("udiPid"), name="product identifier", maximum=128),
                serial_number=returned_serial,
            )
            matches.append(ProductInstanceLocation(AccountSelection(smart, virtual), instance))
        if len(matches) != 1:
            raise CiscoPlrRequestError(
                "Cisco must return exactly one globally accessible product instance matching the FTD serial number"
            )
        return matches[0]

    def product_instance_exists(
        self, selection: AccountSelection, instance: ProductInstance
    ) -> bool:
        """Check whether one exact product instance remains in the selected VA."""
        if not isinstance(selection, AccountSelection):
            raise ValueError("selection must be an AccountSelection")
        if not isinstance(instance, ProductInstance):
            raise ValueError("instance must be a ProductInstance")
        path = self.profile.product_instances_path_template.format(
            smart_account_domain=_path_value(
                selection.smart_account.domain, name="smart-account domain"
            )
        )
        result = self.get_json(
            path,
            params={
                "virtualAccountName": selection.virtual_account.name,
                "instanceName": instance.serial_number,
                "limit": 50,
                "offset": 0,
            },
        )
        return any(
            item.product_id == instance.product_id
            and item.serial_number == instance.serial_number
            and item.product_tag == instance.product_tag
            for item in self._product_instances(result)
        )

    @staticmethod
    def _product_instances(result: Any) -> tuple[ProductInstance, ...]:
        if (
            not isinstance(result, Mapping)
            or result.get("status") != "SUCCESS"
            or not isinstance(result.get("devices"), list)
        ):
            raise CiscoPlrRequestError(
                "Product-instance search response was not successful"
            )
        parsed: list[ProductInstance] = []
        for item in result["devices"]:
            if not isinstance(item, Mapping) or not isinstance(item.get("sudi"), Mapping):
                raise CiscoPlrRequestError(
                    "Product-instance search returned invalid device data"
                )
            sudi = item["sudi"]
            parsed.append(
                ProductInstance(
                    instance_name=_trimmed_response_text(
                        item.get("instanceName"), name="product-instance name"
                    ),
                    product_tag=_bounded_text(
                        item.get("productTagName"),
                        name="product tag",
                        maximum=4096,
                    ),
                    product_id=_bounded_text(
                        sudi.get("udiPid"), name="product identifier"
                    ),
                    serial_number=_bounded_text(
                        sudi.get("udiSerialNumber"), name="device serial number"
                    ),
                )
            )
        return tuple(parsed)

    def reserve_universal_plr(
        self, selection: AccountSelection, reservation_code: str
    ) -> PlrAuthorization:
        """Preflight and submit one OpenAPI-defined Universal PLR reservation."""
        if not isinstance(selection, AccountSelection):
            raise ValueError("selection must be an AccountSelection")
        reservation_code = _bounded_text(
            reservation_code, name="PLR reservation code", maximum=16_384
        )
        preflight = self.preflight_universal_plr(selection, reservation_code)
        if preflight.existing_instance is not None:
            raise ExistingProductInstanceError(preflight.existing_instance)
        path = self.profile.reserve_path_template.format(
            smart_account_domain=_path_value(selection.smart_account.domain, name="smart-account domain"),
            virtual_account_name=_path_value(selection.virtual_account.name, name="virtual-account name"),
        )
        result = self.post_json(path, json={"reservationRequests": [{
            "reservationCode": reservation_code,
            "reservationType": "UNIVERSAL",
        }]})
        return self._parse_universal_authorization(result, reservation_code)

    def return_universal_plr(
        self,
        selection: AccountSelection,
        instance: ProductInstance,
        return_code: str,
    ) -> PlrReturnResult:
        """Submit one FDM-generated return code to the v3 removal endpoint."""
        if not isinstance(selection, AccountSelection):
            raise ValueError("selection must be an AccountSelection")
        if not isinstance(instance, ProductInstance):
            raise ValueError("instance must be a ProductInstance")
        product_id = _bounded_text(
            instance.product_id, name="product identifier", maximum=128
        )
        serial_number = _bounded_text(
            instance.serial_number, name="device serial number", maximum=128
        )
        product_tag = _bounded_text(
            instance.product_tag, name="product tag", maximum=4096
        )
        return_code = _bounded_text(
            return_code, name="PLR return code", maximum=16_384
        )
        path = self.profile.return_path_template.format(
            smart_account_domain=_path_value(
                selection.smart_account.domain, name="smart-account domain"
            )
        )
        result = self.post_json(
            path,
            params={"virtualAccountName": selection.virtual_account.name},
            json={
                "productInstancesRemoveRequests": [
                    {
                        "sudi": {
                            "udiPid": product_id,
                            "udiSerialNumber": serial_number,
                        },
                        "productTagName": product_tag,
                        "returnCode": return_code,
                    }
                ]
            },
        )
        return self._parse_plr_return(result)

    @staticmethod
    def _parse_plr_return(result: Any) -> PlrReturnResult:
        if not isinstance(result, Mapping) or result.get("status") != "SUCCESS":
            raise CiscoPlrRequestError("PLR return response was not successful")
        entries = result.get("removeProductInstancesStatus")
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], Mapping):
            raise CiscoPlrRequestError(
                "PLR return response must contain exactly one product-instance result"
            )
        entry = entries[0]
        status = _bounded_text(entry.get("status"), name="PLR return status", maximum=32)
        if status != "SUCCESS":
            raise CiscoPlrRequestError("Cisco did not remove the PLR product instance")
        return PlrReturnResult(
            status=status,
            message=_trimmed_response_text(
                entry.get("statusMessage"), name="PLR return message"
            ),
            device=_trimmed_response_text(
                entry.get("device"), name="PLR return device"
            ),
        )

    @staticmethod
    def _parse_universal_authorization(result: Any, reservation_code: str) -> PlrAuthorization:
        if not isinstance(result, Mapping) or result.get("status") != "SUCCESS":
            raise CiscoPlrRequestError("PLR reservation response was not successful")
        entries = result.get("authorizationCodes")
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], Mapping):
            raise CiscoPlrRequestError("PLR reservation response must contain exactly one authorization result")
        entry = entries[0]
        returned_code = _bounded_text(entry.get("reservationCode"), name="returned reservation code", maximum=16_384)
        if returned_code != reservation_code:
            raise CiscoPlrRequestError("PLR reservation response did not match the submitted request")
        status = _bounded_text(entry.get("status"), name="authorization status", maximum=32)
        if status != "SUCCESS":
            raise CiscoPlrRequestError("PLR authorization result was not successful")
        try:
            authorization_code = validate_plr_authorization_code(
                entry.get("authorizationCode")
            )
        except ValueError as exc:
            raise CiscoPlrRequestError(
                "PLR reservation response contained an invalid authorization code"
            ) from exc
        return PlrAuthorization(authorization_code, returned_code, status)

    def reserve_licenses(
        self,
        path: str,
        *,
        payload: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """
        Submit the PLR reservation request.

        The exact payload is Cisco-endpoint-specific, so the caller supplies the
        request body directly.
        """
        if not isinstance(payload, Mapping) or not payload:
            raise ValueError("payload must be a non-empty mapping")
        return self.post_json(path, json=dict(payload), headers=headers)

    def exchange_plr_request_code(
        self,
        path: str,
        *,
        payload: Mapping[str, Any],
        authorization_code_field: str = "authorizationCode",
        headers: Mapping[str, str] | None = None,
    ) -> str:
        """Submit one endpoint-specific reservation and return its authorization code.

        Cisco does not publish one universal CSSM PLR route and payload for all
        entitled API clients. The approved route and complete payload therefore
        remain explicit caller inputs. This method performs exactly one POST.
        """
        authorization_code_field = validate_opaque_value(
            authorization_code_field,
            name="authorization_code_field",
            maximum=128,
        )
        result = self.reserve_licenses(path, payload=payload, headers=headers)
        if not isinstance(result, Mapping):
            raise CiscoPlrRequestError("PLR reservation response must be an object")
        try:
            return validate_opaque_value(
                result[authorization_code_field],
                name="PLR authorization code",
                maximum=16_384,
            )
        except (KeyError, ValueError) as exc:
            raise CiscoPlrRequestError(
                "PLR reservation response did not contain a valid authorization code"
            ) from exc

    def close(self) -> None:
        if self._closed:
            return
        self.session.close()
        self._closed = True

    def _build_url(self, path: str) -> str:
        normalized = validate_relative_api_path(path)
        url = urljoin(self.base_url, normalized)

        base = urlparse(self.base_url)
        target = urlparse(url)
        if (target.scheme, target.netloc) != (base.scheme, base.netloc):
            raise ValueError("Request path escaped the configured Cisco origin")
        if not target.path.startswith(base.path):
            raise ValueError("Request path escaped the configured Cisco API root")
        return url

    def _ensure_open(self) -> None:
        if self._closed:
            raise CiscoPlrError("CiscoPlrReservationClient is closed")
