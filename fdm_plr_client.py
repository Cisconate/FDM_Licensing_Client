"""Atomic Universal Permanent License Reservation operations for FDM."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

from fdm_client import FDMClient, FDMRequestError
from security_validation import validate_opaque_value


MAX_PLR_CODE_LENGTH = 16_384
_UPLR_AUTHORIZATION_CODE = re.compile(r"^[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{6}){5}$")


class FdmPlrError(RuntimeError):
    """FDM returned an invalid PLR result or the requested state was ambiguous."""


@dataclass(frozen=True, slots=True)
class PlrRequestCode:
    """Validated PLR request-code handoff artifact returned by FDM."""

    code: str
    object_id: str | None = None


@dataclass(frozen=True, slots=True)
class PlrInstallResult:
    """Non-secret metadata returned after installing an authorization code."""

    response: Mapping[str, Any]


class FdmPlrClient:
    """Perform individual Universal PLR operations through an authenticated FDM client.

    The class does not own or close ``fdm``. It deliberately does not chain
    operations: callers decide when to cross each state-changing boundary.
    """

    def __init__(self, fdm: FDMClient) -> None:
        if not isinstance(fdm, FDMClient):
            raise TypeError("fdm must be an FDMClient")
        self._fdm = fdm
        self._profile = fdm.require_api_profile()

    def list_smart_agent_connections(self) -> tuple[Mapping[str, Any], ...]:
        """Return current Smart Agent connection objects without changing state."""
        data = self._fdm.get_json(self._profile.smart_agent_connections_path)
        return self._validated_items(data, operation="Smart Agent connection list")

    def create_universal_plr_connection(self) -> Mapping[str, Any]:
        """Create a Smart Agent connection in Universal PLR mode."""
        return self._post_json(
            self._profile.smart_agent_connections_path,
            {"type": "smartagentconnection", "connectionType": "UNIVERSAL_PLR"},
        )

    def update_connection_to_universal_plr(
        self,
        *,
        connection_id: str,
        version: str,
        performance_tier: str | None = None,
    ) -> Mapping[str, Any]:
        """Update one existing Smart Agent connection to Universal PLR mode."""
        connection_id = validate_opaque_value(
            connection_id, name="connection_id", maximum=256
        )
        version = validate_opaque_value(version, name="version", maximum=256)
        payload: dict[str, Any] = {
            "id": connection_id,
            "version": version,
            "type": "smartagentconnection",
            "connectionType": "UNIVERSAL_PLR",
        }
        if performance_tier is not None:
            payload["performanceTier"] = validate_opaque_value(
                performance_tier, name="performance_tier", maximum=256
            )
        return self._put_json(
            f"{self._profile.smart_agent_connections_path}/{connection_id}", payload
        )

    def list_plr_request_codes(self) -> tuple[PlrRequestCode, ...]:
        """Retrieve all current PLR request-code objects without changing state."""
        data = self._fdm.get_json(self._profile.plr_request_codes_path)
        items = self._validated_items(data, operation="PLR request-code list")
        return tuple(self._request_code(item) for item in items)

    def get_plr_request_code(self, object_id: str) -> PlrRequestCode:
        """Retrieve one PLR request-code object by its FDM identifier."""
        object_id = validate_opaque_value(object_id, name="object_id", maximum=256)
        data = self._fdm.get_json(f"{self._profile.plr_request_codes_path}/{object_id}")
        if not isinstance(data, Mapping):
            raise FdmPlrError("PLR request-code response must be an object")
        return self._request_code(data)

    def install_authorization_code(self, authorization_code: str) -> PlrInstallResult:
        """Install one CSSM-issued Universal PLR authorization code on FDM."""
        authorization_code = validate_opaque_value(
            authorization_code,
            name="authorization_code",
            maximum=MAX_PLR_CODE_LENGTH,
        )
        if not _UPLR_AUTHORIZATION_CODE.fullmatch(authorization_code):
            raise ValueError(
                "authorization_code must contain six groups of six alphanumeric characters"
            )
        response = self._post_json(
            self._profile.install_plr_code_path,
            {"type": "PLRAuthorizationCode", "code": authorization_code},
        )
        return PlrInstallResult(response=response)

    def _post_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._response_json(self._fdm.request("POST", path, json=payload), "POST")

    def _put_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._response_json(self._fdm.request("PUT", path, json=payload), "PUT")

    @staticmethod
    def _response_json(response: Any, method: str) -> Mapping[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            path = urlparse(getattr(response, "url", "")).path
            raise FDMRequestError(f"{method} {path} returned invalid JSON") from exc
        if not isinstance(data, Mapping):
            raise FdmPlrError(f"{method} PLR response must be an object")
        return dict(data)

    @staticmethod
    def _validated_items(
        data: Any, *, operation: str
    ) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(data, Mapping) or not isinstance(data.get("items"), list):
            raise FdmPlrError(f"{operation} response must contain an items list")
        if not all(isinstance(item, Mapping) for item in data["items"]):
            raise FdmPlrError(f"{operation} contained a non-object item")
        return tuple(dict(item) for item in data["items"])

    @staticmethod
    def _request_code(item: Mapping[str, Any]) -> PlrRequestCode:
        try:
            code = validate_opaque_value(
                item["code"], name="PLR request code", maximum=MAX_PLR_CODE_LENGTH
            )
            object_id = item.get("id")
            if object_id is not None:
                object_id = validate_opaque_value(
                    object_id, name="PLR request-code id", maximum=256
                )
        except (KeyError, ValueError) as exc:
            raise FdmPlrError("FDM returned an invalid PLR request-code object") from exc
        return PlrRequestCode(code=code, object_id=object_id)
