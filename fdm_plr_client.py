"""Atomic Universal Permanent License Reservation operations for FDM."""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from typing import Any, Mapping
from urllib.parse import urlparse

from fdm_client import FDMClient, FDMRequestError
from security_validation import validate_opaque_value, validate_plr_authorization_code


MAX_PLR_CODE_LENGTH = 16_384


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


@dataclass(frozen=True, slots=True)
class PlrReturnCode:
    """Sensitive return-code handoff produced by cancelling FDM reservation."""

    code: str = dataclass_field(repr=False)
    object_id: str | None = None


@dataclass(frozen=True, slots=True)
class FdmPlrReturnIdentity:
    serial_number: str
    platform_model: str
    registration_status: str


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

    def get_return_identity(self, *, allow_pending: bool = False) -> FdmPlrReturnIdentity:
        """Validate installed UPLR state and return stable device identity."""
        statuses = self._validated_items(
            self._fdm.get_json("license/smartagentstatuses"),
            operation="Smart Agent status list",
        )
        if len(statuses) != 1:
            raise FdmPlrError("FDM must expose exactly one Smart Agent status")
        status = statuses[0]
        registration = status.get("registrationStatus")
        authorization = status.get("authorizationStatus")
        authorized = registration == "UNIVERSAL_PLR" and authorization == "AUTHORIZED"
        pending = (
            registration == "PLR_DEACTIVATION_IN_PROGRESS"
            and authorization == "NOT_AUTHORIZED"
        )
        if not authorized and not (allow_pending and pending):
            raise FdmPlrError(
                "FDM is neither authorized with Universal PLR nor in a supported pending-return state"
            )
        system = self._fdm.system_information
        if not isinstance(system, Mapping):
            raise FdmPlrError("FDM system information must be an object")
        try:
            return FdmPlrReturnIdentity(
                serial_number=validate_opaque_value(
                    system["serialNumber"], name="FTD serial number", maximum=128
                ),
                platform_model=validate_opaque_value(
                    system["platformModel"], name="FTD platform model", maximum=256
                ),
                registration_status=registration,
            )
        except (KeyError, ValueError) as exc:
            raise FdmPlrError("FDM returned invalid device identity") from exc

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
        authorization_code = validate_plr_authorization_code(authorization_code)
        response = self._post_json(
            self._profile.install_plr_code_path,
            {"type": "PLRAuthorizationCode", "code": authorization_code},
        )
        return PlrInstallResult(response=response)

    def generate_return_code(self) -> PlrReturnCode:
        """Cancel the installed reservation once and return its CSSM handoff code."""
        self.get_return_identity()
        response = self._post_json(
            self._profile.cancel_plr_reservation_path,
            {"type": "PLRReleaseCode"},
        )
        try:
            code = validate_opaque_value(
                response["code"], name="PLR return code", maximum=MAX_PLR_CODE_LENGTH
            )
            object_id = response.get("id")
            if object_id is not None:
                object_id = validate_opaque_value(
                    object_id, name="PLR return-code id", maximum=256
                )
        except (KeyError, ValueError) as exc:
            raise FdmPlrError("FDM returned an invalid PLR return-code object") from exc
        response_type = response.get("type")
        if response_type is not None:
            try:
                validate_opaque_value(
                    response_type, name="PLR return-code type", maximum=128
                )
            except ValueError as exc:
                raise FdmPlrError(
                    "FDM returned an invalid PLR return-code type"
                ) from exc
        return PlrReturnCode(code=code, object_id=object_id)

    def finalize_return(self) -> None:
        """Delete the sole Smart Agent connection after CSSM accepts the return."""
        identity = self.get_return_identity(allow_pending=True)
        if identity.registration_status != "PLR_DEACTIVATION_IN_PROGRESS":
            raise FdmPlrError("FDM is not waiting for PLR return completion")
        connections = self.list_smart_agent_connections()
        if len(connections) != 1:
            raise FdmPlrError("FDM must expose exactly one Smart Agent connection")
        try:
            connection_id = validate_opaque_value(
                connections[0]["id"], name="Smart Agent connection id", maximum=256
            )
        except (KeyError, ValueError) as exc:
            raise FdmPlrError("FDM returned an invalid Smart Agent connection") from exc
        response = self._fdm.request(
            "DELETE", f"{self._profile.smart_agent_connections_path}/{connection_id}"
        )
        response.close()

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
