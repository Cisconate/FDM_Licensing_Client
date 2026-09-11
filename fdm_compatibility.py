"""FTD software-version detection and API route selection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from security_validation import validate_opaque_value


SYSTEM_INFORMATION_PATH = "operational/systeminfo/default"
_SOFTWARE_VERSION = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:[-.]?(?P<build>\d+))?$"
)


class FdmCompatibilityError(RuntimeError):
    """The device version cannot be identified or is not supported."""


class JsonReader(Protocol):
    def get_json(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class FtdSoftwareVersion:
    raw: str
    major: int
    minor: int
    patch: int
    build: int | None


@dataclass(frozen=True, slots=True)
class FdmApiProfile:
    """Version-scoped routes used by supported FDM capabilities."""

    name: str
    major: int
    minor: int
    smart_agent_connections_path: str
    plr_request_codes_path: str
    install_plr_code_path: str
    cancel_plr_reservation_path: str

    def supports(self, version: FtdSoftwareVersion) -> bool:
        return (version.major, version.minor) == (self.major, self.minor)


FTD_7_6_PROFILE = FdmApiProfile(
    name="FTD 7.6",
    major=7,
    minor=6,
    smart_agent_connections_path="license/smartagentconnections",
    plr_request_codes_path="license/operational/plrrequestcode",
    install_plr_code_path="license/action/installplrcode",
    cancel_plr_reservation_path="license/action/cancelreservation",
)
SUPPORTED_FDM_PROFILES: tuple[FdmApiProfile, ...] = (FTD_7_6_PROFILE,)


@dataclass(frozen=True, slots=True)
class FdmCompatibility:
    software_version: FtdSoftwareVersion
    profile: FdmApiProfile
    system_information: Mapping[str, Any]


def parse_software_version(value: object) -> FtdSoftwareVersion:
    try:
        raw = validate_opaque_value(value, name="softwareVersion", maximum=128)
    except ValueError as exc:
        raise FdmCompatibilityError(
            "FDM system information returned an invalid softwareVersion"
        ) from exc
    match = _SOFTWARE_VERSION.fullmatch(raw)
    if match is None:
        raise FdmCompatibilityError(f"Unsupported FTD software version format: {raw}")
    return FtdSoftwareVersion(
        raw=raw,
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")),
        build=int(match.group("build")) if match.group("build") else None,
    )


def detect_fdm_compatibility(client: JsonReader) -> FdmCompatibility:
    """Read authenticated system information and select one supported profile."""
    data = client.get_json(SYSTEM_INFORMATION_PATH)
    if not isinstance(data, Mapping):
        raise FdmCompatibilityError("FDM system information response must be an object")
    version = parse_software_version(data.get("softwareVersion"))
    for profile in SUPPORTED_FDM_PROFILES:
        if profile.supports(version):
            return FdmCompatibility(version, profile, dict(data))
    supported = ", ".join(f"{item.major}.{item.minor}.x" for item in SUPPORTED_FDM_PROFILES)
    raise FdmCompatibilityError(
        f"FTD {version.raw} is unsupported; supported releases: {supported}"
    )
