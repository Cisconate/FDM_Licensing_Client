"""Static capability metadata used to construct CLI and GUI navigation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CapabilityCategory(str, Enum):
    WORKFLOW = "Licensing Workflow"
    FDM = "FTD / FDM"
    CISCO = "Cisco Internet Services"


class OperationRisk(str, Enum):
    LOCAL = "local"
    AUTHENTICATION = "authentication"
    READ_ONLY = "read-only"
    MUTATING = "mutating"


@dataclass(frozen=True, slots=True)
class Capability:
    id: str
    category: CapabilityCategory
    title: str
    description: str
    risk: OperationRisk
    page_key: str
    available: bool = True


@dataclass(frozen=True, slots=True)
class WorkflowOperation:
    """Presentation-neutral metadata for one operator-visible workflow step."""

    id: str
    title: str
    risk: OperationRisk
    handler: str
    requires: tuple[str, ...] = ()


FTD_LICENSING_OPERATIONS: tuple[WorkflowOperation, ...] = (
    WorkflowOperation(
        "bootstrap", "Bootstrap / refresh certificate", OperationRisk.AUTHENTICATION,
        "_bootstrap_certificate", ("connection",),
    ),
    WorkflowOperation(
        "inspect", "Inspect FDM", OperationRisk.READ_ONLY, "_inspect", ("connection",),
    ),
    WorkflowOperation(
        "request_code", "Configure PLR", OperationRisk.MUTATING,
        "_generate_request_code", ("inspection",),
    ),
    WorkflowOperation(
        "reserve", "Select account and reserve", OperationRisk.MUTATING,
        "_start_reservation", ("request_code",),
    ),
    WorkflowOperation(
        "install", "Install authorization code", OperationRisk.MUTATING,
        "_install", ("inspection", "authorization_code"),
    ),
    WorkflowOperation(
        "return", "Return PLR", OperationRisk.MUTATING, "_start_return", ("inspection",),
    ),
)


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        id="workflow.ftd-licensing",
        category=CapabilityCategory.WORKFLOW,
        title="FTD Licensing Workflow",
        description="Guide the device-to-Cisco-to-device licensing sequence.",
        risk=OperationRisk.LOCAL,
        page_key="workflow",
    ),
    Capability(
        id="fdm.connection",
        category=CapabilityCategory.FDM,
        title="FDM Connection",
        description="Bootstrap certificate trust and validate FDM authentication.",
        risk=OperationRisk.AUTHENTICATION,
        page_key="fdm",
    ),
    Capability(
        id="cisco.credentials",
        category=CapabilityCategory.CISCO,
        title="Credential Management",
        description="Manage Cisco API and default FDM credentials in the OS vault.",
        risk=OperationRisk.LOCAL,
        page_key="credentials",
    ),
    Capability(
        id="cisco.oauth",
        category=CapabilityCategory.CISCO,
        title="Cisco Authentication",
        description="Validate Cisco OAuth client credentials with a live token request.",
        risk=OperationRisk.AUTHENTICATION,
        page_key="cisco_auth",
    ),
    Capability(
        id="cisco.accounts",
        category=CapabilityCategory.CISCO,
        title="Cisco Account Selection",
        description="Discover and select accessible smart and virtual accounts.",
        risk=OperationRisk.READ_ONLY,
        page_key="cisco_accounts",
    ),
)


def capabilities_by_category() -> dict[CapabilityCategory, tuple[Capability, ...]]:
    return {
        category: tuple(item for item in CAPABILITIES if item.category == category)
        for category in CapabilityCategory
    }


def get_capability(capability_id: str) -> Capability:
    for capability in CAPABILITIES:
        if capability.id == capability_id:
            return capability
    raise KeyError(f"Unknown capability: {capability_id}")
