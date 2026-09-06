"""Validated immutable commands and presentation-safe application results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from security_validation import (
    MAX_CREDENTIAL_LENGTH,
    resolve_operator_path,
    validate_api_version,
    validate_host,
    validate_opaque_value,
    validate_port,
)


@dataclass(frozen=True, slots=True)
class CiscoCredentialsCommand:
    client_id: str
    client_secret: str

    @classmethod
    def from_untrusted(
        cls, client_id: str, client_secret: str
    ) -> "CiscoCredentialsCommand":
        normalized_id = validate_opaque_value(
            client_id, name="client_id", maximum=MAX_CREDENTIAL_LENGTH
        ).strip()
        normalized_id = validate_opaque_value(
            normalized_id, name="client_id", maximum=MAX_CREDENTIAL_LENGTH
        )
        secret = validate_opaque_value(
            client_secret, name="client_secret", maximum=MAX_CREDENTIAL_LENGTH
        )
        return cls(normalized_id, secret)


@dataclass(frozen=True, slots=True)
class FdmConnectionCommand:
    host: str
    port: int
    username: str
    password: str
    api_version: str
    certificate_store_dir: Path

    @classmethod
    def from_untrusted(
        cls,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        api_version: str,
        certificate_store_dir: str | Path,
    ) -> "FdmConnectionCommand":
        return cls(
            host=validate_host(host),
            port=validate_port(port),
            username=validate_opaque_value(
                username, name="username", maximum=MAX_CREDENTIAL_LENGTH
            ),
            password=validate_opaque_value(
                password, name="password", maximum=MAX_CREDENTIAL_LENGTH
            ),
            api_version=validate_api_version(api_version),
            certificate_store_dir=resolve_operator_path(
                certificate_store_dir, name="certificate_store_dir"
            ),
        )


@dataclass(frozen=True, slots=True)
class FdmBootstrapCommand:
    host: str
    port: int
    certificate_store_dir: Path

    @classmethod
    def from_untrusted(
        cls, *, host: str, port: int, certificate_store_dir: str | Path
    ) -> "FdmBootstrapCommand":
        return cls(
            host=validate_host(host),
            port=validate_port(port),
            certificate_store_dir=resolve_operator_path(
                certificate_store_dir, name="certificate_store_dir"
            ),
        )


@dataclass(frozen=True, slots=True)
class OperationResult:
    title: str
    message: str
