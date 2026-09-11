#!/usr/bin/env python3
"""Secure, cross-platform storage for Cisco API client credentials."""

from __future__ import annotations

import argparse
import getpass
import platform
import sys
from dataclasses import dataclass
from typing import Any, Sequence

from security_validation import (
    MAX_CREDENTIAL_LENGTH,
    validate_host,
    validate_opaque_value,
    validate_port,
)

try:
    import keyring
    from keyring.errors import PasswordDeleteError
except ImportError:  # Produce a clear error and permit dependency-free mock tests.
    keyring = None  # type: ignore[assignment]

    class PasswordDeleteError(Exception):
        """Fallback used only when keyring is not installed."""


SERVICE_NAME = "fdm-client/cisco-support"
CLIENT_ID_KEY = "client-id"
CLIENT_SECRET_KEY = "client-secret"
FDM_HOST_KEY = "fdm-host"
FDM_PORT_KEY = "fdm-port"
FDM_USERNAME_KEY = "fdm-username"
FDM_PASSWORD_KEY = "fdm-password"
FDM_KEYS = (FDM_HOST_KEY, FDM_PORT_KEY, FDM_USERNAME_KEY, FDM_PASSWORD_KEY)
CISCO_CLIENT = "CISCO_CLIENT"
FDM = "FDM"
SUPPORTED_SYSTEMS = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}
INSECURE_BACKEND_MARKERS = ("fail", "null", "plaintext")


class KeyManagerError(RuntimeError):
    """Base exception for credential-storage failures."""


class UnsupportedPlatformError(KeyManagerError):
    """The current operating system is not supported."""


class SecureBackendUnavailableError(KeyManagerError):
    """No acceptable secure OS credential backend is available."""


class CredentialsNotFoundError(KeyManagerError):
    """One or more required Cisco client credentials are absent."""


class CredentialAccessError(KeyManagerError):
    """The configured native credential store could not be read."""


class InvalidStoredCredentialsError(KeyManagerError):
    """Stored credential values do not satisfy the credential grammar."""


class CredentialStorageError(KeyManagerError):
    """The credential backend failed to store or delete a value."""


@dataclass(frozen=True, slots=True)
class CiscoClientCredentials:
    """Cisco OAuth client credentials retrieved from secure storage."""

    client_id: str
    client_secret: str


@dataclass(frozen=True, slots=True)
class FdmCredentials:
    """One default device-scoped FDM credential record."""

    host: str
    port: int
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class CredentialStatus:
    """Non-secret diagnostic information about credential availability."""

    platform: str
    backend: str
    client_id_present: bool
    client_secret_present: bool

    @property
    def complete(self) -> bool:
        return self.client_id_present and self.client_secret_present


@dataclass(frozen=True, slots=True)
class FdmCredentialStatus:
    host_present: bool
    port_present: bool
    username_present: bool
    password_present: bool

    @property
    def complete(self) -> bool:
        return all(
            (self.host_present, self.port_present, self.username_present, self.password_present)
        )


class KeyManager:
    """Store Cisco client credentials in the native OS credential store."""

    def __init__(
        self,
        *,
        service_name: str = SERVICE_NAME,
        backend: Any | None = None,
        system_name: str | None = None,
    ) -> None:
        self.service_name = service_name
        detected_system = system_name or platform.system()
        self._platform_name = self._validate_platform(detected_system)
        if backend is None:
            if keyring is None:
                raise SecureBackendUnavailableError(
                    "The 'keyring' package is not installed; install project requirements"
                )
            try:
                backend = keyring.get_keyring()
            except Exception as exc:
                raise SecureBackendUnavailableError(
                    "Unable to initialize the operating-system credential backend"
                ) from exc
        self._backend = backend
        self._backend_name = self._validate_backend(backend)

    @staticmethod
    def _validate_platform(system_name: str) -> str:
        try:
            return SUPPORTED_SYSTEMS[system_name]
        except KeyError as exc:
            raise UnsupportedPlatformError(
                f"Unsupported operating system: {system_name or 'unknown'}"
            ) from exc

    @staticmethod
    def _validate_backend(backend: Any) -> str:
        backend_name = f"{type(backend).__module__}.{type(backend).__qualname__}"
        try:
            priority = float(backend.priority)
        except (AttributeError, TypeError, ValueError) as exc:
            raise SecureBackendUnavailableError(
                f"Credential backend is not usable: {backend_name}"
            ) from exc
        normalized = backend_name.lower()
        if priority <= 0 or any(x in normalized for x in INSECURE_BACKEND_MARKERS):
            raise SecureBackendUnavailableError(
                f"Refusing insecure or unavailable credential backend: {backend_name}"
            )
        return backend_name

    def _get(self, username: str) -> str | None:
        try:
            value = self._backend.get_password(self.service_name, username)
        except Exception as exc:
            store_name = {
                "macOS": "macOS Keychain",
                "Windows": "Windows Credential Manager",
                "Linux": "Linux secret-service/keyring",
            }[self._platform_name]
            raise CredentialAccessError(
                f"{store_name} could not be accessed using {self._backend_name}; "
                "verify the current user, unlock the credential store, and allow "
                "this Python executable to read it"
            ) from exc
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise InvalidStoredCredentialsError(
                f"Stored {username} is not a text value"
            )
        return value

    def get_cisco_credentials(self) -> CiscoClientCredentials:
        """Return the complete credential pair or fail without partial results."""
        client_id = self._get(CLIENT_ID_KEY)
        client_secret = self._get(CLIENT_SECRET_KEY)
        missing = []
        if not client_id:
            missing.append("Client ID")
        if not client_secret:
            missing.append("Client Secret")
        if missing:
            raise CredentialsNotFoundError(
                f"Cisco {' and '.join(missing)} {'are' if len(missing) > 1 else 'is'} "
                "empty or not stored; run 'key_manager.py store'"
            )
        try:
            client_id = validate_opaque_value(
                client_id, name="stored client_id", maximum=MAX_CREDENTIAL_LENGTH
            )
            client_secret = validate_opaque_value(
                client_secret,
                name="stored client_secret",
                maximum=MAX_CREDENTIAL_LENGTH,
            )
        except ValueError as exc:
            raise InvalidStoredCredentialsError(
                "Stored Cisco credentials are malformed or exceed the supported length; "
                "store a new credential pair"
            ) from exc
        return CiscoClientCredentials(client_id, client_secret)

    def store_cisco_credentials(self, client_id: str, client_secret: str) -> None:
        """Store a pair, restoring prior values after a partial failure."""
        client_id = validate_opaque_value(
            client_id, name="client_id", maximum=MAX_CREDENTIAL_LENGTH
        ).strip()
        client_id = validate_opaque_value(
            client_id, name="client_id", maximum=MAX_CREDENTIAL_LENGTH
        )
        client_secret = validate_opaque_value(
            client_secret, name="client_secret", maximum=MAX_CREDENTIAL_LENGTH
        )
        old_id = self._get(CLIENT_ID_KEY)
        old_secret = self._get(CLIENT_SECRET_KEY)
        try:
            self._backend.set_password(
                self.service_name, CLIENT_ID_KEY, client_id
            )
            self._backend.set_password(
                self.service_name, CLIENT_SECRET_KEY, client_secret
            )
        except Exception as exc:
            self._restore(CLIENT_ID_KEY, old_id)
            self._restore(CLIENT_SECRET_KEY, old_secret)
            raise CredentialStorageError(
                "The credential backend failed while storing credentials"
            ) from exc

    def get_fdm_credentials(self) -> FdmCredentials:
        """Return the default FDM record or fail without partial results."""
        values = {key: self._get(key) for key in FDM_KEYS}
        missing = [key.removeprefix("fdm-") for key, value in values.items() if not value]
        if missing:
            raise CredentialsNotFoundError(
                f"FDM {', '.join(missing)} {'are' if len(missing) > 1 else 'is'} "
                "empty or not stored; run 'key_manager.py store'"
            )
        try:
            return FdmCredentials(
                host=validate_host(values[FDM_HOST_KEY]),
                port=validate_port(int(values[FDM_PORT_KEY])),
                username=validate_opaque_value(
                    values[FDM_USERNAME_KEY], name="stored FDM username",
                    maximum=MAX_CREDENTIAL_LENGTH,
                ),
                password=validate_opaque_value(
                    values[FDM_PASSWORD_KEY], name="stored FDM password",
                    maximum=MAX_CREDENTIAL_LENGTH,
                ),
            )
        except (TypeError, ValueError) as exc:
            raise InvalidStoredCredentialsError(
                "Stored FDM credentials are malformed; update the FDM credential record"
            ) from exc

    def store_fdm_credentials(
        self, *, host: str, port: int, username: str, password: str
    ) -> None:
        """Atomically store one default FDM record scoped by its device identity."""
        values = {
            FDM_HOST_KEY: validate_host(host),
            FDM_PORT_KEY: str(validate_port(port)),
            FDM_USERNAME_KEY: validate_opaque_value(
                username, name="username", maximum=MAX_CREDENTIAL_LENGTH
            ),
            FDM_PASSWORD_KEY: validate_opaque_value(
                password, name="password", maximum=MAX_CREDENTIAL_LENGTH
            ),
        }
        old = {key: self._get(key) for key in FDM_KEYS}
        try:
            for key, value in values.items():
                self._backend.set_password(self.service_name, key, value)
        except Exception as exc:
            for key, value in old.items():
                self._restore(key, value)
            raise CredentialStorageError(
                "The credential backend failed while storing FDM credentials"
            ) from exc

    def _restore(self, username: str, value: str | None) -> None:
        try:
            if value is None:
                self._backend.delete_password(self.service_name, username)
            else:
                self._backend.set_password(self.service_name, username, value)
        except Exception:
            pass  # Preserve the original exception without exposing values.

    def delete_cisco_credentials(self) -> None:
        """Delete both values; an already-absent value is treated as success."""
        failures = []
        for username in (CLIENT_ID_KEY, CLIENT_SECRET_KEY):
            try:
                self._backend.delete_password(self.service_name, username)
            except PasswordDeleteError:
                continue
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise CredentialStorageError(
                "The credential backend failed while deleting credentials"
            ) from failures[0]

    def delete_fdm_credentials(self) -> None:
        """Delete the default FDM record; absent values are successful."""
        failures = []
        for key in FDM_KEYS:
            try:
                self._backend.delete_password(self.service_name, key)
            except PasswordDeleteError:
                continue
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise CredentialStorageError(
                "The credential backend failed while deleting FDM credentials"
            ) from failures[0]

    def credential_status(self) -> CredentialStatus:
        """Return availability metadata without returning credential values."""
        return CredentialStatus(
            platform=self._platform_name,
            backend=self._backend_name,
            client_id_present=self._get(CLIENT_ID_KEY) is not None,
            client_secret_present=self._get(CLIENT_SECRET_KEY) is not None,
        )

    def fdm_credential_status(self) -> FdmCredentialStatus:
        return FdmCredentialStatus(
            host_present=self._get(FDM_HOST_KEY) is not None,
            port_present=self._get(FDM_PORT_KEY) is not None,
            username_present=self._get(FDM_USERNAME_KEY) is not None,
            password_present=self._get(FDM_PASSWORD_KEY) is not None,
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage Cisco API and device-scoped FDM credentials in the native OS credential store."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show backend and credential availability.")
    commands.add_parser(
        "store", help="Prompt only for credential groups that are not complete."
    )
    update = commands.add_parser(
        "update", help="Prompt for and replace one specified credential group."
    )
    update.add_argument(
        "credential_group",
        type=str.upper,
        choices=(CISCO_CLIENT, FDM),
        help="CISCO_CLIENT or FDM",
    )
    delete = commands.add_parser("delete", help="Delete stored credentials.")
    delete.add_argument(
        "credential_group",
        nargs="?",
        type=str.upper,
        choices=(CISCO_CLIENT, FDM, "ALL"),
        default="ALL",
    )
    delete.add_argument(
        "--yes", action="store_true", help="Delete without interactive confirmation."
    )
    return parser.parse_args(argv)


def _prompt_cisco(manager: KeyManager) -> None:
    client_id = input("Cisco Client ID: ").strip()
    client_secret = getpass.getpass("Cisco Client Secret: ")
    manager.store_cisco_credentials(client_id, client_secret)
    print("Cisco client credentials stored securely.")


def _prompt_fdm(manager: KeyManager) -> None:
    host = input("FDM hostname or IP address: ").strip()
    raw_port = input("FDM HTTPS port [443]: ").strip()
    try:
        port = int(raw_port) if raw_port else 443
    except ValueError as exc:
        raise ValueError("FDM port must be an integer") from exc
    username = input("FDM username [admin]: ").strip() or "admin"
    password = getpass.getpass(f"Password for {username}@{host}: ")
    manager.store_fdm_credentials(
        host=host, port=port, username=username, password=password
    )
    print("FDM credentials stored securely for the specified device.")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manager = KeyManager()
        if args.command == "status":
            status = manager.credential_status()
            fdm_status = manager.fdm_credential_status()
            print(f"Platform: {status.platform}")
            print(f"Backend: {status.backend}")
            print(f"Cisco Client ID stored: {'yes' if status.client_id_present else 'no'}")
            print(f"Cisco Client Secret stored: {'yes' if status.client_secret_present else 'no'}")
            print(f"FDM host stored: {'yes' if fdm_status.host_present else 'no'}")
            print(f"FDM port stored: {'yes' if fdm_status.port_present else 'no'}")
            print(f"FDM username stored: {'yes' if fdm_status.username_present else 'no'}")
            print(f"FDM password stored: {'yes' if fdm_status.password_present else 'no'}")
            return 0 if status.complete and fdm_status.complete else 1
        if args.command == "store":
            changed = False
            if not manager.credential_status().complete:
                _prompt_cisco(manager)
                changed = True
            if not manager.fdm_credential_status().complete:
                _prompt_fdm(manager)
                changed = True
            if not changed:
                print("All supported credential groups are already stored.")
            return 0
        if args.command == "update":
            if args.credential_group == CISCO_CLIENT:
                _prompt_cisco(manager)
            else:
                _prompt_fdm(manager)
            return 0
        if not args.yes:
            answer = input(
                f"Delete stored {args.credential_group} credentials? [y/N]: "
            )
            if answer.strip().lower() not in {"y", "yes"}:
                print("Deletion cancelled.")
                return 0
        if args.credential_group in {CISCO_CLIENT, "ALL"}:
            manager.delete_cisco_credentials()
        if args.credential_group in {FDM, "ALL"}:
            manager.delete_fdm_credentials()
        print(f"Stored {args.credential_group} credentials deleted.")
        return 0
    except (KeyManagerError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
