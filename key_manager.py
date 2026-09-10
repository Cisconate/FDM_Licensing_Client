#!/usr/bin/env python3
"""Secure, cross-platform storage for Cisco API client credentials."""

from __future__ import annotations

import argparse
import getpass
import platform
import sys
from dataclasses import dataclass
from typing import Any, Sequence

from security_validation import MAX_CREDENTIAL_LENGTH, validate_opaque_value

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
class CredentialStatus:
    """Non-secret diagnostic information about credential availability."""

    platform: str
    backend: str
    client_id_present: bool
    client_secret_present: bool

    @property
    def complete(self) -> bool:
        return self.client_id_present and self.client_secret_present


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

    def credential_status(self) -> CredentialStatus:
        """Return availability metadata without returning credential values."""
        return CredentialStatus(
            platform=self._platform_name,
            backend=self._backend_name,
            client_id_present=self._get(CLIENT_ID_KEY) is not None,
            client_secret_present=self._get(CLIENT_SECRET_KEY) is not None,
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage Cisco API credentials in the native OS credential store."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show backend and credential availability.")
    commands.add_parser("store", help="Securely prompt for and store credentials.")
    delete = commands.add_parser("delete", help="Delete stored credentials.")
    delete.add_argument(
        "--yes", action="store_true", help="Delete without interactive confirmation."
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manager = KeyManager()
        if args.command == "status":
            status = manager.credential_status()
            print(f"Platform: {status.platform}")
            print(f"Backend: {status.backend}")
            print(f"Client ID stored: {'yes' if status.client_id_present else 'no'}")
            print(f"Client Secret stored: {'yes' if status.client_secret_present else 'no'}")
            return 0 if status.complete else 1
        if args.command == "store":
            client_id = input("Cisco Client ID: ").strip()
            client_secret = getpass.getpass("Cisco Client Secret: ")
            manager.store_cisco_credentials(client_id, client_secret)
            print("Cisco client credentials stored securely.")
            return 0
        if not args.yes:
            answer = input("Delete stored Cisco client credentials? [y/N]: ")
            if answer.strip().lower() not in {"y", "yes"}:
                print("Deletion cancelled.")
                return 0
        manager.delete_cisco_credentials()
        print("Stored Cisco client credentials deleted.")
        return 0
    except (KeyManagerError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
