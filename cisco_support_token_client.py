"""
Cisco Support API bearer-token client.

This module only performs the OAuth2 client-credentials token request against:

  https://id.cisco.com/oauth2/default/v1/token

It caches the token in memory, refreshes it when near expiration, and returns
the bearer token string for downstream API clients.
"""

from __future__ import annotations

import argparse
import threading
import time
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter

from security_validation import (
    MAX_CREDENTIAL_LENGTH,
    MAX_TOKEN_LENGTH,
    resolve_operator_path,
    validate_bool,
    validate_https_base_url,
    validate_lifetime,
    validate_opaque_value,
    validate_timeout,
    validate_user_agent,
)


class CiscoSupportTokenError(RuntimeError):
    """Base exception for Cisco token acquisition failures."""


class CiscoSupportTokenRequestError(CiscoSupportTokenError):
    """The token endpoint could not be reached or returned a bad response."""


class CiscoSupportCredentialRejectedError(CiscoSupportTokenRequestError):
    """The OAuth provider rejected the supplied client credentials."""


class CiscoSupportTokenTransportError(CiscoSupportTokenRequestError):
    """The OAuth provider could not be reached securely within the timeout."""


class CiscoSupportTokenServiceError(CiscoSupportTokenRequestError):
    """The OAuth provider was reachable but unavailable or returned bad data."""


@dataclass(slots=True)
class BearerToken:
    access_token: str
    expires_at: float
    token_type: str = "Bearer"
    scope: str | None = None

    def valid(self, leeway_seconds: int = 60) -> bool:
        return time.monotonic() < self.expires_at - leeway_seconds


class CiscoSupportTokenClient:
    """
    Fetch and cache a Cisco Support API bearer token.

    Args:
        client_id:
            Cisco API Console client ID.
        client_secret:
            Cisco API Console client secret.
        token_url:
            OAuth2 token endpoint. Defaults to Cisco's Common Identity token URL.
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
        client_id: str,
        client_secret: str,
        token_url: str = "https://id.cisco.com/oauth2/default/v1/token",
        timeout: tuple[float, float] = (5.0, 30.0),
        ca_bundle: str | Path | None = None,
        verify_certificate: bool = True,
        user_agent: str = "cisco-support-token-client/1.0",
    ) -> None:
        self._client_id = validate_opaque_value(
            client_id, name="client_id", maximum=MAX_CREDENTIAL_LENGTH
        )
        self._client_secret = validate_opaque_value(
            client_secret, name="client_secret", maximum=MAX_CREDENTIAL_LENGTH
        )
        self._token_url = validate_https_base_url(token_url, name="token_url").rstrip("/")
        self._timeout = validate_timeout(timeout)
        verify_certificate = validate_bool(
            verify_certificate, name="verify_certificate"
        )
        self._token: BearerToken | None = None
        self._token_lock = threading.RLock()
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

    def __enter__(self) -> "CiscoSupportTokenClient":
        self.authenticate()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _token_post(self) -> dict[str, Any]:
        try:
            response = self.session.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            raise CiscoSupportTokenTransportError(
                "TLS validation failed when contacting the Cisco token endpoint"
            ) from exc
        except requests.exceptions.ConnectTimeout as exc:
            raise CiscoSupportTokenTransportError(
                f"Timed out connecting to the Cisco token endpoint after {self._timeout[0]:g} seconds"
            ) from exc
        except requests.exceptions.ReadTimeout as exc:
            raise CiscoSupportTokenTransportError(
                f"The Cisco token endpoint did not respond within {self._timeout[1]:g} seconds"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise CiscoSupportTokenTransportError(
                "Unable to reach the Cisco token endpoint due to a network error"
            ) from exc

        if response.is_redirect:
            raise CiscoSupportTokenServiceError(
                f"Unexpected redirect from token endpoint (HTTP {response.status_code})"
            )
        if response.status_code != 200:
            provider_error = self._provider_error_code(response)
            if response.status_code in {400, 401, 403} and provider_error in {
                "invalid_client", "invalid_grant", "unauthorized_client"
            }:
                raise CiscoSupportCredentialRejectedError(
                    f"Cisco OAuth rejected the Client ID or Client Secret "
                    f"(HTTP {response.status_code}, {provider_error}); verify that the "
                    "stored pair is current and belongs to the same API application"
                )
            if response.status_code == 429:
                raise CiscoSupportTokenServiceError(
                    "Cisco OAuth rate-limited the token request (HTTP 429); try again later"
                )
            if response.status_code >= 500:
                raise CiscoSupportTokenServiceError(
                    f"Cisco OAuth is currently unavailable (HTTP {response.status_code})"
                )
            detail = f", {provider_error}" if provider_error else ""
            raise CiscoSupportTokenRequestError(
                f"Cisco OAuth rejected the token request (HTTP {response.status_code}{detail}); "
                "the response does not conclusively identify a bad credential pair"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise CiscoSupportTokenServiceError(
                "Token endpoint returned invalid JSON"
            ) from exc

        if not isinstance(data, dict) or not data.get("access_token"):
            raise CiscoSupportTokenServiceError(
                "Token response did not contain access_token"
            )
        return data

    @staticmethod
    def _provider_error_code(response: Response) -> str | None:
        """Return only a bounded OAuth error code, never provider detail text."""
        try:
            data = response.json()
        except ValueError:
            return None
        if not isinstance(data, Mapping):
            return None
        value = data.get("error")
        if not isinstance(value, str) or not value or len(value) > 128:
            return None
        if not all(char.isalnum() or char in {"_", "-"} for char in value):
            return None
        return value

    @staticmethod
    def _token_from_response(data: Mapping[str, Any]) -> BearerToken:
        now = time.monotonic()
        try:
            expires_in = validate_lifetime(data["expires_in"], name="expires_in")
        except (KeyError, ValueError) as exc:
            raise CiscoSupportTokenServiceError(
                "Token response contained an invalid expires_in value"
            ) from exc

        try:
            access_token = validate_opaque_value(
                data["access_token"], name="access_token", maximum=MAX_TOKEN_LENGTH
            )
            token_type = validate_opaque_value(
                data.get("token_type", "Bearer"), name="token_type", maximum=32
            )
            scope = data.get("scope")
            if scope is not None:
                scope = validate_opaque_value(scope, name="scope", maximum=2048)
        except (KeyError, ValueError) as exc:
            raise CiscoSupportTokenServiceError(
                "Token response contained an invalid token field"
            ) from exc

        return BearerToken(
            access_token=access_token,
            expires_at=now + expires_in,
            token_type=token_type,
            scope=scope,
        )

    def authenticate(self) -> BearerToken:
        """Request a new token and cache it."""
        with self._token_lock:
            self._ensure_open()
            data = self._token_post()
            self._token = self._token_from_response(data)
            return self._token

    def refresh(self) -> BearerToken:
        """Force a fresh token request."""
        with self._token_lock:
            self._ensure_open()
            data = self._token_post()
            self._token = self._token_from_response(data)
            return self._token

    def get_bearer_token(self) -> str:
        """Return a valid bearer token string."""
        with self._token_lock:
            self._ensure_open()
            if self._token is None:
                self.authenticate()
            elif not self._token.valid():
                self.refresh()

            assert self._token is not None
            return self._token.access_token

    def get_authorization_header(self) -> dict[str, str]:
        """Return an Authorization header suitable for downstream requests."""
        token = self.get_bearer_token()
        return {"Authorization": f"Bearer {token}"}

    def invalidate(self) -> None:
        """Discard the cached token so the next lookup authenticates again."""
        with self._token_lock:
            self._ensure_open()
            self._token = None

    def close(self) -> None:
        if self._closed:
            return
        self.session.close()
        self._token = None
        self._client_id = ""
        self._client_secret = ""
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise CiscoSupportTokenError("CiscoSupportTokenClient is closed")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the standalone token-client diagnostic options."""
    parser = argparse.ArgumentParser(
        prog="cisco_support_token_client.py",
        description=(
            "Cisco Support OAuth token client. Credentials are read from the "
            "operating-system credential store."
        ),
        epilog=(
            "example: python cisco_support_token_client.py --check\n\n"
            "This command performs a live OAuth request but never displays the "
            "credential values or returned token."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "request a token to validate stored credentials without displaying "
            "the credentials or token"
        ),
    )
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("--check is required")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Run a non-mutating live authentication check against Cisco OAuth."""
    parse_args(argv)

    # Keep credential storage optional for library users and avoid coupling at
    # module import time.
    from key_manager import KeyManager, KeyManagerError

    client: CiscoSupportTokenClient | None = None
    try:
        credentials = KeyManager().get_cisco_credentials()
        client = CiscoSupportTokenClient(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
        )
        token = client.authenticate()
        print(
            "Cisco authentication succeeded "
            f"(token type: {token.token_type}, scope present: "
            f"{'yes' if token.scope else 'no'})."
        )
        return 0
    except (KeyManagerError, CiscoSupportTokenError, ValueError) as exc:
        print(f"Cisco authentication failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
