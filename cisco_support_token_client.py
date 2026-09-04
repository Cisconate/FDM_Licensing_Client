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


class CiscoSupportTokenError(RuntimeError):
    """Base exception for Cisco token acquisition failures."""


class CiscoSupportTokenRequestError(CiscoSupportTokenError):
    """The token endpoint could not be reached or returned a bad response."""


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
        if not client_id:
            raise ValueError("client_id must not be empty")
        if not client_secret:
            raise ValueError("client_secret must not be empty")
        if not token_url.startswith("https://"):
            raise ValueError("token_url must use https://")

        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._timeout = timeout
        self._token: BearerToken | None = None
        self._token_lock = threading.RLock()
        self._closed = False

        self.session: Session = requests.Session()
        if ca_bundle is not None:
            ca_path = Path(ca_bundle).expanduser().resolve()
            if not ca_path.is_file():
                raise FileNotFoundError(f"CA bundle not found: {ca_path}")
            self.session.verify = str(ca_path)
        else:
            self.session.verify = verify_certificate
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": user_agent,
            }
        )
        self.session.mount("https://", HTTPAdapter(max_retries=0))

    def __enter__(self) -> "CiscoSupportTokenClient":
        self.authenticate()
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
        return text[:limit]

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
            raise CiscoSupportTokenRequestError(
                "TLS validation failed when contacting the Cisco token endpoint"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise CiscoSupportTokenRequestError(
                f"Unable to reach the Cisco token endpoint: {exc}"
            ) from exc

        if response.is_redirect:
            raise CiscoSupportTokenRequestError(
                f"Unexpected redirect from token endpoint (HTTP {response.status_code})"
            )
        if response.status_code != 200:
            raise CiscoSupportTokenRequestError(
                f"Token request failed with HTTP {response.status_code}: "
                f"{self._safe_error_text(response)}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise CiscoSupportTokenRequestError(
                "Token endpoint returned invalid JSON"
            ) from exc

        if not isinstance(data, dict) or not data.get("access_token"):
            raise CiscoSupportTokenRequestError(
                "Token response did not contain access_token"
            )
        return data

    @staticmethod
    def _token_from_response(data: Mapping[str, Any]) -> BearerToken:
        now = time.monotonic()
        try:
            expires_in = max(1, int(data["expires_in"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise CiscoSupportTokenRequestError(
                "Token response contained an invalid expires_in value"
            ) from exc

        return BearerToken(
            access_token=str(data["access_token"]),
            expires_at=now + expires_in,
            token_type=str(data.get("token_type", "Bearer")),
            scope=str(data["scope"]) if data.get("scope") else None,
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
        description=(
            "Cisco Support OAuth token client. Credentials are read from the "
            "operating-system credential store."
        )
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
