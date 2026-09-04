"""
Cisco Smart Accounts and Licensing reservation client.

This client does not obtain tokens. It accepts a bearer token from
cisco_support_token_client.py and uses that token for reservation requests.

The reservation endpoint is configurable because Cisco's Smart Accounts API
surface is route-specific and the caller may need to target a customer, smart
account, or virtual account path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urljoin, urlparse

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter


class CiscoPlrError(RuntimeError):
    """Base exception for PLR reservation failures."""


class CiscoPlrRequestError(CiscoPlrError):
    """The reservation request failed."""


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
        timeout: tuple[float, float] = (5.0, 30.0),
        ca_bundle: str | Path | None = None,
        verify_certificate: bool = True,
        user_agent: str = "cisco-plr-reservation-client/1.0",
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("base_url must use https://")
        if bearer_token is None and token_provider is None:
            raise ValueError("bearer_token or token_provider is required")

        self.base_url = base_url.rstrip("/") + "/"
        self._bearer_token = bearer_token
        self._token_provider = token_provider
        self._timeout = timeout
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
        return text[:limit]

    def set_bearer_token(self, bearer_token: str) -> None:
        if not bearer_token:
            raise ValueError("bearer_token must not be empty")
        self._bearer_token = bearer_token

    def _resolve_bearer_token(self) -> str:
        if self._bearer_token:
            return self._bearer_token
        if self._token_provider is None:
            raise CiscoPlrError("No bearer token available")

        token = self._token_provider()
        if not token:
            raise CiscoPlrError("Token provider returned an empty bearer token")
        return token

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
        method = method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"Unsupported HTTP method: {method}")

        url = self._build_url(path)
        request_headers = dict(headers or {})
        request_headers["Authorization"] = f"Bearer {self._resolve_bearer_token()}"

        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=json,
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

    def post_json(
        self,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        response = self.request("POST", path, params=params, json=json, headers=headers)
        try:
            return response.json()
        except ValueError as exc:
            raise CiscoPlrRequestError(
                f"POST {urlparse(response.url).path} returned invalid JSON"
            ) from exc

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

    def close(self) -> None:
        if self._closed:
            return
        self.session.close()
        self._closed = True

    def _build_url(self, path: str) -> str:
        if not path:
            raise ValueError("path must not be empty")
        if path.startswith("http://") or path.startswith("https://"):
            raise ValueError("Absolute URLs are not accepted")

        normalized = path.lstrip("/")
        url = urljoin(self.base_url, normalized)

        base = urlparse(self.base_url)
        target = urlparse(url)
        if (target.scheme, target.netloc) != (base.scheme, base.netloc):
            raise ValueError("Request path escaped the configured Cisco origin")
        return url

    def _ensure_open(self) -> None:
        if self._closed:
            raise CiscoPlrError("CiscoPlrReservationClient is closed")
