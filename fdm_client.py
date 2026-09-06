"""
Secure Cisco Secure Firewall Threat Defense / Firewall Device Manager REST client.

Authentication flow:
  POST /api/fdm/{api_version}/fdm/token
  Authorization: Bearer <access_token>

Security defaults:
  * TLS certificate verification is enabled by default.
  * Credentials and tokens are never logged.
  * Tokens are reused and refreshed rather than recreated for every request.
  * Tokens are revoked when close() is called or the context manager exits.

Dependencies:
  pip install requests
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urljoin, urlparse

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter

from fdm_certificate_store import certificate_bundle_path
from security_validation import (
    MAX_CREDENTIAL_LENGTH,
    MAX_TOKEN_LENGTH,
    encode_json_payload,
    resolve_operator_path,
    safe_error_text,
    validate_api_version,
    validate_bool,
    validate_headers,
    validate_host,
    validate_http_method,
    validate_lifetime,
    validate_opaque_value,
    validate_port,
    validate_query_params,
    validate_relative_api_path,
    validate_timeout,
    validate_user_agent,
)


class FDMError(RuntimeError):
    """Base exception for FDM client failures."""


class FDMAuthenticationError(FDMError):
    """Authentication, token refresh, or token revocation failure."""


class FDMRequestError(FDMError):
    """An FDM REST API request failed."""


@dataclass(slots=True)
class TokenState:
    access_token: str
    refresh_token: str | None
    access_expires_at: float
    refresh_expires_at: float | None
    token_type: str = "Bearer"

    def access_valid(self, leeway_seconds: int = 60) -> bool:
        return time.monotonic() < self.access_expires_at - leeway_seconds

    def refresh_valid(self, leeway_seconds: int = 30) -> bool:
        return (
            self.refresh_token is not None
            and self.refresh_expires_at is not None
            and time.monotonic() < self.refresh_expires_at - leeway_seconds
        )


class FDMClient:
    """
    Secure REST client for an FTD device managed locally through FDM.

    Args:
        host:
            FDM hostname or IP address. A hostname matching the certificate
            is preferred, for example "ftd01.example.com".
        username:
            Local or supported external FDM/API username.
        password:
            Password for username.
        ca_bundle:
            Path to a PEM CA bundle that validates the FDM HTTPS certificate.
            This can contain the issuing CA chain or a specifically trusted
            self-signed device certificate. Takes precedence over
            certificate_store_dir when provided.
        certificate_store_dir:
            Directory containing the local project certificate store. When
            certificate verification is enabled and ca_bundle is not supplied,
            the client looks for a PEM bundle named fdm-ca-bundle.pem inside
            this directory.
        verify_certificate:
            When True, verify the FDM HTTPS certificate using ca_bundle.
            When False, skip certificate verification. Use this only during
            initial setup or other controlled environments where the device
            is using a self-generated certificate.
        port:
            HTTPS management port, normally 443.
        api_version:
            "latest" or a version exposed by the device, such as "v6".
        timeout:
            (connect timeout, read timeout), in seconds.
        user_agent:
            Identifies the automation client without exposing credentials.
        debug_logging:
            When True, emit debug logs to both a local file and the console.
        log_file:
            Optional path for the debug log file. When omitted and
            debug_logging is enabled, the client writes
            fdm_client_debug.log next to this module.
    """

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        ca_bundle: str | Path | None = None,
        certificate_store_dir: str | Path | None = None,
        verify_certificate: bool = True,
        port: int = 443,
        api_version: str = "latest",
        timeout: tuple[float, float] = (5.0, 30.0),
        user_agent: str = "secure-fdm-python-client/1.0",
        debug_logging: bool = False,
        log_file: str | Path | None = None,
    ) -> None:
        host = validate_host(host)
        port = validate_port(port)
        api_version = validate_api_version(api_version)
        verify_certificate = validate_bool(
            verify_certificate, name="verify_certificate"
        )
        debug_logging = validate_bool(debug_logging, name="debug_logging")
        username = validate_opaque_value(
            username, name="username", maximum=MAX_CREDENTIAL_LENGTH
        )
        password = validate_opaque_value(
            password, name="password", maximum=MAX_CREDENTIAL_LENGTH
        )

        ca_path: Path | None = None
        if verify_certificate:
            if ca_bundle is not None:
                ca_path = resolve_operator_path(ca_bundle, name="ca_bundle")
            elif certificate_store_dir is not None:
                ca_path = certificate_bundle_path(certificate_store_dir)
            else:
                raise ValueError(
                    "ca_bundle or certificate_store_dir is required when "
                    "verify_certificate is True"
                )
            if not ca_path.is_file():
                raise FileNotFoundError(f"CA bundle not found: {ca_path}")

        self._username = username
        self._password = password
        self._timeout = validate_timeout(timeout)
        self._token: TokenState | None = None
        self._token_lock = threading.RLock()
        self._closed = False
        self._debug_logging = debug_logging
        self._logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}.{id(self)}"
        )
        self._logger.propagate = False
        self._log_handlers: list[logging.Handler] = []

        if self._debug_logging:
            self._configure_debug_logging(log_file)

        self.base_url = f"https://{host}:{port}/api/fdm/{api_version}/"
        self.token_url = urljoin(self.base_url, "fdm/token")

        self.session: Session = requests.Session()
        self.session.verify = str(ca_path) if ca_path is not None else False
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": validate_user_agent(user_agent),
            }
        )

        # No automatic retries are configured for POST/PUT/PATCH/DELETE.
        # Blindly replaying a write can duplicate or alter configuration.
        self.session.mount("https://", HTTPAdapter(max_retries=0))

    def __enter__(self) -> "FDMClient":
        self.authenticate()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _safe_error_text(response: Response, limit: int = 1000) -> str:
        """
        Return a bounded server error message. Never include request data or
        request headers because those can contain passwords or bearer tokens.
        """
        try:
            body = response.json()
            text = repr(body)
        except ValueError:
            text = response.text
        return safe_error_text(text, limit=limit)

    def _configure_debug_logging(self, log_file: str | Path | None) -> None:
        if log_file is None:
            log_path = Path(__file__).resolve().with_name("fdm_client_debug.log")
        else:
            log_path = resolve_operator_path(log_file, name="log_file")

        if log_path.is_symlink() or (log_path.exists() and not log_path.is_file()):
            raise ValueError("log_file must be a regular file and not a symbolic link")

        log_path.parent.mkdir(parents=True, exist_ok=True)
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        )

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)

        self._logger.setLevel(logging.DEBUG)
        self._logger.addHandler(file_handler)
        self._logger.addHandler(console_handler)
        self._log_handlers = [file_handler, console_handler]
        self._logger.debug("Debug logging enabled; file=%s", log_path)

    def _debug(self, message: str, *args: Any) -> None:
        if self._debug_logging:
            self._logger.debug(message, *args)

    def _token_post(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        grant_type = str(payload.get("grant_type", "unknown"))
        self._debug("Posting token request using %s grant", grant_type)
        try:
            response = self.session.post(
                self.token_url,
                json=dict(payload),
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            raise FDMAuthenticationError(
                "TLS validation failed. Verify the FDM certificate, hostname, "
                "and supplied CA bundle."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise FDMAuthenticationError(
                f"Unable to reach the FDM token endpoint: {exc}"
            ) from exc

        if response.is_redirect:
            raise FDMAuthenticationError(
                f"Unexpected redirect from token endpoint (HTTP {response.status_code})"
            )
        if response.status_code != 200:
            raise FDMAuthenticationError(
                f"Token request failed with HTTP {response.status_code}: "
                f"{self._safe_error_text(response)}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise FDMAuthenticationError(
                "Token endpoint returned invalid JSON"
            ) from exc

        if not isinstance(data, dict) or not data.get("access_token"):
            raise FDMAuthenticationError(
                "Token response did not contain access_token"
            )
        self._debug("Token request using %s grant succeeded", grant_type)
        return data

    @staticmethod
    def _state_from_response(data: Mapping[str, Any]) -> TokenState:
        now = time.monotonic()
        try:
            expires_in = validate_lifetime(data["expires_in"], name="expires_in")
        except (KeyError, ValueError) as exc:
            raise FDMAuthenticationError(
                "Token response contained an invalid expires_in value"
            ) from exc

        refresh_token = data.get("refresh_token")
        refresh_expires_at: float | None = None
        if refresh_token:
            try:
                refresh_expires_at = now + validate_lifetime(
                    data["refresh_expires_in"], name="refresh_expires_in"
                )
            except (KeyError, ValueError) as exc:
                raise FDMAuthenticationError(
                    "Token response contained an invalid refresh_expires_in value"
                ) from exc

        try:
            access_token = validate_opaque_value(
                data["access_token"], name="access_token", maximum=MAX_TOKEN_LENGTH
            )
            validated_refresh = (
                validate_opaque_value(
                    refresh_token, name="refresh_token", maximum=MAX_TOKEN_LENGTH
                )
                if refresh_token
                else None
            )
            token_type = validate_opaque_value(
                data.get("token_type", "Bearer"), name="token_type", maximum=32
            )
        except (KeyError, ValueError) as exc:
            raise FDMAuthenticationError(
                "Token response contained an invalid token field"
            ) from exc

        return TokenState(
            access_token=access_token,
            refresh_token=validated_refresh,
            access_expires_at=now + expires_in,
            refresh_expires_at=refresh_expires_at,
            token_type=token_type,
        )

    def authenticate(self) -> None:
        """Obtain a password-granted token pair."""
        with self._token_lock:
            self._ensure_open()
            self._debug("Authenticating with password grant")
            data = self._token_post(
                {
                    "grant_type": "password",
                    "username": self._username,
                    "password": self._password,
                }
            )
            self._token = self._state_from_response(data)
            self._debug("Authentication succeeded")

    def refresh(self) -> None:
        """Exchange the current refresh token for a new token pair."""
        with self._token_lock:
            self._ensure_open()
            if self._token is None or not self._token.refresh_valid():
                # The refresh token is absent/expired; authenticate again.
                self._debug(
                    "Refresh token unavailable or expired; re-authenticating"
                )
                self.authenticate()
                return

            self._debug("Refreshing access token with refresh grant")
            data = self._token_post(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": self._token.refresh_token,
                }
            )
            self._token = self._state_from_response(data)
            self._debug("Token refresh succeeded")

    def _ensure_access_token(self) -> str:
        with self._token_lock:
            self._ensure_open()
            if self._token is None:
                self._debug("No cached token available; authenticating")
                self.authenticate()
            elif not self._token.access_valid():
                self._debug("Cached access token expired; refreshing")
                self.refresh()

            assert self._token is not None
            return self._token.access_token

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        retry_once_on_401: bool = True,
    ) -> Response:
        """
        Send an authenticated FDM API request.

        path can be:
          * Relative to /api/fdm/{api_version}/, e.g. "object/networks"
          * An absolute path under the same API root, e.g.
            "/api/fdm/latest/object/networks"

        The method returns requests.Response after raise_for_status-style
        validation. JSON callers can use response.json().
        """
        self._ensure_open()
        method = validate_http_method(method)

        url = self._build_url(path)
        request_path = urlparse(url).path
        request_headers = validate_headers(headers)
        request_params = validate_query_params(params)
        request_body = encode_json_payload(json)
        request_headers["Authorization"] = (
            f"Bearer {self._ensure_access_token()}"
        )

        self._debug("Sending %s request to %s", method, request_path)

        try:
            response = self.session.request(
                method,
                url,
                params=request_params,
                data=request_body,
                headers=request_headers,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            raise FDMRequestError(
                "TLS validation failed during the FDM API request"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise FDMRequestError(f"FDM API request failed: {exc}") from exc

        if response.is_redirect:
            raise FDMRequestError(
                f"Unexpected redirect from FDM API (HTTP {response.status_code})"
            )

        # A 401 can mean that the device invalidated the session before our
        # local timer did. Refresh/re-authenticate once, then replay once.
        if response.status_code == 401 and retry_once_on_401:
            self._debug(
                "Received HTTP 401 for %s %s; refreshing credentials and retrying once",
                method,
                request_path,
            )
            with self._token_lock:
                self._token = None
            request_headers["Authorization"] = (
                f"Bearer {self._ensure_access_token()}"
            )
            try:
                response = self.session.request(
                    method,
                    url,
                    params=request_params,
                    data=request_body,
                    headers=request_headers,
                    timeout=self._timeout,
                    allow_redirects=False,
                )
            except requests.exceptions.RequestException as exc:
                raise FDMRequestError(
                    f"FDM API retry after authentication failed: {exc}"
                ) from exc

        if not response.ok:
            self._debug(
                "%s request to %s failed with HTTP %s",
                method,
                request_path,
                response.status_code,
            )
            raise FDMRequestError(
                f"{method} {urlparse(url).path} failed with "
                f"HTTP {response.status_code}: {self._safe_error_text(response)}"
            )
        self._debug(
            "%s request to %s completed with HTTP %s",
            method,
            request_path,
            response.status_code,
        )
        return response

    def get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Convenience method for authenticated GET requests returning JSON."""
        response = self.request("GET", path, params=params)
        try:
            return response.json()
        except ValueError as exc:
            raise FDMRequestError(
                f"GET {urlparse(response.url).path} returned invalid JSON"
            ) from exc

    def revoke(self) -> None:
        """
        Revoke the current password-granted access token.

        Revocation itself requires a valid password-granted access token.
        The current token is used to revoke itself.
        """
        with self._token_lock:
            if self._token is None:
                return

            self._debug("Revoking current access token")
            access_token = self._token.access_token
            try:
                self._token_post(
                    {
                        "grant_type": "revoke_token",
                        "access_token": access_token,
                        "token_to_revoke": access_token,
                    }
                )
            finally:
                self._token = None

    def close(self) -> None:
        """Best-effort token revocation followed by local session cleanup."""
        if self._closed:
            return
        try:
            self.revoke()
        except FDMAuthenticationError:
            # The token might already be expired or invalidated. Local cleanup
            # must still happen. Call revoke() directly when the caller needs
            # revocation failures to propagate.
            pass
        finally:
            self._debug("Closing client session")
            self._password = ""
            self.session.close()
            self._shutdown_debug_logging()
            self._closed = True

    def _build_url(self, path: str) -> str:
        normalized = validate_relative_api_path(path)
        api_prefix = urlparse(self.base_url).path.lstrip("/")
        if normalized.startswith(api_prefix):
            origin = self.base_url.split("/api/", 1)[0] + "/"
            url = urljoin(origin, normalized)
        else:
            url = urljoin(self.base_url, normalized)

        base = urlparse(self.base_url)
        target = urlparse(url)
        if (target.scheme, target.netloc) != (base.scheme, base.netloc):
            raise ValueError("Request path escaped the configured FDM origin")
        if not target.path.startswith(base.path):
            raise ValueError("Request path escaped the configured FDM API root")
        return url

    def _ensure_open(self) -> None:
        if self._closed:
            raise FDMError("FDMClient is closed")

    def _shutdown_debug_logging(self) -> None:
        if not self._log_handlers:
            return

        for handler in self._log_handlers:
            try:
                handler.flush()
            finally:
                self._logger.removeHandler(handler)
                handler.close()
        self._log_handlers = []
