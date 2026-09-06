"""Validation helpers for values crossing external trust boundaries."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit, urlunsplit

MAX_CREDENTIAL_LENGTH = 8192
MAX_TOKEN_LENGTH = 16384
MAX_HEADER_LENGTH = 8192
MAX_PATH_LENGTH = 2048
MAX_ERROR_LENGTH = 1000
MAX_TIMEOUT_SECONDS = 300.0
MAX_RESPONSE_LIFETIME_SECONDS = 365 * 24 * 60 * 60
MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
MAX_QUERY_PARAMETERS = 1000

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_API_VERSION = re.compile(r"^v[1-9][0-9]*$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _has_control_characters(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def validate_opaque_value(value: str, *, name: str, maximum: int) -> str:
    """Validate an opaque credential/token without changing its bytes."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds the maximum length")
    if _has_control_characters(value):
        raise ValueError(f"{name} contains control characters")
    return value


def validate_host(host: str) -> str:
    """Return a canonical DNS, IPv4, or bracketed IPv6 host."""
    if not isinstance(host, str) or not host or host != host.strip():
        raise ValueError("host must be a hostname or IP address only")
    if len(host) > 255 or _has_control_characters(host):
        raise ValueError("host must be a hostname or IP address only")

    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if any(char in host for char in "/\\:@?#[]"):
            raise ValueError("host must be a hostname or IP address only")
        try:
            ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("host is not a valid DNS name") from exc
        if not ascii_host or len(ascii_host) > 253:
            raise ValueError("host is not a valid DNS name")
        if any(not _DNS_LABEL.fullmatch(label) for label in ascii_host.split(".")):
            raise ValueError("host is not a valid DNS name")
        return ascii_host
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return port


def validate_timeout(timeout: tuple[float, float]) -> tuple[float, float]:
    if not isinstance(timeout, tuple) or len(timeout) != 2:
        raise ValueError("timeout must be a (connect, read) tuple")
    values: list[float] = []
    for value in timeout:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("timeout values must be numbers")
        number = float(value)
        if not math.isfinite(number) or not 0 < number <= MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout values must be finite and between 0 and 300 seconds")
        values.append(number)
    return values[0], values[1]


def validate_lifetime(value: Any, *, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        lifetime = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 1 <= lifetime <= MAX_RESPONSE_LIFETIME_SECONDS:
        raise ValueError(f"{name} must be between 1 second and 1 year")
    return lifetime


def validate_api_version(value: str) -> str:
    if value == "latest":
        return value
    if not isinstance(value, str) or not _API_VERSION.fullmatch(value):
        raise ValueError("api_version must be 'latest' or a version such as 'v6'")
    return value


def validate_https_base_url(value: str, *, name: str = "base_url") -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a valid HTTPS URL")
    if len(value) > MAX_PATH_LENGTH or _has_control_characters(value):
        raise ValueError(f"{name} must be a valid HTTPS URL")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"{name} must use https://")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{name} must not contain user information")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{name} must not contain a query or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} contains an invalid port") from exc
    host = validate_host(parsed.hostname)
    validate_relative_api_path(parsed.path or "/")
    netloc = host if port is None else f"{host}:{validate_port(port)}"
    path = parsed.path.rstrip("/") + "/"
    return urlunsplit(("https", netloc, path, "", ""))


def validate_relative_api_path(path: str) -> str:
    if not isinstance(path, str) or not path or path != path.strip():
        raise ValueError("path must be a non-empty relative API path")
    if len(path) > MAX_PATH_LENGTH or _has_control_characters(path) or "\\" in path:
        raise ValueError("path contains invalid characters")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("path must not contain a URL, query, or fragment")
    if _INVALID_PERCENT_ESCAPE.search(path):
        raise ValueError("path contains an invalid percent escape")
    decoded = path
    for _ in range(10):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    else:
        raise ValueError("path contains excessive nested encoding")
    if _has_control_characters(decoded) or "\\" in decoded:
        raise ValueError("path contains invalid encoded characters")
    if any(part in {".", ".."} for part in decoded.split("/")):
        raise ValueError("path must not contain traversal segments")
    return path.lstrip("/")


def validate_http_method(method: str) -> str:
    if not isinstance(method, str):
        raise ValueError("HTTP method must be a string")
    normalized = method.upper()
    if normalized not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError(f"Unsupported HTTP method: {normalized}")
    return normalized


def validate_bool(value: bool, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def validate_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        raise ValueError("headers must be a mapping")
    result: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise ValueError("header name is invalid")
        if not isinstance(value, str) or len(value) > MAX_HEADER_LENGTH:
            raise ValueError(f"header {name!r} must be a bounded string")
        if _has_control_characters(value):
            raise ValueError(f"header {name!r} contains control characters")
        if name.lower() == "authorization":
            raise ValueError("callers may not supply the Authorization header")
        result[name] = value
    return result


def validate_query_params(params: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if params is None:
        return None
    if not isinstance(params, Mapping) or len(params) > MAX_QUERY_PARAMETERS:
        raise ValueError("params must be a mapping with at most 1000 entries")
    result: dict[str, Any] = {}
    for name, value in params.items():
        if not isinstance(name, str) or not name or _has_control_characters(name):
            raise ValueError("query parameter names must be non-empty strings")
        result[name] = value
    return result


def encode_json_payload(value: Any) -> str | None:
    """Validate and snapshot a JSON value once for transmission."""
    if value is None:
        return None
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("json payload must contain only valid JSON values") from exc
    if len(encoded.encode("utf-8")) > MAX_REQUEST_BODY_BYTES:
        raise ValueError("json payload exceeds the 2 MiB maximum")
    return encoded


def validate_user_agent(value: str) -> str:
    value = validate_opaque_value(value, name="user_agent", maximum=512)
    if value != value.strip():
        raise ValueError("user_agent must not have surrounding whitespace")
    return value


def validate_plain_filename(value: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError("bundle_name must be a plain filename")
    if len(value) > 255 or Path(value).name != value or "/" in value or "\\" in value:
        raise ValueError("bundle_name must be a plain filename")
    if _has_control_characters(value):
        raise ValueError("bundle_name contains control characters")
    return value


def resolve_operator_path(value: str | Path, *, name: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise ValueError(f"{name} must be a filesystem path") from exc
    if not isinstance(raw, str) or not raw or len(raw) > 4096:
        raise ValueError(f"{name} must be a non-empty filesystem path")
    if _has_control_characters(raw):
        raise ValueError(f"{name} contains control characters")
    return Path(raw).expanduser().resolve()


def safe_error_text(value: Any, *, limit: int = MAX_ERROR_LENGTH) -> str:
    """Create bounded single-line diagnostic text from untrusted response data."""
    text = repr(value) if not isinstance(value, str) else value
    cleaned = "".join(char if ord(char) >= 32 and ord(char) != 127 else "?" for char in text)
    return cleaned[:limit]
