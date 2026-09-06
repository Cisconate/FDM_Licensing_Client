"""Helpers for bootstrapping and locating a project-local FDM certificate store."""

from __future__ import annotations

import socket
import ssl
import tempfile
import math
from pathlib import Path

from security_validation import (
    resolve_operator_path,
    validate_host,
    validate_plain_filename,
    validate_port,
)

DEFAULT_BUNDLE_NAME = "fdm-ca-bundle.pem"
MAX_CERTIFICATE_BUNDLE_BYTES = 2 * 1024 * 1024


def certificate_bundle_path(
    certificate_store_dir: str | Path,
    *,
    bundle_name: str = DEFAULT_BUNDLE_NAME,
) -> Path:
    """
    Return the PEM bundle file inside a certificate store directory.

    The directory is intentionally kept simple so it can be checked into a
    project-local workflow or created on demand during bootstrap.
    """
    store_dir = resolve_operator_path(
        certificate_store_dir, name="certificate_store_dir"
    )
    return store_dir / validate_plain_filename(bundle_name)


def bootstrap_certificate_store(
    *,
    host: str,
    port: int = 443,
    certificate_store_dir: str | Path,
    bundle_name: str = DEFAULT_BUNDLE_NAME,
    timeout: float = 5.0,
) -> Path:
    """
    Fetch the server certificate over an intentionally unverified TLS session
    and save it into a local PEM bundle.

    This is intended for initial trust establishment against a device that
    presents a self-signed certificate before the normal verification flow is
    available.
    """
    host = validate_host(host)
    socket_host = host[1:-1] if host.startswith("[") else host
    port = validate_port(port)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 0 < float(timeout) <= 300
    ):
        raise ValueError("timeout must be finite and between 0 and 300 seconds")
    bundle_name = validate_plain_filename(bundle_name)

    store_dir = resolve_operator_path(
        certificate_store_dir, name="certificate_store_dir"
    )
    store_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = store_dir / bundle_name

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((socket_host, port), timeout=float(timeout)) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=socket_host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)

    if not der_cert:
        raise RuntimeError("FDM endpoint did not present a certificate")

    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    if not pem_cert.endswith("\n"):
        pem_cert += "\n"

    if bundle_path.is_symlink():
        raise ValueError("certificate bundle must not be a symbolic link")
    if bundle_path.exists():
        if not bundle_path.is_file():
            raise ValueError("certificate bundle path must be a regular file")
        if bundle_path.stat().st_size > MAX_CERTIFICATE_BUNDLE_BYTES:
            raise ValueError("certificate bundle exceeds the maximum size")
        existing = bundle_path.read_text(encoding="utf-8")
        if pem_cert in existing:
            return bundle_path
        if existing and not existing.endswith("\n"):
            existing += "\n"
        updated = existing + ("\n" if existing else "") + pem_cert
    else:
        updated = pem_cert

    if len(updated.encode("utf-8")) > MAX_CERTIFICATE_BUNDLE_BYTES:
        raise ValueError("certificate bundle exceeds the maximum size")

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        dir=str(store_dir),
        prefix=f".{bundle_path.name}.",
        suffix=".tmp",
    ) as tmp:
        tmp.write(updated)
        temp_path = Path(tmp.name)

    temp_path.replace(bundle_path)
    return bundle_path
