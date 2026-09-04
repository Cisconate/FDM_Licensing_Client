"""Helpers for bootstrapping and locating a project-local FDM certificate store."""

from __future__ import annotations

import socket
import ssl
import tempfile
from pathlib import Path

DEFAULT_BUNDLE_NAME = "fdm-ca-bundle.pem"


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
    store_dir = Path(certificate_store_dir).expanduser().resolve()
    return store_dir / bundle_name


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
    if not host or "/" in host or "://" in host:
        raise ValueError("host must be a hostname or IP address only")
    if not (1 <= port <= 65535):
        raise ValueError("port must be between 1 and 65535")
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")

    store_dir = Path(certificate_store_dir).expanduser().resolve()
    store_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = store_dir / bundle_name

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)

    if not der_cert:
        raise RuntimeError("FDM endpoint did not present a certificate")

    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    if not pem_cert.endswith("\n"):
        pem_cert += "\n"

    if bundle_path.exists():
        existing = bundle_path.read_text(encoding="utf-8")
        if pem_cert in existing:
            return bundle_path
        if existing and not existing.endswith("\n"):
            existing += "\n"
        updated = existing + ("\n" if existing else "") + pem_cert
    else:
        updated = pem_cert

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
