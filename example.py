#!/usr/bin/env python3
"""Minimal secure usage example for fdm_client.py."""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from fdm_client import FDMClient, FDMError
from fdm_certificate_store import bootstrap_certificate_store


def _environment_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError(f"${name} must be true/false, yes/no, or 1/0")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="example.py",
        description="Example FDM client usage with optional TLS verification control and certificate bootstrap.",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("FDM_HOST"),
        help="FDM hostname or IP address (default: $FDM_HOST).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=os.getenv("FDM_PORT", "443"),
        help="FDM HTTPS management port (default: $FDM_PORT or 443).",
    )
    parser.add_argument(
        "--username",
        default=os.getenv("FDM_USERNAME", "admin"),
        help="FDM username (default: $FDM_USERNAME or 'admin').",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("FDM_PASSWORD"),
        help="FDM password (default: $FDM_PASSWORD; prompts if omitted).",
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.getenv("FDM_CA_BUNDLE"),
        help="Path to CA bundle used when certificate verification is enabled "
        "(default: $FDM_CA_BUNDLE).",
    )
    parser.add_argument(
        "--certificate-store-dir",
        default=os.getenv("FDM_CERTIFICATE_STORE_DIR", "certificates"),
        help="Project-local directory used to store the bootstrapped PEM bundle "
        "(default: $FDM_CERTIFICATE_STORE_DIR or ./certificates).",
    )
    parser.add_argument(
        "--bootstrap-certificate",
        action="store_true",
        help="Fetch the device certificate without verification and save it into the local certificate store.",
    )
    parser.add_argument(
        "--api-version",
        default=os.getenv("FDM_API_VERSION", "latest"),
        help="FDM API version, such as latest or v6 (default: $FDM_API_VERSION or 'latest').",
    )
    parser.add_argument(
        "--debug-logging",
        action="store_true",
        default=_environment_bool("FDM_DEBUG_LOGGING", False),
        help="Write debug logs to the console and to fdm_client_debug.log.",
    )
    parser.add_argument(
        "--log-file",
        default=os.getenv("FDM_LOG_FILE"),
        help="Optional path for the debug log file (default: ./fdm_client_debug.log next to fdm_client.py).",
    )
    parser.add_argument(
        "--verify-certificate",
        dest="verify_certificate",
        action="store_true",
        default=_environment_bool("FDM_VERIFY_CERTIFICATE", True),
        help="Verify the FDM TLS certificate using the CA bundle.",
    )
    parser.add_argument(
        "--no-verify-certificate",
        dest="verify_certificate",
        action="store_false",
        help="Skip TLS certificate verification for self-signed initial setup.",
    )
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not args.host:
        print("Error: --host or $FDM_HOST is required", file=sys.stderr)
        return 1

    if not (1 <= args.port <= 65535):
        print("Error: --port must be between 1 and 65535", file=sys.stderr)
        return 1

    if args.bootstrap_certificate:
        try:
            bundle_path = bootstrap_certificate_store(
                host=args.host,
                port=args.port,
                certificate_store_dir=args.certificate_store_dir,
            )
            print(f"Bootstrapped certificate bundle: {bundle_path}")
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"Error bootstrapping certificate store: {exc}", file=sys.stderr)
            return 1

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    if args.verify_certificate and not args.ca_bundle:
        if not args.bootstrap_certificate:
            print(
                "Error: --ca-bundle or --bootstrap-certificate is required when certificate verification is enabled",
                file=sys.stderr,
            )
            return 1

    try:
        with FDMClient(
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            ca_bundle=args.ca_bundle,
            certificate_store_dir=args.certificate_store_dir,
            verify_certificate=args.verify_certificate,
            api_version=args.api_version,
            debug_logging=args.debug_logging,
            log_file=args.log_file,
        ) as fdm:
            # Replace this with a resource shown by the device's API Explorer.
            result = fdm.get_json("object/networks", params={"limit": 10})
            print(result)
        return 0
    except (FDMError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
