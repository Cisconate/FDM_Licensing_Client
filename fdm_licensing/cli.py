"""Command-line interface for supported application capabilities."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence

from .capabilities import CAPABILITIES
from .models import (
    CiscoCredentialsCommand,
    FdmBootstrapCommand,
    FdmConnectionCommand,
    OperationResult,
)
from .services import (
    CiscoAccountService,
    CiscoAuthenticationService,
    CredentialService,
    FdmAuthenticationService,
    FdmCertificateService,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fdm-licensing")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capabilities", help="List supported application capabilities")

    credentials = commands.add_parser("credentials", help="Manage Cisco credentials")
    credential_commands = credentials.add_subparsers(dest="credential_command", required=True)
    credential_commands.add_parser("status")
    credential_commands.add_parser("store")
    credential_commands.add_parser("delete")

    cisco = commands.add_parser("cisco", help="Cisco Internet capabilities")
    cisco_commands = cisco.add_subparsers(dest="cisco_command", required=True)
    cisco_commands.add_parser("auth-check")
    accounts = cisco_commands.add_parser(
        "accounts",
        help="Discover and select an accessible smart and virtual account",
        description=(
            "Discover Cisco smart and virtual accounts. Missing selections are "
            "prompted for only when stdin is interactive."
        ),
        epilog=(
            "example: fdm-licensing cisco accounts --smart-account example.com "
            "--virtual-account Default"
        ),
    )
    accounts.add_argument(
        "--smart-account",
        help="exact smart-account domain, ID, or display name; prompted when omitted",
    )
    accounts.add_argument(
        "--virtual-account",
        help="exact virtual-account ID or display name; prompted when omitted",
    )

    fdm = commands.add_parser("fdm", help="FTD/FDM capabilities")
    fdm_commands = fdm.add_subparsers(dest="fdm_command", required=True)
    for name in ("bootstrap-certificate", "auth-check"):
        operation = fdm_commands.add_parser(name)
        operation.add_argument("--host", required=True)
        operation.add_argument("--port", type=int, default=443)
        operation.add_argument("--certificate-store-dir", default="certificates")
        if name == "auth-check":
            operation.add_argument("--username", default="admin")
            operation.add_argument("--api-version", default="latest")
    return parser


def _select_account(options, supplied, *, label, keys, display):
    if not options:
        raise RuntimeError(f"No accessible {label}s were returned")
    if supplied is not None:
        matches = [
            item
            for item in options
            if any(supplied.casefold() == value.casefold() for value in keys(item))
        ]
        if len(matches) != 1:
            raise ValueError(f"{label} selection is unknown or ambiguous")
        return matches[0]
    if len(options) == 1:
        return options[0]
    if not sys.stdin.isatty():
        option = "--smart-account" if label == "smart account" else "--virtual-account"
        raise ValueError(f"{option} is required when input is not interactive")
    for index, item in enumerate(options, 1):
        print(f"{index}. {display(item)}")
    raw = input(f"Select {label} [1-{len(options)}]: ").strip()
    try:
        index = int(raw)
    except ValueError as exc:
        raise ValueError(f"{label} selection must be a number") from exc
    if not 1 <= index <= len(options):
        raise ValueError(f"{label} selection is out of range")
    return options[index - 1]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "capabilities":
            for capability in CAPABILITIES:
                print(f"{capability.id}: {capability.title} [{capability.risk.value}]")
            return 0

        if args.command == "credentials":
            service = CredentialService()
            if args.credential_command == "status":
                result = service.status()
            elif args.credential_command == "store":
                result = service.store(
                    CiscoCredentialsCommand.from_untrusted(
                        input("Cisco Client ID: "),
                        getpass.getpass("Cisco Client Secret: "),
                    )
                )
            else:
                if input("Delete stored Cisco credentials? [y/N]: ").strip().lower() not in {
                    "y",
                    "yes",
                }:
                    print("Deletion cancelled.")
                    return 0
                result = service.delete()
        elif args.command == "cisco":
            if args.cisco_command == "auth-check":
                result = CiscoAuthenticationService().validate()
            else:
                service = CiscoAccountService()
                smart = _select_account(
                    service.list_smart_accounts(),
                    args.smart_account,
                    label="smart account",
                    keys=lambda item: (item.domain, item.account_id, item.name),
                    display=lambda item: f"{item.name} ({item.domain})",
                )
                virtual = _select_account(
                    service.list_virtual_accounts(smart),
                    args.virtual_account,
                    label="virtual account",
                    keys=lambda item: (item.account_id, item.name),
                    display=lambda item: item.name,
                )
                result = OperationResult(
                    "Cisco account selection",
                    f"Selected {smart.name} / {virtual.name}.",
                )
        elif args.fdm_command == "bootstrap-certificate":
            result = FdmCertificateService().bootstrap(
                FdmBootstrapCommand.from_untrusted(
                    host=args.host,
                    port=args.port,
                    certificate_store_dir=args.certificate_store_dir,
                )
            )
        else:
            command = FdmConnectionCommand.from_untrusted(
                host=args.host,
                port=args.port,
                username=args.username,
                password=getpass.getpass(f"Password for {args.username}@{args.host}: "),
                api_version=args.api_version,
                certificate_store_dir=args.certificate_store_dir,
            )
            result = FdmAuthenticationService().validate(command)
        print(f"{result.title}: {result.message}")
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
