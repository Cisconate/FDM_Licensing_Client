"""Command-line interface for supported application capabilities."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence

from .capabilities import CAPABILITIES
from .models import CiscoCredentialsCommand, FdmBootstrapCommand, FdmConnectionCommand
from .services import (
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
            result = CiscoAuthenticationService().validate()
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
