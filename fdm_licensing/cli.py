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
from cisco_support_api_client import AccountSelection, ProductInstance
from fdm_certificate_store import certificate_bundle_path
from fdm_client import FDMAuthenticationError, FDMRequestError
from key_manager import CiscoClientCredentials, CredentialsNotFoundError, KeyManager
from .plr_workflow import FdmPlrState, ReturnHandoff, UniversalPlrWorkflowService
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

    plr = commands.add_parser(
        "plr",
        help="Inspect and perform staged Universal PLR operations",
        description=(
            "Inspect is read-only. Reserve changes Cisco licensing state; install "
            "changes FDM state. Return-generate cancels FDM authorization and "
            "return-complete removes the CSSM product instance through API v3. "
            "Secrets and handoff codes are never accepted as command-line arguments."
        ),
    )
    plr_commands = plr.add_subparsers(dest="plr_command", required=True)
    for name in (
        "run", "inspect", "reserve", "install", "return-inspect",
        "return-generate", "return-complete", "return",
    ):
        operation = plr_commands.add_parser(
            name,
            epilog=f"example: fdm-licensing plr {name} --host 192.0.2.10",
        )
        operation.add_argument(
            "--host", help="FDM hostname or IP address; prompted when omitted"
        )
        operation.add_argument("--port", type=int)
        operation.add_argument("--username")
        operation.add_argument("--api-version", default="latest")
        operation.add_argument("--certificate-store-dir", default="certificates")
        operation.add_argument(
            "--unattended", action="store_true",
            help=(
                "bypass licensing mutation confirmations after validating all inputs; "
                "requires an existing trusted FDM certificate"
            ),
        )
        if name in {"run", "reserve", "return-generate", "return-complete", "return"}:
            operation.add_argument(
                "--smart-account",
                help="exact smart-account domain, ID, or name; prompted when omitted",
            )
            operation.add_argument(
                "--virtual-account",
                help="exact virtual-account ID or name; prompted when omitted",
            )
        if name == "return-complete":
            operation.add_argument("--product-id", help="exact device PID; prompted when omitted")
            operation.add_argument("--serial-number", help="exact device serial; prompted when omitted")
            operation.add_argument("--product-tag", help="exact CSSM product tag; prompted when omitted")
    return parser


def _fdm_command(args) -> FdmConnectionCommand:
    manager = KeyManager()
    try:
        if args.host:
            stored = manager.get_fdm_credentials(host=args.host)
        else:
            stored = manager.get_fdm_credentials()
    except CredentialsNotFoundError:
        stored = None
    host = args.host or (stored.host if stored is not None else None)
    if not host:
        if not sys.stdin.isatty():
            raise ValueError("--host is required when input is not interactive")
        host = input("FDM hostname or IP address: ").strip()
        try:
            stored = manager.get_fdm_credentials(host=host)
        except CredentialsNotFoundError:
            stored = None
    port = args.port or (
        stored.port if stored is not None and stored.host == host else 443
    )
    username = args.username or (
        stored.username
        if stored is not None and stored.host == host and stored.port == port
        else "admin"
    )
    if (
        stored is not None
        and stored.host == host
        and stored.port == port
        and stored.username == username
    ):
        password = stored.password
    else:
        password = getpass.getpass(f"Password for {username}@{host}: ")
    return FdmConnectionCommand.from_untrusted(
        host=host,
        port=port,
        username=username,
        password=password,
        api_version=args.api_version,
        certificate_store_dir=args.certificate_store_dir,
    )


def _confirmed(
    prompt: str, *, unattended: bool = False, notification: str | None = None
) -> bool:
    if unattended:
        print(notification or prompt.rstrip("?"))
        return True
    if not sys.stdin.isatty():
        raise ValueError("interactive confirmation is required for this mutation")
    return input(f"{prompt} [y/N]: ").strip().casefold() in {"y", "yes"}


def _ensure_fdm_certificate(
    command: FdmConnectionCommand, *, unattended: bool = False
) -> None:
    """Offer explicit trust bootstrap when the configured bundle is absent."""
    bundle = certificate_bundle_path(command.certificate_store_dir)
    if bundle.is_file():
        return
    if unattended:
        raise RuntimeError(
            "unattended mode requires an existing trusted FDM certificate bundle"
        )
    _bootstrap_fdm_certificate(command)


def _bootstrap_fdm_certificate(command: FdmConnectionCommand) -> None:
    if not _confirmed(
        f"No trusted FDM certificate exists for this workflow. Fetch the "
        f"certificate currently presented by {command.host}:{command.port}?"
    ):
        raise RuntimeError("FDM certificate bootstrap was declined")
    result = FdmCertificateService().bootstrap(
        FdmBootstrapCommand.from_untrusted(
            host=command.host,
            port=command.port,
            certificate_store_dir=command.certificate_store_dir,
        )
    )
    print(f"{result.title}: {result.message}")
    if not _confirmed("I verified this fingerprint through a trusted channel. Continue?"):
        raise RuntimeError("FDM certificate fingerprint was not confirmed")


def _with_certificate_recovery(
    command: FdmConnectionCommand, operation, *, unattended: bool = False
):
    """Retry once after an explicitly verified bootstrap on a TLS trust failure."""
    try:
        return operation()
    except (FDMAuthenticationError, FDMRequestError) as exc:
        if "TLS validation failed" not in str(exc):
            raise
        if unattended:
            raise RuntimeError(
                "unattended mode cannot replace or bootstrap FDM trust material"
            ) from exc
        _bootstrap_fdm_certificate(command)
        return operation()


def _cisco_credentials(*, unattended: bool = False) -> CiscoClientCredentials:
    """Use stored credentials, or securely collect a session pair when absent."""
    manager = KeyManager()
    try:
        return manager.get_cisco_credentials()
    except CredentialsNotFoundError:
        if not sys.stdin.isatty():
            raise ValueError(
                "Cisco credentials are missing and cannot be prompted non-interactively"
            ) from None
        command = CiscoCredentialsCommand.from_untrusted(
            input("Cisco Client ID: "), getpass.getpass("Cisco Client Secret: ")
        )
        save = False if unattended else input(
            "Save these credentials in the operating-system vault? [y/N]: "
        ).strip().casefold() in {"y", "yes"}
        if save:
            manager.store_cisco_credentials(command.client_id, command.client_secret)
            print("Cisco credentials stored in the operating-system vault.")
        else:
            print("Cisco credentials will be used for this session only.")
        return CiscoClientCredentials(command.client_id, command.client_secret)


def _select_account(options, supplied, *, label, keys, display):
    if not options:
        raise RuntimeError(f"No accessible {label}s were returned")
    if supplied is not None:
        if supplied.isdigit() and 1 <= int(supplied) <= len(options):
            return options[int(supplied) - 1]
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
    raw = input(
        f"Select {label} by number or exact name [1-{len(options)}]: "
    ).strip()
    try:
        index = int(raw)
    except ValueError:
        matches = [
            item for item in options
            if any(raw.casefold() == value.casefold() for value in keys(item))
        ]
        if len(matches) != 1:
            raise ValueError(f"{label} name is unknown or ambiguous")
        return matches[0]
    else:
        if not 1 <= index <= len(options):
            raise ValueError(f"{label} selection is out of range")
        return options[index - 1]


def _select_cisco_accounts(args, accounts):
    smart = _select_account(
        accounts.list_smart_accounts(), args.smart_account,
        label="smart account",
        keys=lambda item: (item.domain, item.account_id, item.name),
        display=lambda item: f"{item.name} ({item.domain})",
    )
    virtual = _select_account(
        accounts.list_virtual_accounts(smart), args.virtual_account,
        label="virtual account",
        keys=lambda item: (item.account_id, item.name),
        display=lambda item: item.name,
    )
    return AccountSelection(smart, virtual)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    active_workflow: UniversalPlrWorkflowService | None = None
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
            credentials = _cisco_credentials()
            if args.cisco_command == "auth-check":
                result = CiscoAuthenticationService(credentials=credentials).validate()
            else:
                service = CiscoAccountService(credentials=credentials)
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
        elif args.command == "plr":
            command = _fdm_command(args)
            _ensure_fdm_certificate(command, unattended=args.unattended)
            credentials = (
                _cisco_credentials(unattended=args.unattended)
                if args.plr_command in {
                    "run", "reserve", "return-generate", "return-complete", "return"
                }
                else None
            )
            workflow = UniversalPlrWorkflowService(credentials=credentials)
            workflow.start_reuse()
            active_workflow = workflow
            if args.plr_command == "inspect":
                inspection = _with_certificate_recovery(
                    command, lambda: workflow.inspect_fdm(command),
                    unattended=args.unattended,
                )
                result = OperationResult(
                    "Universal PLR inspection",
                    f"State: {inspection.state.value}; Smart Agent connections: "
                    f"{inspection.connection_count}; request codes: "
                    f"{len(inspection.request_codes)}.",
                )
            elif args.plr_command == "return-inspect":
                identity = _with_certificate_recovery(
                    command, lambda: workflow.inspect_return(command),
                    unattended=args.unattended,
                )
                result = OperationResult(
                    "Universal PLR return inspection",
                    f"FDM return state: {identity.registration_status}; device: "
                    f"{identity.platform_model}; serial: {identity.serial_number}.",
                )
            elif args.plr_command == "return-complete":
                supplied_identity = all(
                    (args.product_id, args.serial_number, args.product_tag)
                )
                if supplied_identity:
                    selection = _select_cisco_accounts(args, workflow)
                    product_id = args.product_id
                    serial = args.serial_number
                    tag = args.product_tag
                else:
                    location = workflow.locate_return(command)
                    selection = location.selection
                    instance = location.instance
                    print(
                        f"Located {instance.product_id}/{instance.serial_number} in "
                        f"{selection.smart_account.name} / {selection.virtual_account.name}."
                    )
                    product_id = instance.product_id
                    serial = instance.serial_number
                    tag = instance.product_tag
                return_code = getpass.getpass("Universal PLR return code: ")
                instance = ProductInstance(
                    instance_name=f"UDI_PID:{product_id}; UDI_SN:{serial};",
                    product_tag=tag,
                    product_id=product_id,
                    serial_number=serial,
                )
                if not _confirmed(
                    f"Submit the return code for {product_id}/{serial} to Cisco v3?",
                    unattended=args.unattended,
                    notification=f"Submitting the return code for {product_id}/{serial} to Cisco v3",
                ):
                    print("Cisco return cancelled.")
                    return 0
                completed = workflow.complete_return(
                    selection, instance, return_code
                )
                if not _confirmed(
                    f"Cisco accepted the return. Complete unregister on {command.host}?",
                    unattended=args.unattended,
                    notification=f"Completing unregister on {command.host}",
                ):
                    print(
                        "FDM final unregister remains pending; rerun return-complete "
                        "with the same identity to finish it."
                    )
                    return 0
                _with_certificate_recovery(
                    command, lambda: workflow.finalize_return(command),
                    unattended=args.unattended,
                )
                result = OperationResult(
                    "Universal PLR return",
                    f"Cisco removed the product instance and FDM unregistered: {completed.message}",
                )
            elif args.plr_command in {"return-generate", "return"}:
                location = workflow.locate_return(command)
                selection = location.selection
                instance = location.instance
                print(
                    f"Located {instance.product_id}/{instance.serial_number} in "
                    f"{selection.smart_account.name} / {selection.virtual_account.name}."
                )
                return_identity = workflow.inspect_return(command)
                if return_identity.registration_status == "PLR_DEACTIVATION_IN_PROGRESS":
                    if args.plr_command == "return-generate":
                        raise RuntimeError(
                            "FDM already generated a return code; use plr return-complete"
                        )
                    return_code = getpass.getpass("Existing Universal PLR return code: ")
                    handoff = ReturnHandoff(return_code, instance)
                else:
                    if not _confirmed(
                        f"Return Universal PLR from {command.host} for "
                        f"{instance.product_id}/{instance.serial_number}?",
                        unattended=args.unattended,
                        notification=(
                            f"Returning Universal PLR from {command.host} for "
                            f"{instance.product_id}/{instance.serial_number}"
                        ),
                    ):
                        print("FDM return cancelled.")
                        return 0
                    handoff = _with_certificate_recovery(
                        command, lambda: workflow.generate_return(command, instance),
                        unattended=args.unattended,
                    )
                if args.plr_command == "return-generate":
                    print("FDM generated this return code. Save it until Cisco confirms removal:")
                    print(handoff.return_code)
                    print("Next, run 'fdm-licensing plr return-complete'.")
                    return 0
                print("FDM generated the return code. It will now be submitted to Cisco v3.")
                if not _confirmed(
                    f"Remove {instance.product_id}/{instance.serial_number} from "
                    f"{selection.smart_account.name} / {selection.virtual_account.name}?",
                    unattended=args.unattended,
                    notification=(
                        f"Removing {instance.product_id}/{instance.serial_number} from "
                        f"{selection.smart_account.name} / {selection.virtual_account.name}"
                    ),
                ):
                    print("Cisco completion cancelled. Save this return code:")
                    print(handoff.return_code)
                    return 0
                try:
                    completed = workflow.complete_return(
                        selection, handoff.instance, handoff.return_code
                    )
                except Exception:
                    print(
                        "FDM return succeeded but Cisco completion failed. Save this return code:",
                        file=sys.stderr,
                    )
                    print(handoff.return_code, file=sys.stderr)
                    raise
                if not _confirmed(
                    f"Cisco accepted the return. Complete unregister on {command.host}?",
                    unattended=args.unattended,
                    notification=f"Completing unregister on {command.host}",
                ):
                    print("Cisco return completed; FDM final unregister remains pending.")
                    return 0
                _with_certificate_recovery(
                    command, lambda: workflow.finalize_return(command),
                    unattended=args.unattended,
                )
                result = OperationResult(
                    "Universal PLR return",
                    f"FDM generated a return, Cisco removed the product instance, "
                    f"and FDM unregistered: {completed.message}",
                )
            elif args.plr_command == "install":
                authorization = getpass.getpass("Universal PLR authorization code: ")
                if not _confirmed(
                    f"Install this authorization code on {command.host}?",
                    unattended=args.unattended,
                    notification=f"Installing the authorization code on {command.host}",
                ):
                    print("Installation cancelled.")
                    return 0
                _with_certificate_recovery(
                    command, lambda: workflow.install(command, authorization),
                    unattended=args.unattended,
                )
                result = OperationResult(
                    "Universal PLR installation",
                    "FDM accepted the authorization-code installation request.",
                )
            else:
                inspection = _with_certificate_recovery(
                    command, lambda: workflow.inspect_fdm(command),
                    unattended=args.unattended,
                )
                if inspection.state is not FdmPlrState.REQUEST_CODE_AVAILABLE:
                    if inspection.state is FdmPlrState.AMBIGUOUS:
                        raise RuntimeError(
                            "FDM licensing state is ambiguous and cannot be changed safely"
                        )
                    if not _confirmed(
                        f"Configure Universal PLR on {command.host} to generate a request code?",
                        unattended=args.unattended,
                        notification=(
                            f"Configuring Universal PLR on {command.host} to generate a request code"
                        ),
                    ):
                        print("Reservation cancelled.")
                        return 0
                    inspection = workflow.configure_universal_plr(command)
                request_code = inspection.request_codes[0].code
                smart = _select_account(
                    workflow.list_smart_accounts(), args.smart_account,
                    label="smart account",
                    keys=lambda item: (item.domain, item.account_id, item.name),
                    display=lambda item: f"{item.name} ({item.domain})",
                )
                virtual = _select_account(
                    workflow.list_virtual_accounts(smart), args.virtual_account,
                    label="virtual account",
                    keys=lambda item: (item.account_id, item.name),
                    display=lambda item: item.name,
                )
                selection = AccountSelection(smart, virtual)
                summary, preflight = workflow.reservation_preview(
                    selection, request_code
                )
                if not preflight.may_reserve:
                    raise RuntimeError(
                        "Cisco already tracks this product instance. The published API "
                        "does not return its authorization code; retrieve it in Cisco "
                        "License Central, or contact TAC for a poisoned product instance."
                    )
                compatible = workflow.compatible_licenses(
                    preflight.identity.product_id, summary
                )
                if compatible:
                    print("Compatible Universal PLR license inventory:")
                    for item in compatible:
                        print(
                            f"- {item.display_name}: entitled={item.entitled}, "
                            f"in-use={item.in_use}, reserved={item.reserved}, "
                            f"available={item.available}"
                        )
                else:
                    print(
                        f"No explicit license-summary mapping is defined for "
                        f"{preflight.identity.product_id}; Cisco will validate "
                        "compatibility during reservation."
                    )
                if not _confirmed(
                    f"Reserve Universal PLR for {preflight.identity.product_id} "
                    f"in {smart.name} / {virtual.name}?",
                    unattended=args.unattended,
                    notification=(
                        f"Reserving Universal PLR for {preflight.identity.product_id} "
                        f"in {smart.name} / {virtual.name}"
                    ),
                ):
                    print("Reservation cancelled.")
                    return 0
                handoff = workflow.reserve(selection, request_code)
                if args.plr_command == "run":
                    try:
                        _with_certificate_recovery(
                            command,
                            lambda: workflow.install(
                                command, handoff.authorization_code
                            ),
                            unattended=args.unattended,
                        )
                    except Exception:
                        print(
                            "Cisco reservation succeeded but FDM installation failed. "
                            "Save this authorization code for recovery:",
                            file=sys.stderr,
                        )
                        print(handoff.authorization_code, file=sys.stderr)
                        raise
                    print(
                        "Universal PLR reservation and FDM authorization installation "
                        "completed successfully."
                    )
                    return 0
                print("Reservation completed. Save this authorization code now:")
                print(handoff.authorization_code)
                print(
                    "Next, run 'fdm-licensing plr install' and enter the code at "
                    "the secure prompt."
                )
                return 0
        elif args.fdm_command == "bootstrap-certificate":
            result = FdmCertificateService().bootstrap(
                FdmBootstrapCommand.from_untrusted(
                    host=args.host,
                    port=args.port,
                    certificate_store_dir=args.certificate_store_dir,
                )
            )
        else:
            command = _fdm_command(args)
            result = FdmAuthenticationService().validate(command)
        print(f"{result.title}: {result.message}")
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if active_workflow is not None:
            active_workflow.close()


if __name__ == "__main__":
    raise SystemExit(main())
