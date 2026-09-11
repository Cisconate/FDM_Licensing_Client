# Contributor and Agent Guide

## Document authority and starting point

Read this file first. Its contributor requirements and security rules are
mandatory. Use the following documents for detail:

1. `SECURITY.md` owns trust-boundary, validation, and output-encoding rules.
2. `TESTING.md` owns mocked and live-test construction and execution.
3. `CREDENTIAL_MANAGEMENT.md` owns credential storage and retrieval.
4. `README.md` describes supported behavior and routes work to modules.
5. `ROADMAP.md` records desired future enhancements and priorities. A roadmap
   entry is not approval to invent an API contract or perform a live change.

For a code change, inspect the routed module, its directly imported project
modules, and its associated tests. A repository-wide read is unnecessary unless
the requested behavior crosses those boundaries.

## Project scope

This repository contains standalone Python modules for:

- local FDM authentication and REST requests;
- FDM certificate trust bootstrap;
- Cisco Support API OAuth2 client-credentials authentication; and
- Cisco Smart Licensing/PLR requests.

Keep endpoint-specific payloads and policy decisions in calling code unless a
well-documented, reusable interface is intentionally added.

The transport library remains synchronous. Application services coordinate
workflows, and the CLI and GUI call those services rather than transport clients
directly. Preserve public constructor and method behavior unless a change
intentionally documents a compatibility break. Do not invent Cisco endpoint
paths, payload schemas, or version policy.

Design the system around cohesive, loosely coupled modules with clear
interfaces. Within those modules, prefer focused operations that perform one
well-defined responsibility. Make operations atomic where partial completion
would create an invalid or ambiguous system state. Do not decompose code merely
to make functions smaller; decompose where doing so creates a meaningful
abstraction, reusable operation, test boundary, or failure boundary.

FDM capability workflows must enter `FDMClient` through its context manager so
authentication occurs before the system-information compatibility check. Add a
tested `FdmApiProfile` for each newly supported FTD major/minor release and keep
route differences inside that profile; do not scatter version comparisons
through services, CLI code, or GUI code. Both presentation layers must surface
the same bounded unsupported-version error from the shared service.

## Change routing

| Responsibility | Primary module/API | Tests and related guidance |
| --- | --- | --- |
| Local FDM authentication and REST | `fdm_client.py` / `FDMClient` | `tests/test_security_validation.py`; add focused FDM tests; `SECURITY.md` |
| FDM certificate bootstrap | `fdm_certificate_store.py` | `tests/test_security_validation.py`; add focused certificate tests; `SECURITY.md` |
| FDM Universal PLR operations | `fdm_plr_client.py` / `FdmPlrClient` | `tests/test_plr_workflow.py`; `PLR_WORKFLOW.md`; `SECURITY.md` |
| FTD compatibility and API profiles | `fdm_compatibility.py` | `tests/test_fdm_compatibility.py`; README; validate before capability calls |
| Cisco OAuth token generation | `cisco_support_token_client.py` / `CiscoSupportTokenClient` | `tests/test_key_manager.py`, `tests/test_live_cisco_token.py`; credential guide |
| Cisco credential storage | `key_manager.py` / `KeyManager` | `tests/test_key_manager.py`; credential guide |
| Smart Licensing requests | `cisco_support_api_client.py` / `CiscoPlrReservationClient` | `tests/test_key_manager.py`, `tests/test_security_validation.py`; add endpoint tests; `SECURITY.md` |
| Shared boundary validation | `security_validation.py` | `tests/test_security_validation.py`; `SECURITY.md` |
| CLI/environment behavior | `example.py` and module `main` functions | Add or update focused CLI tests; README |
| CI and agent test policy | `.github/workflows`, `TESTING.md` | Pull-request template |
| Shared application workflows | `fdm_licensing/services.py` | `tests/test_application.py` |
| CLI commands and desktop menu | `fdm_licensing/cli.py`, `fdm_licensing/gui` | `tests/test_application.py`; `PACKAGING.md` |
| Capability registration | `fdm_licensing/capabilities.py` | `tests/test_application.py` |
| Future enhancements and priorities | `ROADMAP.md` | Create a linked issue when work is scheduled |

## Security invariants

- Do not hardcode or commit credentials, tokens, private keys, or customer data.
- Do not log authorization headers, passwords, tokens, or request bodies.
- TLS verification remains enabled by default.
- Any unverified TLS operation must be explicit and limited to certificate
  bootstrap or another clearly documented trust-establishment workflow.
- Do not automatically retry mutating requests. A single retry after HTTP 401
  is intentional; broader retries require idempotency analysis.
- Reject absolute or cross-origin request paths. Preserve the URL-boundary
  checks in both API clients.
- Keep error output bounded and avoid including request headers or request data.
- Close sessions, clear cached credentials, and revoke tokens where supported.

## Input-boundary standard

Follow `SECURITY.md` for every external input. Validate and normalize once at
the public boundary that owns the value, then pass a stable trusted
representation internally without repeated validation. Treat CLI arguments,
environment variables, public API arguments, callbacks, credential stores,
filesystem content, and every HTTP response as untrusted inputs.

Do not apply generic escaping. Validate against the destination's grammar,
reject malformed security-sensitive input, preserve validated opaque secrets,
and encode at the output sink. Every feature that adds or changes an input must
co-develop boundary tests and update the boundary inventory when appropriate.

## Development workflow

1. Use Python 3.10 or newer in a virtual environment.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Keep changes focused and update `README.md` when public behavior changes.
4. Co-develop tests with every behavior change and bug fix. See `TESTING.md`.
5. Run `python -m unittest discover -v` before considering a change complete.
6. Before committing, inspect `git diff --cached` and scan for secrets.

### Command-line usage contract

Treat each executable Python module and installed console command as a public
interface. Every CLI must provide `--help` through `argparse` and describe all
commands, switches, defaults or environment-variable fallbacks, security-
relevant effects, and at least one copy/paste example where the invocation is
not obvious. When adding or changing a switch, update the parser help, the
relevant README or operator guide, and a focused help/argument test in the same
change. Keep the standard human test commands in `TESTING.md` current. Help
must not initialize credential stores, prompt, access the network, or expose
secrets.

Use mocks or controlled fixtures for every feature and bug fix; never record
real credentials or tokens in test data. In addition, run applicable live tests
when the current system has the complete credentials and non-secret endpoint
configuration required by that module. A live test supplements mocked tests and
never replaces them.

Live tests may authenticate and use documented read-only operations. Do not add
live mutating licensing or device-changing calls unless the user explicitly
authorizes the exact test, endpoint, target, and cleanup behavior. Read local
credentials through the approved OS credential store. Hosted workflows must
read credentials from protected CI secrets. A missing credential or endpoint
causes a clearly reported skip; an available but invalid credential causes a
test failure. Report live-test pass, failure, or skip status in the final result.

Agent-executed macOS Keychain tests must use elevated permissions when the
execution sandbox otherwise blocks native Keychain access. Do not interpret a
sandbox-denied Keychain read as credential absence or credential rejection.

When a request includes `Test requirement: <behavior>` or `[test-required]`,
treat the stated behavior as an acceptance criterion. Add or update a focused
`unittest` test in the same change, use mocks at network and credential-store
boundaries, and report the exact test command and result. Do not claim the work
is complete while that test is missing or failing. Tests are expected for all
observable behavior changes even when the request omits the marker. A test may
be omitted only for documentation-only or other non-behavioral changes, and
the final response must state why.

## Style

- Preserve type annotations and focused exception classes.
- Prefer context managers for deterministic client cleanup.
- Keep public docstrings current and make secure behavior the default.
- Avoid adding dependencies when the Python standard library or existing
  `requests` dependency is sufficient.
