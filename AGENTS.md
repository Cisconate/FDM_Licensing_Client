# Contributor and Agent Guide

## Project scope

This repository contains standalone Python modules for:

- local FDM authentication and REST requests;
- FDM certificate trust bootstrap;
- Cisco Support API OAuth2 client-credentials authentication; and
- Cisco Smart Licensing/PLR requests.

Keep endpoint-specific payloads and policy decisions in calling code unless a
well-documented, reusable interface is intentionally added.

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

## Development workflow

1. Use Python 3.10 or newer in a virtual environment.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Keep changes focused and update `README.md` when public behavior changes.
4. Co-develop tests with every behavior change and bug fix. See `TESTING.md`.
5. Run `python -m unittest discover -v` before considering a change complete.
6. Before committing, inspect `git diff --cached` and scan for secrets.

Do not perform live authentication or device-changing requests in automated
tests. Use mocks or controlled fixtures, and never record real credentials or
tokens in test data.

The sole exception is the manually dispatched Cisco OAuth integration workflow
documented in `TESTING.md`. Keep it separate from push and pull-request CI,
read credentials only from the protected GitHub Environment, and perform token
acquisition only. Do not add live licensing or device-changing calls to it.

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
