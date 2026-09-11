# FDM Client

A small Python client for working with Cisco Firewall Device Manager (FDM),
plus supporting clients for Cisco Support API authentication and Smart
Licensing reservation requests. It includes a shared CLI and Windows-first
desktop GUI foundation.

> [!IMPORTANT]
> This project is an early-stage client, not an official Cisco SDK. Validate
> requests against the API Explorer and software version on the target device
> before using it to change production configuration.

## Features

- Authenticates to an FTD device managed locally through FDM.
- Caches, refreshes, and revokes FDM access tokens.
- Sends authenticated `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` requests.
- Retries a request once after an HTTP 401 by re-authenticating.
- Verifies TLS certificates by default.
- Can bootstrap a project-local certificate bundle for initial trust setup.
- Obtains and caches Cisco Support API OAuth2 client-credentials tokens.
- Sends Smart Licensing reservation requests using a supplied bearer token.
- Provides atomic Universal PLR operations for FDM request-code generation,
  CSSM handoff, and FDM authorization-code installation.
- Avoids logging passwords, bearer tokens, and request bodies.

## Requirements

- Python 3.10 or newer
- Network access to the relevant FDM or Cisco API endpoints
- Valid credentials and permissions for those systems

Install the dependency in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Quick start: FDM

Display every supported option and its environment-variable fallback before
connecting to a device:

```bash
python example.py --help
```

The example reads configuration from environment variables and prompts for the
password when `FDM_PASSWORD` is not set:

```bash
export FDM_HOST="ftd01.example.com"
export FDM_USERNAME="admin"
python example.py --bootstrap-certificate
```

Certificate bootstrap makes one intentionally unverified TLS connection to
retrieve the certificate. Review the resulting certificate out of band before
trusting it. Subsequent API connections use the saved certificate bundle.

After the certificate has been bootstrapped, run:

```bash
python example.py
```

The included example requests `object/networks` with a limit of 10. Replace
that resource with one exposed by the target device's API Explorer.

### Supported environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `FDM_HOST` | FDM hostname or IP address | Required |
| `FDM_PORT` | HTTPS management port | `443` |
| `FDM_USERNAME` | FDM username | `admin` |
| `FDM_PASSWORD` | FDM password; prompts when omitted | None |
| `FDM_CA_BUNDLE` | Path to a trusted PEM CA bundle | None |
| `FDM_CERTIFICATE_STORE_DIR` | Local certificate directory | `certificates` |
| `FDM_API_VERSION` | API version such as `latest` or `v6` | `latest` |
| `FDM_VERIFY_CERTIFICATE` | Enable TLS verification | `true` |
| `FDM_DEBUG_LOGGING` | Enable console and file debug logging | `false` |
| `FDM_LOG_FILE` | Custom debug log path | `fdm_client_debug.log` |

See `.env.example` for a configuration template. The example does not load
`.env` files automatically; export the values in your shell or configure them
in the PyCharm run configuration.

### Library usage

```python
from fdm_client import FDMClient

with FDMClient(
    host="ftd01.example.com",
    username="admin",
    password="read-at-runtime",
    certificate_store_dir="certificates",
) as client:
    networks = client.get_json("object/networks", params={"limit": 10})
    print(networks)
```

Using the context manager authenticates on entry and performs best-effort token
revocation and session cleanup on exit. Immediately after authentication it
reads `operational/systeminfo/default`, validates the detected FTD software
release, and selects the matching API profile. The current supported profile is
FTD `7.6.x`; unsupported or malformed versions fail before a capability request
is sent.

## Cisco Support and Smart Licensing clients

`CiscoSupportTokenClient` obtains an OAuth2 client-credentials token. That
token can be supplied dynamically to `CiscoPlrReservationClient`:

```python
from cisco_support_api_client import CiscoPlrReservationClient
from cisco_support_token_client import CiscoSupportTokenClient
from key_manager import KeyManager

credentials = KeyManager().get_cisco_credentials()

with CiscoSupportTokenClient(
    client_id=credentials.client_id,
    client_secret=credentials.client_secret,
) as tokens:
    with CiscoPlrReservationClient(
        token_provider=tokens.get_bearer_token,
    ) as licensing:
        result = licensing.reserve_licenses(
            "REPLACE_WITH_APPROVED_ENDPOINT_PATH",
            payload={"replace": "with endpoint-specific payload"},
        )
```

The reservation route and payload depend on the approved Cisco API workflow;
the client deliberately does not guess them.

The supplied Software APIs 1.0.2 contract is available through the named APX
profile. Discover and select accessible accounts with:

```bash
fdm-licensing cisco accounts
fdm-licensing cisco accounts --smart-account example.com --virtual-account Default
```

When multiple results exist, the CLI prompts only on an interactive terminal;
automation must provide both switches. The desktop account-selection page uses
the same discovery service and opens a selector only for multiple choices.

For secure cross-platform credential storage, use `key_manager.py`. It stores
the Cisco Client ID/Secret and a device-scoped default FDM credential record in
the native OS credential store and never prints stored values:

```bash
python key_manager.py store
python key_manager.py update CISCO_CLIENT
python key_manager.py update FDM
python key_manager.py status
python cisco_support_token_client.py --check
```

Diagnostics distinguish missing or malformed stored values, native credential
store access failures, confirmed OAuth credential rejection, inconclusive OAuth
policy rejection, TLS/network timeouts, rate limiting, and provider failure.
They never print credential values, provider descriptions, or bearer tokens.

See [CREDENTIAL_MANAGEMENT.md](CREDENTIAL_MANAGEMENT.md) for platform support,
macOS Keychain setup, application integration, and testing guidance.

## Project layout

| File | Purpose |
| --- | --- |
| `fdm_client.py` | Authenticated FDM REST client |
| `fdm_compatibility.py` | FTD version detection and API route profiles |
| `fdm_certificate_store.py` | Certificate bundle bootstrap and lookup |
| `fdm_plr_client.py` | Atomic FDM Universal PLR operations |
| `example.py` | Command-line FDM example |
| `key_manager.py` | Native OS storage for Cisco client credentials |
| `cisco_support_token_client.py` | Cisco OAuth2 token acquisition and caching |
| `cisco_support_api_client.py` | Smart Licensing/PLR request client |
| `security_validation.py` | Shared trust-boundary validation and safe encoding |
| `fdm_licensing/` | Shared services, CLI, capability registry, and desktop GUI |
| `requirements.txt` | Runtime dependency constraints |
| `tests/` | Unit tests plus the conditional live OAuth test |
| `TESTING.md` | Local, CI, and agent-generated testing policy |
| `SECURITY.md` | Input-boundary inventory and coding standard |
| `PACKAGING.md` | Windows GUI, executable build, and extension guide |
| `ROADMAP.md` | Categorized future enhancements and performance priorities |
| `PLR_WORKFLOW.md` | Universal PLR API map, safety boundaries, and usage |

For implementation work, start with the responsibility map in `AGENTS.md`.
It identifies the owning module, public API, associated tests, and detailed
policy document so focused changes do not require reading every source file.

## CLI and desktop application

Install the project with its GUI dependency and launch either presentation:

```powershell
python -m pip install -e ".[gui]"
fdm-licensing capabilities
fdm-licensing-gui
```

The CLI exposes both an end-to-end Universal PLR command and staged recovery
commands. `run` carries the authorization code in memory from Cisco reservation
through FDM installation. `inspect` is read-only; `reserve` stops after Cisco;
and `install` securely prompts for a previously issued authorization code:

```bash
fdm-licensing plr run --host 192.0.2.10 --smart-account example.com --virtual-account Default
fdm-licensing plr inspect --host 192.0.2.10
fdm-licensing plr reserve --host 192.0.2.10 --smart-account example.com --virtual-account Default
fdm-licensing plr install --host 192.0.2.10
```

PLR return is staged across FDM and Cisco and can be run end to end with
`fdm-licensing plr return`, or resumed with `return-inspect`,
`return-generate`, and `return-complete`. Software APIs 1.0.2 has no v3
reservation-creation route, so original reservations remain on v2; return
completion uses the documented v3 product-instance removal route. Preserve the
FDM-generated return code until Cisco confirms removal.

For return workflows, the application searches Cisco globally using the FTD
serial number and derives the owning Smart and Virtual Account from the product
instance; it does not prompt for an account when exactly one match exists.
General CLI account selection accepts either the displayed number or an exact
account name/domain/ID. GUI account dialogs filter displayed matches 500 ms
after the operator stops typing.

Add `--unattended` to a `plr` command to bypass licensing mutation yes/no
confirmations after inputs have been validated. Each skipped confirmation is
replaced by a present-tense notification describing the operation. Missing
values are securely prompted when a terminal is available and fail clearly in
non-interactive execution. Secrets and handoff codes remain unavailable as
command-line arguments. Unattended mode requires an existing trusted FDM
certificate bundle and will never bootstrap or replace trust material.

Each CLI or GUI workflow reuses one authenticated FDM session and one Cisco
OAuth/licensing HTTP session until the workflow completes. Smart-account lists
and each selected account's Virtual Account list are cached only in memory and
cleared on close; no account metadata persists between executions. Independent
read-only reservation inventory and product-instance preflight requests run
concurrently.

The system-information response read during FDM compatibility validation is
also reused for device serial/model lookup, removing a duplicate API call.
Persistent account caching is intentionally avoided because its small CLI
benefit does not justify stale memberships or retained customer metadata.

```bash
fdm-licensing plr run --unattended --host 192.0.2.10 \
  --smart-account example.com --virtual-account Default
fdm-licensing plr return --unattended --host 192.0.2.10
```

If `--host`, smart-account selection, virtual-account selection, FDM password,
or Cisco credentials are missing, an interactive CLI prompts for them. When the
FDM trust bundle is absent, the workflow offers to fetch the presented
certificate, displays its SHA-256 fingerprint, and continues only after the
operator confirms out-of-band verification. The GUI validates all required
fields and provides the same guided certificate bootstrap.

When a complete FDM record exists in the OS vault, `plr` commands use it without
prompting. An explicitly supplied host, port, or username must match the stored
device identity before its password is used; otherwise the CLI prompts. Use
`python key_manager.py store` to fill only missing groups or
`python key_manager.py update FDM` to replace the record.

Passwords and authorization codes are intentionally unavailable as command-line
switches so they do not enter shell history or process listings. See
[PACKAGING.md](PACKAGING.md) to build unsigned Windows executables.

If Cisco credentials are absent, CLI and GUI workflows prompt for a Client ID
and masked Client Secret, then offer session-only use or storage in the native
OS credential vault. A vault access failure remains an error rather than being
misreported as missing credentials.

The reservation library performs an account-scoped, read-only product-instance
preflight before every Universal PLR POST. An existing matching PID and serial
blocks the mutation and directs the operator to recover the prior authorization
in Cisco License Central or contact TAC for a poisoned product instance. The
published Software APIs contract does not provide an operation for downloading
that existing authorization code.

Reservation confirmation shows explicitly compatible license inventory rather
than aggregate account totals. For example, an FPR-1010 reports the entitled,
in-use, reserved, and currently available quantities for the Firepower 1000
Threat Defense Universal License.

## Automated tests and CI

Use these standard commands from the project root:

```bash
# Complete suite: mocked tests plus the conditional live OAuth test
python -m unittest discover -v

# Safe, direct live OAuth diagnostic using credentials in the OS keyring
python cisco_support_token_client.py --check

# Show the FDM example's supported switches without making a connection
python example.py --help
```

The complete suite's deterministic tests use mocks. Its live OAuth test runs
when a complete credential pair is available in the OS keyring and skips only
when those entries are genuinely absent. Backend access errors, empty CI
secrets, and OAuth failures are test failures. The direct diagnostic makes a
real token request, returns a nonzero exit status on failure, and never prints
credential values or the token.
GitHub Actions runs the suite automatically on every push and pull request
against Python 3.10 and 3.14. See [TESTING.md](TESTING.md) for PyCharm setup,
branch protection, test-writing conventions, and the `[test-required]` agent
contract.
An additional manually triggered workflow can validate real Cisco OAuth token
generation using secrets stored in a protected GitHub Environment.
When the local OS credential store contains a complete Cisco credential pair,
the same test command automatically includes that live OAuth check; otherwise
the integration test is skipped.

## Security notes

- Never commit passwords, client secrets, bearer tokens, private keys, `.env`
  files, or debug logs.
- Prefer prompting for passwords or injecting credentials through an approved
  secret-management mechanism.
- Keep TLS verification enabled after initial certificate bootstrap.
- Verify a bootstrapped certificate fingerprint through a trusted channel.
- Keep repositories containing company code private and follow organizational
  source-control and credential-handling policies.
- Treat server error messages and debug logs as potentially sensitive even
  though this client excludes request credentials and bodies from its logs.
- Treat all external data as untrusted until it passes the owning public
  boundary. See [SECURITY.md](SECURITY.md) for validation, encoding, performance,
  and test requirements.

## Development status

There is not yet a packaged distribution. Run the example only against a device
and account where you are authorized to perform the requested operations.
Contributions should preserve the security invariants documented in `AGENTS.md`
and pass the automated unit-test suite.

## License

No license has been selected yet. Until one is added, normal copyright rules
apply; publishing the source does not automatically grant reuse rights.
