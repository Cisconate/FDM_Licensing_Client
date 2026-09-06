# FDM Client

A small Python client for working with Cisco Firewall Device Manager (FDM),
plus supporting clients for Cisco Support API authentication and Smart
Licensing reservation requests.

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
revocation and session cleanup on exit.

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

For secure cross-platform credential storage, use `key_manager.py`. It stores
the Cisco Client ID and Client Secret in the native OS credential store and
never prints stored values:

```bash
python key_manager.py store
python key_manager.py status
python cisco_support_token_client.py --check
```

See [CREDENTIAL_MANAGEMENT.md](CREDENTIAL_MANAGEMENT.md) for platform support,
macOS Keychain setup, application integration, and testing guidance.

## Project layout

| File | Purpose |
| --- | --- |
| `fdm_client.py` | Authenticated FDM REST client |
| `fdm_certificate_store.py` | Certificate bundle bootstrap and lookup |
| `example.py` | Command-line FDM example |
| `cisco_support_token_client.py` | Cisco OAuth2 token acquisition and caching |
| `cisco_support_api_client.py` | Smart Licensing/PLR request client |
| `security_validation.py` | Shared trust-boundary validation and safe encoding |
| `requirements.txt` | Runtime dependency constraints |
| `test_*.py` | Unit tests plus the conditional live OAuth test |
| `TESTING.md` | Local, CI, and agent-generated testing policy |
| `SECURITY.md` | Input-boundary inventory and coding standard |

## Automated tests and CI

Run the complete test suite from the project root:

```bash
python -m unittest discover -v
```

The unit tests use mocks and do not require live FDM or Cisco credentials.
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
