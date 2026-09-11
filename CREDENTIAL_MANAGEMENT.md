# Cisco Credential Management

## Purpose and design

`key_manager.py` stores both the Cisco OAuth Client ID/Secret and device-scoped
FDM host/port/username/password records in the operating-system
credential store. It supports macOS, Windows, and Linux via Python `keyring`
and refuses known null, failing, or plaintext backends.

The data flow is:

1. `KeyManager` retrieves the Client ID and Client Secret from secure storage.
2. `CiscoSupportTokenClient` exchanges them for a short-lived OAuth token.
3. `CiscoPlrReservationClient` receives tokens through `token_provider`.
4. Context managers close HTTP sessions and clear cached credentials/tokens.

Bearer tokens stay in memory and are never stored by the key manager. The
licensing client remains independent of credential storage.

Cisco OAuth credentials are application-wide. Each FDM credential is bound to the
stored host, HTTPS port, and username; the application never applies the saved
password to a different device identity. This follows the usual industry model
of addressing a secret by provider, resource, and principal rather than using
one global device password.

FDM records use exact, normalized host lookup. The application stores only a
bounded count and sole-host hint for presentation: one stored host may be
pre-filled, while multiple hosts leave the Host field blank. Typing a host
performs a direct hashed-key lookup after a short debounce. The GUI does not
enumerate or render the stored host collection, so lookup behavior does not
grow with the number of device records. Legacy single-record entries remain
readable and are incorporated when new host-scoped records are stored.

## Credential-manager commands

`store` fills only incomplete groups. If `CISCO_CLIENT` is complete and `FDM`
is absent, it prompts only for the FDM record:

```bash
python key_manager.py store
```

Explicitly replace one group when credentials rotate or were entered
incorrectly:

```bash
python key_manager.py update CISCO_CLIENT
python key_manager.py update FDM
```

Inspect presence without displaying values, or delete selected groups:

```bash
python key_manager.py status
python key_manager.py delete CISCO_CLIENT
python key_manager.py delete FDM
python key_manager.py delete ALL
```

`delete` defaults to `ALL` and requests confirmation unless `--yes` is used.

## Diagnostic categories

Credential and OAuth diagnostics report the narrowest conclusion supported by
the failing boundary:

| Message category | Meaning | Operator action |
| --- | --- | --- |
| Cisco or FDM field empty/not stored | One or more fields in the named credential group are absent | Run `python key_manager.py store` |
| Stored credentials malformed | A retrieved value is not text, contains control characters, or exceeds the size limit | Replace the stored pair |
| Credential store unavailable | `keyring` is missing, selected an insecure/null backend, or cannot initialize a native backend | Install requirements and configure a supported native backend |
| Credential store could not be accessed | The selected macOS Keychain, Windows Credential Manager, or Linux secret service rejected or failed the read | Use the correct OS user, unlock the store, and authorize the Python executable |
| Client ID or Client Secret rejected | Cisco returned an OAuth `invalid_client`, `invalid_grant`, or `unauthorized_client` result | Verify/rotate the pair in the Cisco API application |
| OAuth request rejected, cause inconclusive | Cisco rejected the request but did not provide a credential-specific OAuth code | Check application scopes, grant configuration, and provider policy |
| TLS/network/timeout failure | The provider was not reached securely within the configured connect/read timeout | Check DNS, proxy, CA trust, and connectivity |
| OAuth rate limit/provider unavailable | Cisco returned HTTP 429 or a server error | Wait and retry later; do not rotate credentials based on this result alone |
| Invalid token response | Cisco returned success with malformed or incomplete token metadata | Treat as a provider/contract failure |

Provider descriptions and underlying backend exception text are not copied into
user-facing errors because they can contain identifiers or other sensitive
data. The OAuth client reports an incorrect credential pair only when the HTTP
status and bounded OAuth error code support that conclusion.

## Supported environments

- macOS: Keychain
- Windows: a supported native Windows keyring backend
- Linux desktop: Secret Service/GNOME Keyring, KWallet, or another secure backend
- Headless production: an approved centralized secret manager, not plaintext
  keyring storage

## Windows Credential Manager setup

From the project directory in PowerShell, activate the PyCharm virtual
environment and run the interactive storage command:

```powershell
.venv\Scripts\Activate.ps1
python key_manager.py store
```

Enter the Cisco Client ID at the first prompt. Enter the Cisco Client Secret at
the second prompt; secret input is hidden. Python `keyring` stores both entries
through the native Windows credential backend under the service name
`fdm-client/cisco-support`.

Confirm only their presence, without displaying either value:

```powershell
python key_manager.py status
```

Run all tests, including the conditional live token check:

```powershell
python -m unittest discover -v
```

Remove the stored pair when it is no longer needed:

```powershell
python key_manager.py delete
```

Windows associates the entries with the current Windows user account. Run
PyCharm and PowerShell as the same user so both processes see the same store.
If access fails, the diagnostic identifies Windows Credential Manager rather
than reporting the credentials as missing.

OS detection does not establish security by itself, so the active backend is
validated separately. A missing secure backend causes a closed failure and
never silently falls back to a file or environment variable.

## macOS Keychain setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python key_manager.py store
python key_manager.py status
```

The `store` command displays the Client ID while typing but uses hidden input
for the Client Secret. macOS may request Keychain permission; approve it only
for the expected Python executable and project environment.

Remove both entries with:

```bash
python key_manager.py delete
```

Never pass a password or client secret on a command line, store it in `.env`,
paste it into source, or print it for verification.

Keychain authorization is process-sensitive. A command launched by an IDE,
automation agent, or sandbox can be denied even when the same virtual-
environment Python succeeds in Terminal. That condition is reported as a
Keychain access failure and is never treated as an absent credential pair.

## Application integration

When a command needs Cisco credentials and no complete pair is stored, both
presentations offer the same choices: enter a pair and use it only for the
current process, or save it in the native operating-system vault for future
runs. The CLI hides secret input and the GUI uses a masked field. Credential
store access failures and malformed stored values are not treated as missing
credentials and therefore do not silently fall back to a prompt.

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
            payload={"replace": "with approved endpoint-specific payload"},
        )
```

The endpoint and payload must come from the approved Cisco workflow. Do not
guess them or use a mutating reservation request merely to test authentication.

## Testing and future work

The suite includes mocked credential-store tests. When a complete real
credential pair is available, it also performs the conditional live Cisco OAuth
test:

```bash
python -m unittest -v
```

Use `python -m unittest -v tests.test_key_manager` when an explicitly mock-only
credential test run is needed.

For an authorized live check, run `status`, retrieve credentials through
`KeyManager`, and request a token. Report only success and expiry metadata;
never display the token. Start portal testing with a documented read-only
endpoint. Mutating calls require separately reviewed endpoint and payload data.

The following command checks only Cisco OAuth authentication. It does not call
the licensing API and does not print the returned token or credentials:

```bash
python cisco_support_token_client.py --check
```

For a hosted live check, the manual `Cisco integration` GitHub Actions workflow
reads `CISCO_CLIENT_ID` and `CISCO_CLIENT_SECRET` from the protected
`cisco-integration` GitHub Environment. These are GitHub Actions secrets, not
Git credentials. See [TESTING.md](TESTING.md) for setup and execution.

A licensing portal connectivity test additionally requires the exact approved,
read-only endpoint path. Do not substitute a reservation endpoint as a health
check. Once the documented path is known, pass the same token client method as
`token_provider` to `CiscoPlrReservationClient` and issue a `GET` request.

Centralized secret-manager adapters, a read-only Cisco connectivity-check CLI,
CI secret scanning, and credential rotation/revocation guidance are tracked in
[ROADMAP.md](ROADMAP.md).
