# Cisco Credential Management

## Purpose and design

`key_manager.py` stores the Cisco OAuth Client ID and Client Secret in the
operating system credential store. It supports macOS, Windows, and Linux via
Python `keyring` and refuses known null, failing, or plaintext backends.

The data flow is:

1. `KeyManager` retrieves the Client ID and Client Secret from secure storage.
2. `CiscoSupportTokenClient` exchanges them for a short-lived OAuth token.
3. `CiscoPlrReservationClient` receives tokens through `token_provider`.
4. Context managers close HTTP sessions and clear cached credentials/tokens.

Bearer tokens stay in memory and are never stored by the key manager. The
licensing client remains independent of credential storage.

## Diagnostic categories

Credential and OAuth diagnostics report the narrowest conclusion supported by
the failing boundary:

| Message category | Meaning | Operator action |
| --- | --- | --- |
| Client ID/Secret empty or not stored | One or both named entries are absent or empty | Run `python key_manager.py store` |
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

Never pass the secret on a command line, store it in `.env`, paste it into
source, or print it for verification.

Keychain authorization is process-sensitive. A command launched by an IDE,
automation agent, or sandbox can be denied even when the same virtual-
environment Python succeeds in Terminal. That condition is reported as a
Keychain access failure and is never treated as an absent credential pair.

## Application integration

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

Use `python -m unittest -v test_key_manager` when an explicitly mock-only
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
