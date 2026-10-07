# First-time setup

This guide prepares a workstation, Cisco account, and locally managed Secure
Firewall Threat Defense (FTD) device for this application's Universal
Permanent License Reservation (Universal PLR) workflow.

Complete the Cisco and device prerequisites before starting the application.
The application can validate credentials and inspect state, but it cannot grant
portal permissions, enable Universal PLR for a Smart Account, or decide which
Virtual Account should own a device.

> [!IMPORTANT]
> This project is an early-stage client, not an official Cisco SDK. The Cisco
> developer portal is authenticated and its labels can change. The portal steps
> below combine Cisco's published application-registration process with the
> `Software APIs` 1.0.2 contract supplied with this project. Confirm the API
> name, access status, and terms shown in your own portal before proceeding.

## 1. Gather the required access and information

Ask your Cisco Smart Account administrator to confirm all of the following:

- Your Cisco.com account can access the intended Smart Account and Virtual
  Account.
- The Smart Account is enabled for **Universal PLR**. This application does not
  implement Specific License Reservation.
- The selected Virtual Account owns sufficient compatible Universal PLR
  entitlement for the target device.
- You are authorized to create a Cisco API application and request access to
  the Software Licensing APIs. If the portal does not permit the request, a
  customer or Smart Account administrator may need to grant a role or submit
  the request.
- You are authorized to change licensing state on the target FTD device.

Also collect:

- the FDM management hostname or IP address and HTTPS port;
- an FDM username and password with permission to manage licensing;
- the expected SHA-256 fingerprint of the FDM HTTPS certificate, obtained over
  a trusted channel such as the device console or an administrator; and
- the intended Smart Account domain and Virtual Account name.

The supported FTD releases are currently 7.6.x, 10.0.x, and 10.1.x. A newer
minor release can be tested only with an explicit same-major compatibility
override. Cross-major fallback is prohibited.

> [!WARNING]
> Moving an evaluation-mode device to PLR cannot be reversed back to evaluation
> mode. Confirm the licensing plan with the Smart Account owner before making a
> reservation.

## 2. Register a Cisco API application

1. Sign in to the [Cisco Software Licensing API portal](https://it-developer.cisco.com/auth/customer-assets/licensing/apis/latest/#!my_apps)
   with the Cisco.com account that has the required customer access.
2. Open **My Apps**, **My Applications**, or **My Apps & Keys**. Cisco uses
   different labels across versions of its developer portals.
3. Create or register a new application. Use a descriptive name that identifies
   its owner and purpose, for example `FDM Universal PLR - Network Operations`.
4. Select an application or grant type that supports **OAuth 2.0 Client
   Credentials**. This is a service-to-service integration; it does not use an
   interactive authorization-code grant or redirect URI.
5. Request access to **Software APIs** (the contract used by this project is
   version 1.0.2). If the portal presents individual operations instead of one
   API product, the application needs access to operations for:

   - listing accessible Smart Accounts and Virtual Accounts;
   - reading license summaries and product instances;
   - creating a Universal license reservation; and
   - removing a product instance to complete a Universal PLR return.

6. Accept the applicable Cisco terms and submit the request.
7. Wait until the requested API access shows **Approved**, **Active**, or the
   equivalent. Creating credentials does not necessarily mean that the
   licensing API entitlement has been approved.
8. Record the generated **Client ID** (sometimes labeled **Key**) and **Client
   Secret** in an approved password or secret manager.

Use one application registration for all required Software API access so that
one Client ID and Client Secret carry the complete permission set. Do not add
unrelated APIs merely because they are available in the catalog.

The application uses these Cisco endpoints from the supplied contract:

| Purpose | Endpoint |
| --- | --- |
| Obtain a short-lived OAuth token | `https://id.cisco.com/oauth2/default/v1/token` |
| Software Licensing API base | `https://apx.cisco.com/v1/software/apis/` |

The Client ID and Client Secret identify the API application and must be
protected like a password. The application obtains bearer tokens at runtime;
it does not store those tokens.

### Portal checkpoint

Before leaving the portal, verify that:

- the grant type is Client Credentials;
- Software APIs access is active, not pending or rejected;
- both the Client ID and Client Secret are available;
- the application owner and purpose are recognizable; and
- you know how your organization will revoke or rotate the credentials.

If **Software APIs** is not offered, or the portal shows several similarly
named licensing APIs, stop and ask the Cisco Smart Account administrator or
Cisco licensing support which product grants the Software APIs 1.0.2 routes.
Do not guess by granting unrelated APIs.

## 3. Install the application

From the project directory, create a Python 3.10-or-newer virtual environment
and install the project:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e ".[gui]"
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e ".[gui]"
```

The native credential store must be available: macOS Keychain, Windows
Credential Manager, or a supported secure Linux keyring. Plaintext and null
keyring backends are rejected.

## 4. Store credentials securely

Run the interactive credential setup:

```bash
python key_manager.py store
python key_manager.py status
```

Enter the Cisco Client ID and Client Secret from the portal. Then enter the FDM
host, HTTPS port, username, and password for the target device. Secret input is
hidden. The status command reports only whether each credential group exists;
it does not display stored values.

Alternatively, launch `fdm-licensing-gui` and use **Credential Management**.
The application can also use credentials for the current process without
saving them when prompted.

Never put a Client Secret or FDM password in source code, a command argument,
an `.env` file, a screenshot, or a support log. To replace a credential group
later, use:

```bash
python key_manager.py update CISCO_CLIENT
python key_manager.py update FDM
```

## 5. Validate Cisco authentication

Request a token without displaying it:

```bash
python cisco_support_token_client.py --check
```

A successful result proves that Cisco accepted the Client ID and Client Secret.
It does **not** by itself prove that the application can access the required
Smart Account or every Software Licensing operation.

Next, perform the application's read-only account discovery:

```bash
fdm-licensing cisco accounts
```

Confirm that the intended Smart Account and Virtual Account appear. If token
validation succeeds but account discovery is rejected or returns no intended
account, check the API application's Software APIs approval and the Cisco.com
user's customer/Smart Account access. Do not test access by submitting a
reservation.

## 6. Establish trust with the FDM device

The application requires verified TLS. On first connection, when no saved
certificate exists, the CLI and GUI offer certificate bootstrap. Bootstrap
makes one deliberately unverified connection only to retrieve the certificate;
it does not make that certificate trustworthy.

1. Start with a read-only inspection:

   ```bash
   fdm-licensing plr inspect --host ftd.example.com
   ```

2. Accept the offer to retrieve the certificate if the application reports
   that no trust bundle exists.
3. Compare the displayed SHA-256 fingerprint with the value obtained through
   the trusted channel prepared in step 1.
4. Confirm it only when the values match exactly. A mismatch can indicate the
   wrong device or interception; stop and investigate.
5. Run the inspection again if needed.

Inspection authenticates first, detects the FTD release, checks compatibility,
and reads the Smart Agent/PLR state. It does not create a Cisco reservation or
install an authorization code.

## 7. Perform a preflight review

Before a mutating operation, verify this checklist with the operator who owns
the licensing change:

- [ ] Cisco OAuth validation succeeds.
- [ ] The intended Smart Account and Virtual Account are discoverable.
- [ ] Universal PLR is enabled for that Smart Account.
- [ ] Compatible Universal PLR inventory is available.
- [ ] The target device identity and FDM certificate fingerprint are verified.
- [ ] The detected FTD version is supported.
- [ ] The current Smart Agent state is understood.
- [ ] For FTDv, the intended performance tier has been selected.
- [ ] The operator understands that reservation, installation, cancellation,
      Cisco removal, and final unregister are separate state changes.
- [ ] A secure process exists to preserve an authorization or return code if a
      staged workflow must be resumed.

## 8. Start the Universal PLR workflow

For the guided desktop workflow:

```bash
fdm-licensing-gui
```

Open **FTD Licensing Workflow** and proceed through certificate trust,
**Inspect FDM**, **Configure PLR**, **Select account and reserve**, and **Install
authorization code**. Later actions remain unavailable until their
prerequisites have succeeded, and each mutation requires confirmation.

For the CLI, review command help before running anything:

```bash
fdm-licensing plr --help
fdm-licensing plr run --help
```

Then use the end-to-end workflow, supplying the real device and account values:

```bash
fdm-licensing plr run \
  --host ftd.example.com \
  --smart-account example.com \
  --virtual-account Default
```

The workflow is resumable. Do not blindly repeat a failed mutation. If Cisco
creates the reservation but FDM installation fails, preserve the displayed
authorization code securely and resume with `fdm-licensing plr install`.
Consult [PLR_WORKFLOW.md](PLR_WORKFLOW.md) before attempting a return or
recovering from a partial workflow.

## Troubleshooting setup

| Symptom | Likely boundary to check |
| --- | --- |
| The portal will not allow API registration | Cisco.com customer role or API-registration permission |
| Software APIs access remains pending | Portal approval process or Cisco licensing support |
| Client ID/Secret is rejected | Wrong pair, rotated/revoked credential, or incorrect grant configuration |
| OAuth succeeds but accounts are missing | Smart Account/Virtual Account role or Software APIs authorization |
| Credential store is unavailable | Native keyring installation, logged-in OS user, or vault authorization |
| FDM certificate fingerprint differs | Wrong target, changed certificate, or possible interception; do not continue |
| FTD release is unsupported | Use a supported release; use the explicit same-major override only for controlled validation |
| No compatible Universal PLR inventory appears | Account selection, entitlement availability, or unsupported device PID/tier |

Errors are intentionally bounded and do not include secrets, authorization
headers, request bodies, or raw provider responses. Application run logs must
not be used to store handoff codes.

## References

- [Cisco Software Licensing API portal](https://it-developer.cisco.com/auth/customer-assets/licensing/apis/latest/#!my_apps)
- [Cisco Support API application registration](https://developer.cisco.com/docs/support-apis/application-registration/)
- [Cisco Support API authentication](https://developer.cisco.com/docs/support-apis/authentication/)
- [Project credential-management guide](CREDENTIAL_MANAGEMENT.md)
- [Project Universal PLR workflow](PLR_WORKFLOW.md)
- [Project security rules](SECURITY.md)

