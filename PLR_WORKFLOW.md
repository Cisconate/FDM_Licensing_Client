# Universal PLR workflow

Firewall Device Manager supports Universal Permanent License Reservation
(UPLR), not Specific License Reservation. Confirm that the target Smart Account
is enabled for Universal PLR and that the device is in a supported state before
starting. Switching an evaluation-mode device to PLR cannot be reversed back to
evaluation mode.

Opening `FDMClient` as a context manager first obtains an API bearer token and
then reads `GET operational/systeminfo/default`. The returned `softwareVersion`
selects the route profile used by `FdmPlrClient`. FTD `7.6.x`, `10.0.x`, and `10.1.x` are
currently enabled profiles; other releases stop with an unsupported-version
error before a PLR operation is attempted.

An explicit compatibility override may reuse the newest known API profile for
an unsupported minor release within the same major version. The strict gate
remains the default, cross-major fallback is prohibited, and presentations warn
when the override is active. The override is intended for controlled validation
and does not convert the tested release into an officially supported profile.

## Atomic API map

| Step | Owner and operation | HTTP contract | Library method |
| --- | --- | --- | --- |
| 1 | FDM: inspect Smart Agent connection | `GET license/smartagentconnections` | `FdmPlrClient.list_smart_agent_connections()` |
| 2a | FDM: create Universal PLR connection when none exists | `POST license/smartagentconnections` | `create_universal_plr_connection()` |
| 2b | FDM: change an existing connection | `PUT license/smartagentconnections/{id}` with its current `version` | `update_connection_to_universal_plr()` |
| 3 | FDM: retrieve request-code collection or one object | FTD 7.6/10.0/10.1: `GET license/operational/plrrequestcode[/{id}]` | `list_plr_request_codes()` / `get_plr_request_code()` |
| 3a | CSSM: check for an existing product instance | `GET licensing/v2/accounts/{domain}/devices` filtered by VA and request-code identity | `CiscoPlrReservationClient.preflight_universal_plr()` |
| 3b | CSSM: read virtual-account license inventory | `POST licensing/v2/get-summary` | `CiscoPlrReservationClient.get_license_summary()` |
| 4 | CSSM: exchange request code for authorization code | Software APIs 1.0.2 `POST licensing/v2/account/{domain}/virtual-account/{name}/licenses/reserve` | `CiscoPlrReservationClient.reserve_universal_plr()` |
| 5 | FDM: install authorization code | `POST license/action/installplrcode` | `FdmPlrClient.install_authorization_code()` |
| R1 | FDM: cancel reservation and generate return code | FTD 7.6/10.0/10.1: `POST license/action/cancelreservation` | `FdmPlrClient.generate_return_code()` |
| R2 | CSSM: complete return | `POST licensing/v3/accounts/{domain}/devices/remove?virtualAccountName={name}` | `CiscoPlrReservationClient.return_universal_plr()` |
| R3 | FDM: finalize unregister after Cisco acceptance | `DELETE license/smartagentconnections/{id}` | `FdmPlrClient.finalize_return()` |

Steps 2, 4, and 5 change external state. They are not automatically followed by
another step. Cisco requests permit only the transport client's documented
single retry after HTTP 401 with a refreshed bearer token; no other reservation
retry occurs. Persist request and authorization handoff artifacts using an
approved secure operational process if the workflow must be resumed.

FTD 7.6 returns `unableToGeneratePLRRequestCode` when the operational request-code
route is queried before Permanent Licensing is enabled. Inspection therefore
queries request codes only after confirming exactly one `UNIVERSAL_PLR` Smart
Agent connection; other connection states are reported without treating this
expected precondition as a transport failure.

After a confirmed create/update mutation, FDM may report the Universal PLR
connection before its operational request code is ready. The shared workflow
therefore polls the read-only connection / request-code state for up to 60 seconds.
It never repeats the POST/PUT. A timeout is resumable: rerunning inspection or
`plr run` uses the existing Universal PLR connection instead of recreating it.

The FDM contracts are described by Cisco's
[FTD API reference](https://developer.cisco.com/docs/ftd-api-reference/latest/),
including the
[Smart Agent connection update](https://developer.cisco.com/docs/ftd-api-reference/latest/editsmartagentconnection/)
and
[PLR authorization-code install](https://developer.cisco.com/docs/ftd-api-reference/latest/addplrauthorizationcode/).
The operational prerequisites and the six-group authorization-code format are
documented in Cisco's
[FDM licensing guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/70/fdm/fptd-fdm-config-guide-700/fptd-fdm-license.html).

## Library usage

```text python
from cisco_support_api_client import CiscoPlrReservationClient
from cisco_support_token_client import CiscoSupportTokenClient
from fdm_client import FDMClient
from fdm_plr_client import FdmPlrClient

# Create and authenticate these clients with runtime credentials first.
fdm_plr = FdmPlrClient(fdm_client)

# Run only the branch appropriate for the state returned by the first call.
connections = fdm_plr.list_smart_agent_connections()
connection = fdm_plr.create_universal_plr_connection()
# Or, for an existing connection:
# connection = fdm_plr.update_connection_to_universal_plr(
#     connection_id=connections[0]["id"], version=connections[0]["version"]
# )

request_codes = fdm_plr.list_plr_request_codes()
request_code = request_codes[0].code

selection = AccountSelection(smart_account, virtual_account)
authorization = cisco_plr.reserve_universal_plr(selection, request_code)
authorization_code = authorization.authorization_code

install_result = fdm_plr.install_authorization_code(authorization_code)
```

The supplied Software APIs 1.0.2 document defines the APX deployment at
`https://apx.cisco.com/v1/software/apis/`. The code keeps this and the legacy
SWAPI deployment as separate named profiles until read-only testing identifies
which deployment grants the configured OAuth application access.

`UniversalPlrWorkflowService` supplies the shared resumable stages used by
presentations. It opens and closes both FDM and Cisco transports per stage,
classifies FDM state conservatively, and keeps the authorization handoff only
in memory. The CLI exposes the complete path as `plr run`, plus resumable stages
as `plr inspect`, `plr reserve`, and `plr install`; every mutation requires an
interactive confirmation. If Cisco succeeds but FDM installation fails, `run`
displays the authorization code exactly for recovery rather than losing it.

Before opening FDM, CLI and GUI detect an absent trust bundle and offer guided
certificate bootstrap. The newly fetched certificate's SHA-256 fingerprint is
shown and must be confirmed as verified through a trusted channel before the
licensing workflow continues.

FDM factory certificates commonly contain no Subject Alternative Name and use
the generic Common Name `firepower`. For this confirmed pin only, the workflow
continues to validate the presented certificate against the saved trust bundle
while omitting DNS/IP hostname matching. General `FDMClient` callers retain
normal hostname validation by default; this mode is not unverified TLS.

The implemented Universal request contains one `reservationRequests` entry
with the validated FDM `reservationCode` and `reservationType` set to
`UNIVERSAL`. Its parser requires one successful nested `authorizationCodes`
entry and verifies that its reservation code matches the submitted value.

Cisco and FDM examples use multiple authorization-code lengths. The shared
validator accepts 6–16 hyphen-separated alphanumeric groups of 2–8 characters,
covering both the shorter published example and the longer code observed from
the live FPR-1010 reservation, while continuing to reject whitespace, control
characters, and arbitrary text.

The license-summary parser verifies the response nonce and all typed quantities.
Available quantity is `entitled - inuse`; `reserved` is informational because
the observed API counts reservations within in-use quantity.

Before confirmation, the presentation reports only explicitly mapped compatible
Universal PLR inventory. FPR-1000 PIDs such as `FPR-1010` map to the
`FPR1K-TD-ULR` tag; CSF-200 PIDs map to `CSF_200_TD_PLR`. The observed
`CSF-1220CX` request-code PID and the inferred `CSF-1210CE`, `CSF-1210CP`,
`CSF-1230`, `CSF-1240`, and `CSF-1250` PIDs map to the observed
`FPR1200_TD_ULR` tag. FTDv request codes use
the generic PID `NGFWv`, so the workflow carries the sole Smart Agent
connection's validated `performanceTier` through inspection and readiness
polling. `FTDv5`, `FTDv10`, `FTDv20`, `FTDv30`, `FTDv50`, and `FTDv100` map to
the observed 100 Mbps, 1 Gbps, 3 Gbps, 5 Gbps, 10 Gbps, and 16 Gbps Universal
license tags respectively. `FTDvU` and an explicit `null` tier for `NGFWv`
(Variable) map to `FPRV-TD-ULR`. A missing tier or unknown non-null tier remains
informationally unmapped; physical PIDs ignore virtual-tier metadata.

FTDv is identified from the authenticated system-information model `Cisco
Secure Firewall Threat Defense for VMware`. Before the create or update
mutation, the operator must select Variable, 100 Mbps, 1, 3, 5, 10, or 16 Gbps,
or Unlimited. The selected `performanceTier` is included in the same atomic
Smart Agent connection POST/PUT, including an explicit JSON `null` for Variable,
and is verified from the read-back connection before Cisco work begins.

Only evidence-backed request-code PIDs enter the reservation workflow. Every
other well-formed request code retains its parsed PID and device identifier for
diagnostics, presents the same bounded unsupported-platform warning, and stops
before Cisco credential access, account discovery, reservation preflight, or
mutation. The warning notes that the platform may not run FDM without attempting
to maintain specialized explanations for individual unsupported product lines.

Before posting, `reserve_universal_plr()` parses the visible PID and device
identifier from the request code and searches the selected Smart/Virtual
Account. An exact existing PID and serial match blocks the POST. The resulting
error directs the operator to recover the existing authorization in Cisco
License Central, or contact TAC for a poisoned product instance when an FTD
return was initiated but never completed in CSSM.

Software APIs 1.0.2 does not expose an authorization-code field through product
instance search or its documented Licensing GraphQL queries. The library cannot
re-download the existing code through a published API and must not replay a
reservation as a recovery mechanism.

Live testing of steps 2, 4, or 5 is not part of the routine suite because each
can alter the device or licensing state. The mocked contract tests are:

```bash
.venv/bin/python -m unittest -v tests.test_plr_workflow
```

## Returning Universal PLR

An authorized FTD does not permit the operational reservation-code route to
generate another request code. Return preflight instead requires one
`UNIVERSAL_PLR` / `AUTHORIZED` Smart Agent status, reads the hardware serial
from authenticated system information, and requires exactly one matching CSSM
product instance in the selected Virtual Account.

Cisco's live global device-search response differs from the published schema:
the observed successful response uses `status: OK` and a single object in
`data`, while the contract describes `status: COMPLETE` and an array. The
boundary parser accepts both forms, then applies the same exact serial and
single-match validation.

FTD 7.6, 10.0, and 10.1 define `POST license/action/cancelreservation` with a
`{"type":"PLRReleaseCode"}` body. Its returned `code` is a sensitive,
resumable handoff. Live FTD 7.6 testing confirmed that the same POST returns a
valid release code while `smartagentstatuses` reports
`PLR_DEACTIVATION_IN_PROGRESS`, without changing that state. Recovery therefore
checks the pending state, invokes the recovery action once, validates the code,
and verifies the pending state again. It is not a general transport retry; only
the transport's documented single HTTP-401 refresh is permitted, and an
ambiguous failure is never resubmitted automatically.

The normal FDM API read timeout remains 30 seconds. If the initial cancellation
POST exceeds only that read timeout, the shared service reports the ambiguity
and polls `smartagentstatuses` without repeating the mutation. After the pending
state is confirmed, it invokes the verified recovery operation once and resumes
the return. TLS, authentication, HTTP, and other transport failures bypass this
fallback. Failure to confirm pending state or recover a valid code produces a
bounded resumable error instead of another automatic POST.

Software APIs 1.0.2 defines no v3 endpoint for creating the original PLR
reservation; reservation creation ends at v2. Return completion uses the v3
product-instance removal endpoint. The request supplies the exact preflighted
PID, serial number, product tag, and FDM return code in
`productInstancesRemoveRequests`. Both overall and per-device success are
required. After acceptance, the service polls the read-only product-instance
search for up to 60 seconds. If the exact instance remains visible, it reports
an ambiguous convergence result and explicitly prohibits resubmission.

```bash
fdm-licensing plr return-inspect
fdm-licensing plr return-generate
fdm-licensing plr return-complete
fdm-licensing plr return
```

The end-to-end command separately confirms FDM cancellation, Cisco removal, and
final FDM unregister. If Cisco completion fails or is declined, it prints the
return code for recovery with `return-complete`. A pending FDM return is
recognized from `PLR_DEACTIVATION_IN_PROGRESS`; CLI and GUI report "Resuming PLR
return with existing code", recover the code with one guarded POST instead of
prompting for it, and continue to the separately confirmed Cisco removal.

The final Smart Agent connection DELETE is also never repeated after a read
timeout. The shared service retains the exact submitted connection ID and polls
the read-only connection collection for the normal readiness window. Its
disappearance confirms delayed success; a remaining or different connection
produces an explicit recoverable outcome for operator inspection.

CLI invocations and desktop launches create separate timestamped run logs and
retain only the five newest application-owned files. Logs capture phase names,
elapsed durations, error classes, and recovery decisions, but never handoff
codes, credentials, tokens, authorization headers, or request bodies.

`--unattended` converts those mutation confirmations into informational output
after all required inputs have crossed their validation boundaries. Missing
inputs may still use masked or ordinary interactive prompts; without a terminal
they are errors. Existing FDM trust is mandatory because certificate bootstrap
always requires explicit out-of-band fingerprint verification.

Within a CLI command or GUI workflow, one authenticated FDM session and one
Cisco OAuth/licensing session are reused and then closed deterministically.
Account discovery is memoized only inside that workflow. The FDM system
information already read for compatibility is reused for return identity, and
the independent read-only license-summary and product-instance preflight calls
run concurrently. Mutating requests remain strictly ordered.
