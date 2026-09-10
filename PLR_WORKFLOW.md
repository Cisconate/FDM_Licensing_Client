# Universal PLR workflow

Firewall Device Manager supports Universal Permanent License Reservation
(UPLR), not Specific License Reservation. Confirm that the target Smart Account
is enabled for Universal PLR and that the device is in a supported state before
starting. Switching an evaluation-mode device to PLR cannot be reversed back to
evaluation mode.

Opening `FDMClient` as a context manager first obtains an API bearer token and
then reads `GET operational/systeminfo/default`. The returned `softwareVersion`
selects the route profile used by `FdmPlrClient`. FTD `7.6.x` is currently the
only enabled profile; other releases stop with an unsupported-version error
before a PLR operation is attempted.

## Atomic API map

| Step | Owner and operation | HTTP contract | Library method |
| --- | --- | --- | --- |
| 1 | FDM: inspect Smart Agent connection | `GET license/smartagentconnections` | `FdmPlrClient.list_smart_agent_connections()` |
| 2a | FDM: create Universal PLR connection when none exists | `POST license/smartagentconnections` | `create_universal_plr_connection()` |
| 2b | FDM: change an existing connection | `PUT license/smartagentconnections/{id}` with its current `version` | `update_connection_to_universal_plr()` |
| 3 | FDM: retrieve request-code collection or one object | `GET license/plrrequestcodes[/{id}]` | `list_plr_request_codes()` / `get_plr_request_code()` |
| 3a | CSSM: check for an existing product instance | `GET licensing/v2/accounts/{domain}/devices` filtered by VA and request-code identity | `CiscoPlrReservationClient.preflight_universal_plr()` |
| 4 | CSSM: exchange request code for authorization code | Software APIs 1.0.2 `POST licensing/v2/account/{domain}/virtual-account/{name}/licenses/reserve` | `CiscoPlrReservationClient.reserve_universal_plr()` |
| 5 | FDM: install authorization code | `POST license/action/installplrcode` | `FdmPlrClient.install_authorization_code()` |

Steps 2, 4, and 5 change external state. They are not automatically followed by
another step. Cisco requests permit only the transport client's documented
single retry after HTTP 401 with a refreshed bearer token; no other reservation
retry occurs. Persist request and authorization handoff artifacts using an
approved secure operational process if the workflow must be resumed.

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

```python
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

The implemented Universal request contains one `reservationRequests` entry
with the validated FDM `reservationCode` and `reservationType` set to
`UNIVERSAL`. Its parser requires one successful nested `authorizationCodes`
entry and verifies that its reservation code matches the submitted value. CLI
and GUI mutation controls remain disabled pending deployment and inventory
preflight verification.

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
can alter device or licensing state. The mocked contract tests are:

```bash
.venv/bin/python -m unittest -v test_plr_workflow
```
