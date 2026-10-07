# Security boundary and input-validation standard

External data is untrusted until it crosses a documented validation boundary.
Validate and normalize it once at that boundary, store or pass a stable trusted
representation, and avoid repeating the same validation inside the component.
Every HTTP response is a new external input and is validated when received.

Validation is distinct from escaping. Reject invalid security-sensitive values;
do not try to repair them. Preserve opaque credentials and tokens after type,
length, and control-character checks. Encode for the destination: this project
uses `requests` for form/query encoding and a validated JSON snapshot for JSON
bodies. Never construct protocol syntax with untrusted string interpolation.

## Boundary inventory

| Boundary | Validation owner | Required treatment |
| --- | --- | --- |
| CLI and environment | CLI parser and client constructor | Parse strict booleans/numbers; reject invalid values with bounded errors |
| Desktop GUI fields | Validated command-model factory | Use the same validators as the CLI; clear secret controls after submission |
| Public constructors | Constructed client | Validate and normalize hosts, URLs, ports, timeouts, paths, credentials, and headers once |
| Public request methods | API client `request` method | Enforce method/path/header policy; copy query mappings; validate and snapshot JSON |
| Credential backend | `KeyManager` | Validate Cisco and device-scoped FDM records before return; never apply an FDM password to a different host/port/username identity |
| Credential diagnostics | `KeyManager` and OAuth client | Distinguish absence, invalid storage, backend access, credential rejection, transport, and provider failures without including stored values or provider descriptions |
| Token callback | Licensing client | Validate type, presence, length, and control characters on every returned token |
| Cisco account discovery | `CiscoPlrReservationClient` | Bound pagination and record counts; validate IDs, names, domains, and booleans before returning immutable models |
| HTTP response | Receiving client | Validate status, redirects, JSON shape, required fields, field sizes, and lifetimes |
| PLR handoff artifacts | `FdmPlrClient` and `CiscoPlrReservationClient` | Bound and validate request/authorization codes; never log request bodies or codes; require approved CSSM route and schema |
| PLR return handoff | `FdmPlrClient` and `CiscoPlrReservationClient` | Keep the return code secret and resumable; after an initial cancellation read timeout, poll read-only status without repeating the mutation and invoke recovery once only after pending state is confirmed; after a final unregister DELETE read timeout, poll for disappearance of the exact connection without repeating DELETE; perform post-state checks, permit only the documented HTTP-401 refresh, and require the exact preflighted product instance |
| Application run logs | `fdm_licensing.run_logging` | Create user-private per-run files, retain only five application-owned files, use bounded structured fields, reject secret-bearing field names, and never log credentials, tokens, handoff codes, authorization headers, request bodies, or raw responses |
| Staged PLR presentation | `UniversalPlrWorkflowService`, CLI, and GUI | Keep codes in memory, omit them from representations, recover pending return codes without operator entry, and confirm Cisco removal and final unregister separately |
| Existing PLR product instance | `CiscoPlrReservationClient.preflight_universal_plr` | Parse only visible PID/device identity; require an exact account-scoped PID and serial match; block reservation without attempting recovery by replay |
| PLR inventory classification | `FdmPlrClient` and `UniversalPlrWorkflowService` | Validate Smart Agent `performanceTier` once at the FDM response boundary; preserve missing versus explicit `null`; allow only evidence-backed PIDs and block every other parsed device identity before Cisco credential or reservation work |
| FTDv performance mode | CLI/GUI and `UniversalPlrWorkflowService` | Accept only registry keys; require an explicit selection for the evidence-backed FTDv platform model; reject the option for physical devices; atomically include the tier in connection configuration and verify its read-back before Cisco mutation |
| FTD software version | `fdm_compatibility.detect_fdm_compatibility` | Read only after authentication; strictly parse `softwareVersion`; select an allowlisted route profile or fail before capability calls. An explicit test override may select only the newest known same-major profile, is disabled by default, and never crosses a major-version boundary |
| FDM certificate bootstrap | `fdm_certificate_store` and presentations | Offer bootstrap only when trust material is absent; show the SHA-256 fingerprint and require explicit out-of-band verification before continuing |
| Pinned FDM certificate without SAN | `FDMClient` pinned-certificate adapter | Keep CA/signature validation enabled against the explicit bundle; omit hostname matching only after fingerprint-confirmed bootstrap; disabled by default |
| Filesystem | Certificate/logging component | Resolve operator paths; require plain generated filenames; reject unsafe target types and oversized bundles |
| Logs and exceptions | Component producing output | Remove control characters, bound length, and exclude credentials, tokens, headers, and request bodies |

GUI widgets and CLI parsers are presentation boundaries, not independent
security implementations. Both create the same immutable command models before
calling application services. Application services may trust those models;
credential stores, callbacks, files, and HTTP responses remain external inputs.

Only `CredentialsNotFoundError` represents an absent credential pair. Native
backend initialization and access failures must propagate as failures rather
than being converted into absence. OAuth responses may identify bad credentials
only through allowlisted bounded error codes; provider descriptions are not
included in presentation output.

Operator-supplied CA, certificate-store, and log paths may be absolute and may
reside outside the project. Generated `bundle_name` values must be plain
filenames. Endpoint-specific payload schemas remain the caller's responsibility;
the shared clients enforce valid JSON syntax and a bounded request size.

Current shared limits are a 2 MiB JSON request body, a 2 MiB certificate bundle,
300 seconds for each configured request-timeout value, one year for a returned
token lifetime, 1,000 query parameters, 1,000 characters of provider error
text, and bounded credential, token, header, path, and user-agent lengths. A
limit change is a security-policy change and requires boundary tests.

Cisco discovery is limited to 10,000 records per collection and requests 100
records per page. Account values interpolated into routes are validated and
percent-encoded as individual path segments. A reservation response must match
the submitted request code before its authorization code is accepted.

## Coding requirements

For every new or changed external input, document its source, accepted type and
grammar, maximum size, normalization, rejection behavior, and trusted internal
form. Put validation in the narrowest public boundary that owns the policy.
Copy mutable caller inputs or convert them to a stable encoded representation
before use. Internal helpers may trust values only when their caller guarantees
that boundary validation has run.

Add tests for the valid minimum/maximum and representative hostile cases,
including traversal, control characters, malformed encodings, invalid numeric
values, oversized data, mutation after entry, and sensitive-data disclosure.
Security validation failures must occur before filesystem or network side
effects. Do not weaken validation for compatibility without documenting and
testing the newly accepted grammar.
