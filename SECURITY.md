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
| Public constructors | Constructed client | Validate and normalize hosts, URLs, ports, timeouts, paths, credentials, and headers once |
| Public request methods | API client `request` method | Enforce method/path/header policy; copy query mappings; validate and snapshot JSON |
| Credential backend | `KeyManager` | Treat retrieved values as untrusted opaque strings; validate before return |
| Token callback | Licensing client | Validate type, presence, length, and control characters on every returned token |
| HTTP response | Receiving client | Validate status, redirects, JSON shape, required fields, field sizes, and lifetimes |
| Filesystem | Certificate/logging component | Resolve operator paths; require plain generated filenames; reject unsafe target types and oversized bundles |
| Logs and exceptions | Component producing output | Remove control characters, bound length, and exclude credentials, tokens, headers, and request bodies |

Operator-supplied CA, certificate-store, and log paths may be absolute and may
reside outside the project. Generated `bundle_name` values must be plain
filenames. Endpoint-specific payload schemas remain the caller's responsibility;
the shared clients enforce valid JSON syntax and a bounded request size.

Current shared limits are a 2 MiB JSON request body, a 2 MiB certificate bundle,
300 seconds for each configured request-timeout value, one year for a returned
token lifetime, 1,000 query parameters, 1,000 characters of provider error
text, and bounded credential, token, header, path, and user-agent lengths. A
limit change is a security-policy change and requires boundary tests.

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
