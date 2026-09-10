# Project Roadmap

This file records desired enhancements that are outside the current supported
behavior. It is the repository-level source of truth for future work. Create a
GitHub Issue when an item is scheduled, and link the issue from this file.

Roadmap entries describe intent, not an approved API contract or authorization
to make live device changes. Update an entry when its scope, priority, or status
changes. Move implementation details into the linked issue or pull request.

## Tracking conventions

- **Status:** `Proposed`, `Planned`, `In progress`, `Blocked`, or `Complete`.
- **Priority:** `P0` critical, `P1` high, `P2` normal, or `P3` low.
- **Evidence:** the measurement or test required before the item is complete.
- Stable IDs allow roadmap entries to be referenced from issues, commits, and
  pull requests.

## Performance enhancements

Performance work must preserve the validation-once boundary model in
`SECURITY.md`, deterministic resource cleanup, and the existing rule against
automatic retries of mutating requests. Measure current behavior before making
an optimization.

| ID | Enhancement | Priority | Status | Trigger and completion evidence |
| --- | --- | --- | --- | --- |
| PERF-001 | Establish startup and workflow performance baselines | P1 | Proposed | Before broad optimization. Record GUI startup time, CLI startup time, authentication count, request latency, and peak memory on representative Windows hardware. Add repeatable measurements and explicit budgets for any metric used as an acceptance criterion. |
| PERF-002 | Reuse authenticated clients within one licensing workflow | P1 | Proposed | Implement when the reservation workflow spans multiple FDM or Cisco operations. A workflow-scoped service should reuse its HTTP session and cached token, then close and clear them deterministically. Evidence: fewer authentication and TLS handshakes without credential leakage or changed retry behavior. |
| PERF-003 | Keep GUI network work off the UI thread | P1 | Proposed | Apply to each new network-backed GUI action. Use bounded background workers, marshal results back to the UI thread, prevent conflicting duplicate actions, and support safe cancellation where practical. Evidence: the window remains responsive during timeout and slow-network tests. |
| PERF-004 | Bound large API responses and render incrementally | P1 | Proposed | Implement when list or inventory capabilities are added. Use API pagination and limits, cap retained response data, and update the GUI in batches. Evidence: stable memory use and responsive rendering with a representative large result set. |
| PERF-005 | Add bounded concurrency for independent devices | P2 | Proposed | Consider only when a documented multi-device workflow exists. Use a bounded thread pool for network-bound operations and a separate client/session per worker. Evidence: measured throughput improvement with configured concurrency limits and isolated failures. |
| PERF-006 | Create GUI pages lazily | P2 | Proposed | Implement if added capabilities make startup exceed the PERF-001 budget. Construct a page on first use and retain only the state the workflow requires. Evidence: measured startup improvement with equivalent navigation behavior. |
| PERF-007 | Reduce CLI import and startup cost | P3 | Proposed | Implement only if PERF-001 shows startup outside its budget. Delay GUI and capability-specific imports until their command is selected. Evidence: measured startup improvement with unchanged commands and errors. |
| PERF-008 | Evaluate an asynchronous transport | P3 | Proposed | Revisit only for high-concurrency workloads that bounded threads cannot meet. Requires a complete lifecycle, cancellation, rate-limit, and compatibility design. Evidence: a benchmark showing material benefit over the synchronous implementation. |
| PERF-009 | Evaluate multiprocessing for CPU-bound work | P3 | Proposed | Revisit only if profiling identifies sustained CPU-bound processing such as large cryptographic or data transformations. Evidence: a representative benchmark that includes process startup and data-transfer cost. |

## Functional enhancements

| ID | Enhancement | Priority | Status | Dependency or completion evidence |
| --- | --- | --- | --- | --- |
| FUNC-001 | Generate an FDM reservation request code | P1 | Complete | Atomic FDM mode and request-code operations are implemented with mocked boundary tests and documented API contracts. |
| FUNC-002 | Generate a Cisco license authorization code | P1 | Blocked | Atomic exchange and response validation are implemented; a concrete default requires the entitled Cisco CSSM endpoint and payload contract. |
| FUNC-003 | Install an authorization code on FDM | P1 | Complete | Atomic installation is implemented with strict UPLR code validation and mocked no-network failure tests; live mutation remains operator-controlled. |
| FUNC-004 | Coordinate the end-to-end reservation workflow | P1 | Proposed | Depends on FUNC-001 through FUNC-003 and must expose progress and recoverable handoff artifacts without logging sensitive data. |
| FUNC-005 | Add SLR and standard licensing capabilities | P2 | Proposed | Add each capability only after its Cisco/FDM API contract is documented and registered independently. |

## Security and reliability enhancements

| ID | Enhancement | Priority | Status | Dependency or completion evidence |
| --- | --- | --- | --- | --- |
| SEC-001 | Add CI secret scanning | P1 | Proposed | Select and document a scanner; prove that representative test secrets are rejected without exposing real credentials. |
| SEC-002 | Document credential rotation and revocation | P2 | Proposed | Cover local OS stores, GitHub Environments, Cisco credentials, and incident response ownership. |
| SEC-003 | Add centralized secret-manager adapters | P2 | Proposed | For approved headless environments; adapters must fail closed and avoid plaintext fallback. |
| REL-001 | Add a read-only Cisco connectivity-check command | P2 | Proposed | Requires an approved read-only endpoint. It must use stored credentials and report bounded, non-secret results. |

## User experience enhancements

| ID | Enhancement | Priority | Status | Dependency or completion evidence |
| --- | --- | --- | --- | --- |
| UX-001 | Present the reservation workflow as guided GUI steps | P1 | Proposed | Depends on FUNC-001 through FUNC-004. Show prerequisites, progress, validation errors, and safe retry choices at each boundary. |
| UX-002 | Add accessible status and error presentation | P2 | Proposed | Verify keyboard navigation, focus behavior, readable progress states, and actionable bounded errors on Windows. |

## Packaging and release enhancements

| ID | Enhancement | Priority | Status | Dependency or completion evidence |
| --- | --- | --- | --- | --- |
| PKG-001 | Add a Windows installer | P2 | Proposed | Choose MSI or MSIX after validating deployment needs; test clean install, upgrade, uninstall, and credential-store behavior. |
| PKG-002 | Sign Windows executables and installers | P2 | Blocked | Requires an organization-controlled code-signing certificate and release process. |
| PKG-003 | Add macOS and Linux packaging | P3 | Proposed | Begin after the Windows workflow is stable; validate native credential-store and TLS behavior on each platform. |

## Testing and developer experience enhancements

| ID | Enhancement | Priority | Status | Dependency or completion evidence |
| --- | --- | --- | --- | --- |
| TEST-001 | Expand conditional live checks by capability | P1 | Proposed | Each module runs its live check when its complete credential and endpoint configuration is available, while mocked tests always run. Live mutating tests still require explicit authorization under `AGENTS.md`. |
| TEST-002 | Add packaged-application smoke tests | P2 | Proposed | Launch the built CLI and GUI on a clean Windows runner and verify basic startup without credentials. |
| DEV-001 | Link scheduled roadmap work to GitHub Issues | P2 | Proposed | Add an issue link beside an item when work is accepted into a milestone; keep detailed implementation discussion in the issue. |
