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
| PERF-004 | Bound large API responses and render incrementally | P1 | Proposed | Implement when list or inventory capabilities are added. Use API pagination and limits, cap retained response data, and update the GUI in batches. Evidence: stable memory use and responsive rendering with a representative large result set. |
| PERF-005 | Add bounded concurrency for independent devices | P2 | Proposed | Consider only when a documented multi-device workflow exists. Use a bounded thread pool for network-bound operations and a separate client/session per worker. Evidence: measured throughput improvement with configured concurrency limits and isolated failures. |
| PERF-006 | Create GUI pages lazily | P2 | Proposed | Implement if added capabilities make startup exceed the PERF-001 budget. Construct a page on first use and retain only the state the workflow requires. Evidence: measured startup improvement with equivalent navigation behavior. |
| PERF-007 | Reduce CLI import and startup cost | P3 | Proposed | Implement only if PERF-001 shows startup outside its budget. Delay GUI and capability-specific imports until their command is selected. Evidence: measured startup improvement with unchanged commands and errors. |
| PERF-008 | Evaluate an asynchronous transport | P3 | Proposed | Revisit only for high-concurrency workloads that bounded threads cannot meet. Requires a complete lifecycle, cancellation, rate-limit, and compatibility design. Evidence: a benchmark showing material benefit over the synchronous implementation. |
| PERF-009 | Evaluate multiprocessing for CPU-bound work | P3 | Proposed | Revisit only if profiling identifies sustained CPU-bound processing such as large cryptographic or data transformations. Evidence: a representative benchmark that includes process startup and data-transfer cost. |

## Functional enhancements

| ID | Enhancement | Priority | Status | Dependency or completion evidence |
| --- | --- | --- | --- | --- |
| FUNC-005 | Add SLR and standard licensing capabilities | P2 | Proposed | Add each capability only after its Cisco/FDM API contract is documented and registered independently. |
| FUNC-006 | Support Universal PLR inventory classification for the CSF 1200 lineup | P1 | Complete | The observed `CSF-1220CX` PID establishes the model grammar; the five sibling PIDs are explicitly allowlisted, all map to the read-only observed `FPR1200_TD_ULR` tag, and mocked tests cover every model plus the generic unsupported-device boundary. |
| FUNC-007 | Resume an in-progress PLR return without manual code entry | P1 | Complete | Live FTD 7.6 evidence confirms one cancellation POST re-exposes a valid code while the device remains pending; CLI and GUI now guard recovery with before/after state checks and retain separate Cisco and unregister confirmations. |
| FUNC-008 | Recover transparently from an ambiguous initial PLR cancellation read timeout | P1 | Complete | Only a classified FDM API read timeout activates the fallback; read-only status polling must confirm `PLR_DEACTIVATION_IN_PROGRESS` before one communicated recovery invocation, with all other failures and unsuccessful recovery reported normally. |
| FUNC-009 | Select FTDv performance mode during PLR configuration | P1 | Complete | CLI and desktop workflows require an explicit mode for the observed VMware platform model, carry it in the atomic Smart Agent mutation, and verify FDM's returned tier before Cisco reservation. |
| FUNC-010 | Permit controlled testing on unsupported minor FTD releases | P1 | Complete | An explicit CLI/GUI override reuses only the newest known same-major API profile, preserves the strict default gate, warns the operator, and cannot cross a major-version boundary. Read-only inspection of FTD 10.1.0-160 confirmed the licensing routes and payload model shapes used by this application remain present. |
| FUNC-011 | Support FTD 10.1 licensing workflows | P1 | Complete | The live 10.1.0-160 API specification and read-only application inspection confirmed the Smart Agent connection, status, PLR request-code, authorization installation, and cancellation contracts used by the application; 10.1 now has an explicit allowlisted profile. |
| FUNC-012 | Retain secure timestamped diagnostics for recent runs | P1 | Complete | CLI and desktop launches share private per-run structured logging with five-run retention, phase timing, a discoverable platform path, and explicit exclusion of credentials and licensing handoff codes. |
| FUNC-013 | Reconcile final FDM unregister read timeouts | P1 | Complete | A timed-out Smart Agent DELETE is never repeated; the workflow polls for disappearance of the exact connection and reports confirmed delayed success, timeout, or ambiguity consistently in CLI and GUI. |

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
| DEV-001 | Link scheduled roadmap work to GitHub Issues | P2 | Proposed | Add an issue link beside an item when work is accepted into a milestone; keep detailed implementation discussion in the issue. |
