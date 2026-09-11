# Testing guide

This project uses Python's built-in `unittest` framework. The discovered suite
runs locally, in PyCharm, and in GitHub Actions:

```bash
python -m unittest discover -v
```

## Standard human test commands

Run commands from the repository root with the project virtual environment
active:

```bash
# Standard development and pre-commit test (exit 0 means pass)
python -m unittest discover -v

# Focused live Cisco OAuth check (exit 0 means a token was retrieved)
python cisco_support_token_client.py --check

# Focused integration-test form; skips if credentials are unavailable
python -m unittest -v tests.test_live_cisco_token

# Discover all supported FDM example switches; performs no network request
python example.py --help
```

The direct OAuth check reads credentials from the native OS credential store,
makes one live token request, and does not print credentials or the token. Use
`python key_manager.py status` to check whether the Cisco and FDM credential
groups are complete without displaying their values. Mocked GUI tests cover
the scalable host-selection contract: a sole host is pre-filled, multiple
hosts are not enumerated, and typing an exact host retains its matching stored
username and password.
The integration test skips only when the credential entries are genuinely
absent. Empty environment secrets, credential-backend failures, rejected
credentials, and OAuth service failures fail with distinct bounded messages.
Do not treat a skipped integration test as proof that token retrieval works.

Test files live in the importable `tests/` package and use the `test_*.py`
naming convention. Root-level discovery recursively finds them. Test methods should
name the observable behavior they protect, such as
`test_absolute_request_path_is_rejected_before_network_call`.

The suite contains deterministic mocked tests and conditional live integration
tests. `tests/test_live_cisco_token.py` reads Cisco
credentials from environment variables when GitHub injects them, otherwise it
checks the native operating-system credential store. It performs one real OAuth
request when a complete credential pair exists and skips when none exists.

## Declaring a required test

Use either of these phrases in an agent request:

```text
[test-required]
Test requirement: an HTTP 401 causes exactly one re-authentication attempt.
```

Each `Test requirement:` line is an acceptance criterion. The implementation
and its test are one change: the agent must add or update a focused test, run
the full suite, and report mocked and live results separately. This marker is
useful when a specific scenario matters, but observable behavior changes and
bug fixes need mocked tests by default under `AGENTS.md`.

A useful feature request is concrete about inputs, outputs, and side effects:

```text
Add support for refreshing an expired cached token.

[test-required]
Test requirement: an unexpired cached token is returned without an HTTP call.
Test requirement: an expired token causes one HTTP call and replaces the cache.
Test requirement: secrets and bearer tokens never appear in logs or errors.
```

## Test construction rules

- Exercise the public interface unless an internal security invariant cannot
  be observed there.
- Keep one behavior per test and use deterministic inputs.
- Mock HTTP sessions, clocks, credential stores, and other external boundaries.
- Assert important side effects, including call count and cleanup, as well as
  return values and raised exceptions.
- For a bug fix, first add a regression test that demonstrates the failure when
  practical, then implement the fix.
- Keep mocked tests deterministic and isolated from networks, live devices,
  external APIs, and operating-system credential stores.
- Add or update a conditional live test when a feature depends on behavior that
  only the real service can verify. It must skip only when required credentials
  or endpoint configuration are absent.
- Limit routine live tests to authentication and documented read-only requests.
  Mutating live tests require explicit authorization for the exact operation.
- Never place real credentials, tokens, certificates, or customer data in test
  code or fixtures.

## Where tests run

Run the suite locally before pushing for fast feedback. In PyCharm, create a
Python test configuration for `Unittests` with the project directory as the
target, or run an individual test from the gutter icon.

GitHub Actions provides the shared clean-environment run.
`.github/workflows/tests.yml` runs the discovered suite on every push and pull
request using the oldest supported Python version and a current Python version.
Live tests skip there when protected credentials are unavailable. Configure the
repository's protected branch to require both matrix checks before merging.

## Live Cisco OAuth integration test

Git Credential Manager stores credentials used by Git itself to access a remote
repository. Do not put Cisco API credentials in it. GitHub-hosted jobs should
receive application credentials from GitHub Actions secrets, preferably through
a protected GitHub Environment.

Create an Environment named `cisco-integration` in the repository's
**Settings > Environments** page. Add these Environment secrets:

- `CISCO_CLIENT_ID`
- `CISCO_CLIENT_SECRET`

For sensitive organizational credentials, restrict deployment branches and add
required reviewers to that Environment. Then open **Actions > Cisco integration
> Run workflow**. The workflow requests a real token and checks its basic
metadata without printing the token or credentials.

GitHub does not prompt for secret values when a workflow starts. The secrets
must already exist in the Environment; GitHub supplies them to the job after
any Environment protection rules are satisfied.

This workflow is manual and separate from required push/PR checks so protected
credentials are not exposed to untrusted pull-request code. Once credentials
are supplied, invalid credentials or Cisco OAuth failures fail the live test.
The current test validates token generation only; a real licensing API call
requires a documented read-only endpoint and separate integration test.

On a developer workstation, `python -m unittest discover -v` checks the native
keyring automatically. If the credentials were stored with `python
key_manager.py store`, the live token test runs alongside the mocked tests. The
stored FDM record can also drive authorized local device tests without a
plaintext `.env` password. If Cisco credentials are absent, the live token test
reports `skipped`. A GitHub-hosted runner cannot
read the Windows Credential Manager on the computer that pushed the commit.

Every test report must distinguish these outcomes:

- Mocked tests: passed or failed.
- Applicable live tests: passed, failed, or skipped with the missing
  configuration identified without exposing its value.
- A skip is expected only when required configuration is absent. Service errors
  and rejected credentials are failures when the configuration exists.
- Native credential-store access errors are failures, not missing-credential
  skips. On systems that sandbox Keychain or Credential Manager access, run the
  live test in the same approved host context as the application.
- Agent-executed macOS Keychain validation must request elevated execution when
  sandboxed execution cannot access the native Keychain.

CI configuration belongs in the repository because it is reviewed and versioned
with the code, applies consistently to every contributor, and can be reproduced
from a checkout. GitHub hosts the runners, so no local machine needs to remain
online. The tradeoffs are queue time, hosted-runner limits, and some coupling to
GitHub Actions syntax. If the project later moves to GitLab, keep the test
command and test files unchanged and translate only the workflow into
`.gitlab-ci.yml`.
