# Verification results

Release: `0.1.0rc1`. Verification date: 26 October 2026.

## Executed locally

| Check | Result | Scope |
| --- | --- | --- |
| Python test suite | 105 passed | Authentication, signed exact consent, policy, concurrency, review, recovery, connectors, backups and configuration |
| HTTPS integration | Passed | Actual loopback TCP with generated CA, verified server certificates and a separate bank HTTP service |
| Mutual TLS boundary | Passed | Worker client certificate accepted; a caller without a client certificate rejected; an untrusted server certificate not accepted |
| Complete payment flow | Passed | Bank-issued staff/customer JWTs, exact approval receipt, agent enrolment, SDK proof, API reservation, worker dispatch and confirmed fixture settlement |
| Duplicate business request | Passed | Repeated signed requests returned the same operation; the separate bank recorded one payment and one debit |
| Browser console | Passed | Real API operator pause/resume and chain verification, reviewer approval, auditor export and role-specific controls |
| Desktop/mobile layout | Passed | Chromium at 1440 × 1000 and 390 × 844; no horizontal overflow; screenshots inspected |
| Browser credential handling | Passed | No token in localStorage or sessionStorage; token field cleared after connection; disconnect removes the visible records |
| Package build and clean installation | Passed | Wheel installed in a fresh virtual environment; CLI, demo, configuration check, backup, static assets and authenticated OpenAPI verified |

The Python suite ran on Python 3.12.14. Browser automation used Playwright 1.62.1 and Chromium 153 in the local execution environment. CI also defines Python 3.11, 3.12 and 3.13 jobs and a separate browser job. A configured CI job is not itself a passing run; consult the repository's actual Actions results for each commit.

Starlette currently emits a test-client deprecation warning about its `httpx` integration. The tests pass; that warning is recorded here rather than suppressed or presented as a failure.

## Reproduce

```sh
python -m pip install -e '.[test]'
python -m pytest -q
python -m pip wheel . --no-deps --wheel-dir dist
scoutbankai demo --directory .state-verification
scoutbankai check --config .state-verification/config.json
```

For the browser workflow, follow [CONTRIBUTING.md](../CONTRIBUTING.md). It creates private disposable state, runs the actual API and exercises the console at desktop and mobile sizes. Screenshots contain simulated fixture identities and amounts, not bank customer records.

The HTTPS test is in [test_end_to_end.py](../tests/test_end_to_end.py). All certificates are generated at test time and all accounts and money are simulated. Other test files isolate failure cases, including a lost bank response, a worker restart, concurrent spending, proof replay, modified payloads, expired or revoked grants, unauthorised review and audit corruption.

## What remains institution-specific

No live bank credentials were used. No real funds moved. The generic gateway contract has not been accepted by a named bank, and the project has no FAPI certification or independent penetration-test attestation.

The optional model reviewer is tested with controlled provider responses, including failures. No paid live model evaluation was performed. Its usefulness, false alarms, provider terms and operational thresholds require evaluation for the selected deployment.

Load capacity, disaster-recovery objectives, full recovery-gap reconstruction, infrastructure resilience, institution-specific regulatory requirements and production operations require their own evidence. This test report does not assert those outcomes or a guarantee that no defect remains.
