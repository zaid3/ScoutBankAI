# Verification results

Release: `0.3.0rc1`. Verification date: 27 October 2026.

## Executed locally

| Check | Result | Scope |
| --- | --- | --- |
| Python test suite | 205 passed | Prior identity, consent, account, journal, encryption, connector and recovery controls, plus repeated audits, peer bindings, provider failures, scoring and evaluator separation |
| HTTPS integration | Passed | Actual loopback TCP with generated CA, verified server certificates and a separate bank HTTP service |
| Mutual TLS boundary | Passed | Worker client certificate accepted; a caller without a client certificate rejected; an untrusted server certificate not accepted |
| Complete payment flow | Passed | Bank-issued staff/customer JWTs, exact approval receipt, agent enrolment, SDK proof, API reservation, worker dispatch and confirmed fixture settlement |
| Duplicate business request | Passed | Repeated signed requests returned the same operation; the separate bank recorded one payment and one debit |
| Browser console | Passed | Real API policy proposal, control approval, reservations, payment review, export, two audit rounds, independent evaluator labels, calculated points and role-specific controls |
| Desktop/mobile layout | Passed | Chromium at 1440 × 1000 and 390 × 844; no horizontal overflow; screenshots inspected |
| Browser credential handling | Passed | No token in localStorage or sessionStorage; token field cleared after connection; disconnect removes the visible records |
| Package build and clean installation | Passed | Wheel installed in a fresh virtual environment; CLI, demo, configuration check, backup, static assets and authenticated OpenAPI verified |
| Known-vulnerability audit | No known vulnerabilities reported for auditable installed dependencies | `pip-audit 2.10.1` against the local test environment; the ScoutBankAI distribution itself is skipped because it is not on PyPI; advisory coverage is not proof of no vulnerabilities |

The added adversarial cases cover two agents with separate mandates racing against one account cap, settled payments consuming rolling limits, old unknown payments retaining outstanding exposure, stale or self-approved control changes, issuer tokens without an explicit human assertion, duplicate bank account aliases, modified payment state, ciphertext substitution, missing keys and key rotation. Schema-1 migration preserves the existing payment and grant state and identifies reconstructed journal history.

Cross-audit cases cover two/three rounds, independent first reports, exact peer coverage, forged context/peer hashes, attempted self-review, hostile free-text exclusion, sticky disagreements, unanimous model mistakes, capacity exhaustion, crashes and idempotent retries. Evaluator cases check role/tenant boundaries, explicit issuer human assertions, separation from both approving and rejecting payment reviewers, duplicate labels, stale result hashes, mandatory controls and bounded positive/negative scoring. Report corruption blocks reading, startup and dispatch. A schema-2 upgrade preserves queued work and requires human review when no prior audit or approval exists.

The OpenAI audit adapter is exercised through controlled HTTP transports for the fixed endpoint, strict schema, credential separation, refused/incomplete/invalid output, redirects, provider errors, oversized responses and duplicate JSON members. These tests verify integration and failure handling; they do not establish the accuracy or independence of live models.

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

The optional primary model reviewer and cross-audit model roles are tested with controlled provider responses, including failures. No paid live model evaluation was performed. Their usefulness, false alarms, provider terms, latency/cost and operational thresholds require evaluation for the selected deployment. The default council uses deterministic local rules. Quality points describe externally supplied labels; no benchmark accuracy or automatic learning is claimed.

Load capacity, disaster-recovery objectives, full recovery-gap reconstruction, infrastructure resilience, institution-specific regulatory requirements and production operations require their own evidence. This test report does not assert those outcomes or a guarantee that no defect remains.
