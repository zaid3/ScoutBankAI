# Public release review

Reviewed on 27 October 2026. Release: `0.4.0rc1`. Created and maintained by A Haque (zaid).

ScoutBankAI is an implemented security and execution-control layer for agent requests to existing bank APIs. Its strongest engineering feature is the connection between explicit authority, hard limits, recorded reviews, durable payment state and controlled recovery. Optional AI reviewers operate inside that boundary; they do not own it.

## What the evidence supports

| Area | Evidence and current status |
| --- | --- |
| Identity and permission enforcement | Automated tests exercise enrolled keys, proof binding, exact consent, tenant isolation, expiry and revocation |
| Payment safety on the integrated path | Shared limits, reservations, dispatch/reconciliation and cancellation races are tested against simulated bank outcomes and an actual local HTTPS/mTLS fixture |
| Repeated audits | Bounded roles/rounds, preserved disagreements, peer bindings, failures and independent quality labels are implemented and tested |
| Timeline and recovery | Searchable historical evidence, pagination, signed events, exact pre-dispatch cancellation and independently approved policy restoration are implemented |
| Packaging and console | Installable package and browser acceptance tests cover real local API flows; see the current CI run and verification report |
| Live model effectiveness | Not established; controlled provider fixtures verify integration and failure handling, not real-model accuracy |
| Named bank production integration | Not established; no named bank has accepted the generic adapter or supplied live acceptance evidence |
| Independent security assurance | No external penetration-test or certification attestation is claimed |
| Operational scale and resilience | Single-installation SQLite design; bank-scale load, high availability and recovery objectives are not demonstrated |

## The most useful next improvements

1. **Measure real model behaviour.** Use an approved dataset with independent labels, held-out cases and adversarial inputs. Report missed risks, false alarms, latency and cost by model/configuration. More agents or a larger points total cannot substitute for those measurements.
2. **Prove one authorised bank integration.** Exercise its consent, issuer mapping, payment statuses, duplicate handling, cancellation boundary, gateway outages and complete recovery gap in its approved test environment.
3. **Obtain independent testing.** Include identity/permission bypass, prompt manipulation, concurrent requests, role separation, secret exposure and dependency/infrastructure review. Track concrete findings and fixes.
4. **Validate operations.** Establish load limits, alerting, evidence retention, key management and restoration exercises with the institution. Evaluate provider outages and exit plans before depending on live model audits.

These are the next acceptance activities, not features falsely marked complete in this release. [Banking security research](banking-security-review.md) maps current public concerns to the controls and their remaining boundaries.

## How to describe the project publicly

Describe it as an open-source release candidate that gives banks a controlled route for authorised AI agents, with independent audit rounds, traceable decisions and safe recovery actions. Link the repository, exact test evidence and limitations. Say that the default mode uses deterministic rules and that live AI audits require configured models and credentials.

Do not claim that it is deployed by a named bank, endorsed by a regulator, FAPI-certified, immune to AI attacks, independently penetration-tested or proven to reduce fraud losses. None of those outcomes follows from passing repository tests.

For LinkedIn and Medium, a concrete walkthrough of an allowed request, a blocked policy violation, a disagreement requiring review and a cancellation/restore is more useful than a universal-security claim. For Kaggle, a reproducible evaluation notebook with synthetic or properly authorised data would be a useful next deliverable; it is not included or measured yet. Never publish real customer records, tokens or bank credentials as examples.

The current licence is Apache 2.0. See [licensing choices](licensing.md) before promising exclusivity or paid-only commercial use.
