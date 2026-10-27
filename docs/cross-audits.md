# Repeated agent audits and quality points

ScoutBankAI checks requests on the path to an existing bank gateway. Its audit council adds repeatable reviews of each permitted request. It does not operate a bank, change the core ledger or give a model payment authority.

## Roles and rounds

| Role | First-round task |
| --- | --- |
| Policy | Check the review threshold and mandatory account review |
| Evidence | Check the supplied metadata and the existing supervisor's review flag; identify insufficient evidence |
| Challenge | Look for overlooked concerns in request frequency and the remaining delegated budget |

The default is two rounds, producing six reports. Configuration permits three rounds, producing nine reports. Each round runs the three roles concurrently. The first round is independent: no role sees another role's answer. In later rounds, each role must inspect both other roles' reports from the preceding round against the original context. The stored peer checks bind to exact report hashes. A role cannot submit a self-check, omit a peer or substitute a different report.

Only typed finding codes, booleans, report status and hashes pass between roles. Peer summaries and quality scores are excluded. Reports contain a short explanation for staff; the system does not request or store hidden chain-of-thought. The console shows all recorded rounds, including earlier concerns that later reports drop.

Any review finding in any round, differing review decisions, challenged or uncertain peer check, invalid output or unavailable provider requires an independent human review. Later agreement cannot erase that requirement. The coordinator also applies its own deterministic triggers, even if every model misses them. A hard policy denial occurs before any audit provider call.

The deterministic triggers are the configured amount threshold, mandatory account review, an existing supervisor review flag, five or more preceding requests in the last minute, or an amount greater than the delegated budget remaining after this reservation. The last two are conservative extra review heuristics, not validated fraud detection. They never reject an otherwise permitted payment automatically; they require review. The bank should evaluate their operational impact.

The worker requires a completed clear audit or an independent human approval of the exact payment. It rechecks current authority, account controls, request age, reservations and audit integrity before dispatch. Human approval does not waive hard controls. A stopped, failed or capacity-limited audit cannot silently become approval.

## Rules and model modes

New installations use local deterministic checks:

```json
"audit_council": {
  "mode": "rules",
  "rounds": 2,
  "max_concurrent_audits": 4
}
```

The console labels this **Deterministic rules**. This mode makes no model calls and must not be described as a live AI assessment. It is usable without an external provider account.

To use model auditors, explicitly configure an approved model for each role:

```json
"audit_council": {
  "mode": "openai",
  "rounds": 2,
  "models": {
    "policy": "YOUR_APPROVED_POLICY_MODEL_ID",
    "evidence": "YOUR_APPROVED_EVIDENCE_MODEL_ID",
    "challenge": "YOUR_APPROVED_CHALLENGE_MODEL_ID"
  },
  "token_env": "OPENAI_API_KEY",
  "max_concurrent_audits": 4
}
```

These are placeholders, not usable model IDs. Provision the key privately to the API process and restart after changing configuration. Choose models supporting the strict response schema and output budget. Different prompts or model IDs do not establish genuinely independent judgments; shared training, provider failures and common mistakes remain possible.

Each new permitted payment makes six provider requests with two rounds, or nine with three. Enabling the separate primary model supervisor adds one more. Retries of the same business request do not rerun the council. Provider errors are retained as unusable reports; there is no automatic retry loop. Provider charges still apply to calls made before an error or cancellation.

Requests go only to `https://api.openai.com/v1/responses`, with verified TLS, redirects disabled, no tools and `store: false`. The payload contains amount, currency, review threshold, preceding request count, delegated budget remaining after reservation, account/supervisor review flags, role, round and hashes. It excludes bank account IDs, payee IDs, references, customer identities, staff identities, credentials and score history. This is data minimisation, not a promise of anonymity or zero provider retention; the institution must approve the provider's data handling.

Provider responses are capped at 100 KB and use connection/read timeouts plus an elapsed-time check while reading. Configuration allows one to eight simultaneous councils per API process; each has at most three concurrent calls. Capacity exhaustion holds the request without starting more calls. This is a per-process bound, not a bank-wide quota or service-level guarantee.

Audits run synchronously during submission. The SDK's default read timeout is 120 seconds and can be configured through `ScoutClient(..., timeout=...)`. Match proxy and client timeouts to measured deployment latency. After a timeout, use the same business-idempotency key with a fresh proof to retrieve the recorded request. A timeout is not permission to submit a new payment. The worker recovers stale screening to human review; an interrupted audit is not automatically restarted.

## Points come from independent assessment

Models do not grade themselves or award points to one another. The `evaluator` role records an evidence-based label after a council completes. Integrated tokens require the bank issuer's `scout_actor_type: human` assertion. The evaluator must differ from the customer, agent owner and payment reviewer. The payment reviewer cannot later be the evaluator, and an evaluator cannot later review that payment.

In the console, open **Audit agents**, inspect the original context and each round, then record the expected review decision, confirmed finding codes, evidence reference and explanation. The assessment binds to the completed result hash. No label is preselected. Labels cannot deny a configured threshold, mandatory account review or existing supervisor review requirement.

One immutable assessment is permitted per payment. Only each role's final-round report receives points, once. More rounds, retries and more confident wording earn no extra points. Unlabelled requests are shown as **Not yet scored**, never as 100% accurate.

The `quality-v1` rubric is explicit:

| Final-report result | Points |
| --- | ---: |
| Finding independently confirmed | +2 per finding |
| Finding not supported by the label | −2 per finding |
| Confirmed finding missed | −3 per finding |
| Correct review decision | +1 |
| Necessary review missed | −5 |
| Review requested when the label establishes no trigger | −2 |
| Invalid or unavailable report | −10 total |

For a valid report, add finding points and decision points, then clamp the total to −10 through +10. An unusable report receives the minimum score so that failing to answer cannot outscore a missed risk. The console displays assessed sample count, total and average for each current role/model/mode. It does not turn those numbers into an accuracy percentage. Database records retain the per-report breakdown and earlier model scores when configuration changes.

These points are performance records. They do not give models feelings, improve a model's weights, increase permissions, select a winner, change payment status or allow a model to bypass review. Improving the system requires reviewing errors, independently labelled test cases, revised configuration or model training outside this release, and a separately approved deployment.

An evidence reference is a bank-governed case identifier, not automatic proof of ground truth. The service does not fetch or verify external case files. Bad labels, shared identities, evaluator bias or collusion can produce misleading scores. Use institution-controlled evidence, representative cases and separate held-out evaluations. Labels cannot be edited in this release; retain an external correction record and exclude a disputed label from external analysis. Do not manipulate the application database to rewrite a score.

## Evidence and operating limits

Audit context, configuration, request hash, all reports, peer bindings, result hash, feedback and score breakdowns persist with the payment. Application triggers prevent report, feedback and score edits/deletion and completed-run changes. Per-report and result hashes are checked when reading reports, at startup, during local checks and backups, and before dispatch. Run/report/result hashes and label hashes are also recorded in the existing keyed event chain. Protect the host and retain external checkpoints; these controls do not defeat a fully compromised database administrator with access to all keys.

The council covers bounded metadata for the integrated payment path. It does not inspect every bank system, establish customer intent, verify fraud or sanctions, review arbitrary generated code, or certify a bank-wide audit. Repetition and agreement cannot guarantee no errors. Human and model reviewers can share blind spots.

The provider adapter is tested with controlled HTTP fixtures, including malformed output, refusals, unavailable providers and redirects. No paid live model evaluation or live-bank assessment is claimed. Model usefulness, false positives, missed risks, latency, costs, workload capacity and bank acceptance require deployment-specific evidence.

## API

* `GET /v1/audit-agents`: staff/evaluator view of the latest 100 runs and current model scores.
* `GET /v1/payments/{id}/audits`: tenant-scoped original context, all reports, result binding and any human assessment.
* `POST /v1/payments/{id}/audit-feedback`: evaluator-only immutable assessment; returns calculated points.

The feedback body has `result_hash`, `review_required`, `confirmed_findings`, `evidence_reference` and `explanation`. Use the hash returned by the selected completed audit, not a hash of the payment body. A duplicate assessment returns 409. Invalid labels return 422; labels contradicting mandatory controls return 409. See [audit_models.py](../scoutbankai/audit_models.py) for the exact schema and [api.md](api.md) for role boundaries.

Provider interface references: [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) and [agent evaluations](https://developers.openai.com/api/docs/guides/agent-evals). Structured output constrains response shape; the application still validates bindings and treats the content as untrusted.
