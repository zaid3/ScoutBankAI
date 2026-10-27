# API reference

All API routes are relative to the configured origin. The authenticated schema is available at `GET /v1/openapi.json` to an operator or auditor. It documents the request models and authentication schemes. Unknown model fields, duplicate JSON members and ambiguous security headers are rejected. Requests and responses must not be logged with credentials.

## Control API

Use `Authorization: Bearer <bank-issued token>` in integrated mode. Development credentials are accepted only in development mode. Every object access is tenant-scoped.

| Method and path | Role | Purpose |
| --- | --- | --- |
| `POST /v1/agents` | operator | Register a P-256 public key, name and owner |
| `POST /v1/accounts` | operator | Bind an account alias to its customer, bank account alias and currency |
| `POST /v1/payees` | operator | Register an immutable recipient alias |
| `POST /v1/mandates` | customer | Grant exact delegated authority; integrated mode requires a signed consent receipt |
| `POST /v1/mandates/{id}/tokens` | owning customer | Issue a short-lived, proof-bound agent token |
| `POST /v1/mandates/{id}/revoke` | owning customer or operator | Revoke permission and cancel undispatched work |
| `POST /v1/agents/{id}/suspend` | operator | Suspend an agent and cancel undispatched work |
| `POST /v1/pause` | operator | Pause immediately; direct resume is development-only |
| `POST /v1/payments/{id}/review` | independent reviewer | Submit `decision` and the exact `request_hash` |
| `GET /v1/overview` | operator, reviewer, auditor or evaluator | Read the bounded tenant snapshot |
| `GET /v1/audit/verify` | operator or auditor | Verify the installation audit chain and return its latest checkpoint |
| `GET /v1/openapi.json` | operator or auditor | Read the generated OpenAPI schema |
| `GET /v1/controls` | operator, reviewer, auditor or evaluator | Read up to 200 account policies and 100 control changes |
| `POST /v1/control-changes` | operator | Propose account limits, account reopening or bank resume |
| `POST /v1/control-changes/{id}/review` | independent reviewer | Approve or reject the exact proposal hash |
| `POST /v1/accounts/{id}/freeze` | operator | Freeze the account immediately and cancel undispatched work |
| `GET /v1/journal/verify` | operator or auditor | Check tenant reservation entries, payment hashes and remaining grant budgets |
| `GET /v1/audit-agents` | operator, reviewer, auditor or evaluator | Read the latest 100 cross-audits and labelled current-model scores |
| `GET /v1/payments/{id}/audits` | operator, reviewer, auditor or evaluator | Read original context, all audit rounds and an existing assessment |
| `POST /v1/payments/{id}/audit-feedback` | independent evaluator | Record an immutable evidence label and calculate points once |

Required registration, permission and review fields are defined in [models.py](../scoutbankai/models.py). Amounts use integer minor units; GBP, EUR and USD are supported. An amount of `5000` means 50.00 of the selected currency. Floating-point money and arbitrary currencies are rejected.

The mandate defines the account, agent, recipient allowlist, currency, permitted API actions, per-payment cap, total delegated budget, review threshold, expiry and maximum requests per minute. It lasts at most 30 days. The budget is a grant budget, not a daily reset or a substitute for bank funds checks.

Integrated operator, reviewer and evaluator tokens also need the issuer's `scout_actor_type: human` assertion. Account limits are a separate, mandatory integrated control spanning all grants. See [account security](account-security.md) for exact payloads, version conflicts, expiry and monetary semantics. The [cross-audit guide](cross-audits.md) defines assessment fields, the scoring rubric and separation between evaluator and payment reviewer. Agent tokens have no access to these administrative endpoints.

## Agent API

Use `Authorization: DPoP <agent token>`. The provided [Python client](../scoutbankai/client.py) signs proofs locally and obtains fresh nonces. A custom CA can be supplied with `ca_file`; certificate verification cannot be disabled through the client interface.

| Method and path | Additional requirement | Purpose |
| --- | --- | --- |
| `POST /v1/nonce` | Active permission-bound token | Obtain a fresh server nonce |
| `POST /v1/payments` | DPoP proof and stable `Idempotency-Key` | Request a payment under the stored mandate |
| `GET /v1/payments/{id}` | Fresh DPoP proof | Read an operation belonging to the same agent and mandate |

Payment fields are `mandate_id`, `payee_id`, `amount_minor`, `currency` and `reference`. A `202` response means the request has a stored state, not that money has settled. Inspect `status` and reconcile with the bank through the worker.

Reuse a business-idempotency key for retries of the same validated request, with a fresh proof each time. Reusing that key with a different body is a conflict. Tokens expire after at most fifteen minutes; obtain a replacement through the owning customer's approved channel while the original grant remains active. Revoked or expired authority cannot be revived by retrying an old token.

## Errors and health

Errors return `{"error": "machine_readable_code"}`. Validation errors also identify affected field paths without echoing submitted values. Typical responses are 400 for malformed requests, 401 for invalid identity/proof, 403 for denied authority, 409 for a state/idempotency conflict, 413 for oversized bodies, 422 for invalid models, 423 for a paused bank, 429 for rate limits and 503 for unavailable storage.

The `use_dpop_nonce` response includes a new `DPoP-Nonce` when the underlying agent token remains valid. Create a new proof; do not replay the old one. After an uncertain client response, use the original business-idempotency key. Never change the key solely to get around an error.

`GET /healthz` is an unauthenticated local availability check. It does not establish worker or bank health. See [operations](operations.md) for monitoring and deployment boundaries.
