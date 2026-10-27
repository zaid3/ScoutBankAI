# Account security and independent control changes

ScoutBankAI applies three layers of permission: the bank's own controls, a shared account policy approved by staff, and the customer's narrower agent mandate. An agent cannot edit either policy. A model recommendation cannot override a denial.

## Roles that actually have authority

| Actor | Allowed | Excluded |
| --- | --- | --- |
| Customer | Approve an exact mandate through the bank, obtain its token, revoke it | Staff policy changes or review |
| Registered agent | Propose and read payments under its proof-bound mandate | Account administration, reviewer actions, bank credentials |
| Model supervisor | Return a bounded advisory that can require review | Execution tools, arbitrary URLs, identity issuance or policy changes |
| Operator | Enrol approved aliases, propose controls, pause, freeze, suspend and revoke | Approving their own control proposal or directly resuming an integrated bank |
| Independent reviewer | Approve the exact payment or control proposal | Editing a proposal or approving one they proposed |
| Auditor | Read tenant evidence and verify it | Mutating controls or payments |
| Worker | Recheck current authority and submit through the fixed bank gateway | Creating customer consent or ignoring unresolved outcomes |

These are implemented roles and code paths. They are not a claim that autonomous customer service, credit, compliance, fraud investigation or a licensed digital bank has been implemented. The issuer must protect staff authentication, assign distinct people to duties and reserve `scout_actor_type: human` for that protected flow. A signed assertion is not infallible human detection.

## Set shared account limits

An operator calls `POST /v1/control-changes` with a bank-issued bearer token:

```json
{
  "action": "account_limits",
  "account_id": "business_account",
  "reason": "Treasury approved the supplier payment policy",
  "limits": {
    "per_payment_minor": 50000,
    "rolling_day_minor": 100000,
    "max_pending_minor": 100000,
    "max_payments_per_minute": 10,
    "max_request_age_seconds": 900,
    "require_review": true
  }
}
```

Amounts use the registered account's currency in integer minor units. For GBP, `50000` is £500. These are illustrative limits, not recommended limits for a bank. A limit proposal never increases an existing customer mandate.

The response includes `id`, `request_hash` and the complete `proposal`. A different reviewer inspects that proposal and calls `POST /v1/control-changes/{id}/review`:

```json
{"decision": "approve", "request_hash": "EXACT_HASH_RETURNED_WITH_THE_PROPOSAL"}
```

The displayed placeholder must be replaced with the actual 64-character hash. The reviewer cannot supply a replacement policy. Approval expires after fifteen minutes and is single-use. A configuration version change, including another freeze, makes an older approval stale. Rejected and expired proposals do not take effect.

The console exposes the same workflow, including policy details, reason, proposer, expiry, hash and history. Integrated mode blocks new payments without an approved account policy. Development fixtures retain the original mandate-only behaviour until an account policy is approved; this exception is not available in integrated mode.

## What each account limit counts

* `per_payment_minor`: the amount of one request.
* `rolling_day_minor`: amounts reserved during the preceding 86,400 seconds, across all agents and mandates, excluding definitively cancelled or rejected operations. Settled operations still count while their request timestamps remain in that window. This is a request-volume cap, not a settlement-day accounting total.
* `max_pending_minor`: all unresolved reservations, even if older than 24 hours. Screening, review, queued, dispatching, submitted and unknown states all count.
* `max_payments_per_minute`: recorded payment requests during the preceding sixty seconds. Later cancellation does not undo this rate count.
* `max_request_age_seconds`: how long a request may wait before dispatch, from 30 to 3,600 seconds. It does not cancel a payment already sent to the bank.
* `require_review`: requires independent review for every request. Turning it off cannot override a mandate threshold or an advisory requiring review.

Checks and reservations use the same immediate SQLite transaction. Separate mandates cannot race around the shared cap. A canonical upstream bank account identifier can have only one registered alias in a tenant. The bank must normalise that identifier: two different upstream strings for the same real account cannot be recognised automatically.

The worker checks the current policy again immediately before its durable dispatch boundary. A newly disallowed request is cancelled and its grant reservation released. A newly required review returns an unreviewed request to the review queue. If new lower aggregate limits conflict with existing queued work, the worker cancels disallowed queued requests in its normal processing order until the remaining work fits. Already dispatched work is never recalled by changing a limit.

## Containment and recovery

`POST /v1/accounts/{id}/freeze` immediately blocks new requests and cancels undispatched work. Dispatched and unknown payments retain their reservations and continue reconciliation. Reopening requires an `unfreeze_account` proposal with `account_id` and `reason`, followed by independent review.

An operator can pause the tenant immediately with `POST /v1/pause`. In integrated mode, resuming requires a `resume_bank` proposal with a reason and independent approval. A new pause invalidates earlier resume proposals. An agent, customer or auditor cannot initiate these administrative changes.

These controls affect the ScoutBankAI route only. The connected bank must also contain affected credentials, sessions, devices and routes outside this service.

## Reservation journal

The journal records equal amounts against two control buckets for each reservation, release and confirmed settlement. Rows cannot be updated or deleted through normal SQL writes. A payment has one reservation and at most one terminal release or settlement entry. Retries and concurrent reconciliation do not add another terminal entry.

Startup, `scoutbankai check`, backups and `GET /v1/journal/verify` verify payment hashes, journal amounts and states, and the relationship between original grant budgets and remaining reservations. Dispatch also verifies the selected payment before any network request. Corruption fails closed. Audit-chain verification is a separate control; retain independent checkpoints.

This is a delegated-reservation journal. It does not create deposits, calculate a customer's balance, reconcile external statements, implement interest or replace the bank's general ledger. Host administrators with database and key access remain trusted.

## Encryption and key rotation

Fresh `init` and `configure` commands create an owner-only `vault-keys.json`, referenced by `vault_keyring_file` in the configuration. Each key is a random 32-byte AES key. Each encryption uses a fresh random 96-bit nonce and authenticates the tenant, table, record and field. Copying ciphertext to another record or changing its bytes fails authentication.

The encrypted fields are `accounts.bank_id` and `payees.bank_id`. Amounts, payment references, aliases, policies and audit metadata are not encrypted by this vault. The bank worker decrypts identifiers when preparing the bank request. Protect its memory, the host and storage. The file-backed key provider is implemented; managed KMS or HSM integration is not.

For a planned rotation:

1. Stop API intake and workers. Take a verified encrypted backup and preserve the original keyring separately.
2. Provision a fresh random 32-byte key under a new key ID using the institution's secret-management process. Keep old keys and change the keyring's `active` ID atomically. Keep owner-only permissions.
3. Run `scoutbankai vault-reencrypt --config /path/to/config.json`. It decrypts and re-encrypts all current bank identifier fields within one transaction. It prints counts and the key ID, never key values or account identifiers.
4. Run `scoutbankai check`, validate an authorised integration test, then restart services. Other running processes do not hot-reload keyrings; all must restart.
5. Retain old keys for old backups until those backups are migrated or their retention period ends. Plaintext from an earlier release can remain in old backups, WAL or freed storage pages. Re-encryption is not secure erasure; handle those media through the bank's storage lifecycle.

Set rotation and usage limits appropriate to a 96-bit random-nonce GCM design. Do not reuse a nonce intentionally, replace AES with custom cryptography, commit keys, or claim that encryption alone prevents every compromise.
