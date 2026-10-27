# Activity timeline and controlled recovery

Created and maintained by A Haque (zaid).

The console's **Activity timeline** shows who acted, the recorded time, the action, the affected record and the available reason and evidence. It covers recorded bank-control and payment events, including model audit rounds. It is a history of this integration's actions, not a recording of every activity inside the bank.

## Inspect earlier work

Filter by an exact actor ID, action code, payment/account/change ID, or a time range. Dates entered in the console use the browser's local timezone and become Unix timestamps for the API. Open recorded details to inspect hashes and other evidence. New control-change events include readable before/after states, the reason and the identity of the proposer or reviewer. Audit-round events identify their role, model or rules mode, findings and report hash.

The first page captures an event-sequence snapshot. **Load older events** continues within that snapshot, so new arrivals do not shift or duplicate the history being inspected. Refresh or search again to include new events. The API returns at most 100 events per page; the console requests 50. There is no 100-event historical cutoff. Export downloads the currently loaded filtered events and the snapshot/cursor metadata, not all records automatically.

Each returned event's keyed signature is checked. This is not the same as verifying the complete chain or detecting a removed tail. Operator/auditor users can use **Verify chain**, and an independently retained checkpoint is needed to detect truncation through that checkpoint. Historical viewing is read-only and never reinstates old permissions.

Earlier releases did not record every before/after state. Existing events remain as originally recorded; the upgrade does not invent missing historical facts. Filters match IDs actually recorded in event fields. An older event without an account ID can still be found through its change or payment ID.

## What can be undone safely?

| Action | Available recovery | What stays intact |
| --- | --- | --- |
| Payment still screening, held for review or queued | Operator selects **Cancel before dispatch**, gives a reason and confirms the exact request | Original request, reviews, audit history and one reservation release |
| Previously approved account limits | Operator selects **Request restore of these limits**, or restores recorded limits from a timeline approval event | A new proposal is created; the current limits stay active until a separate reviewer approves |
| Account freeze or installation pause | Existing controlled reopening/resume workflow | No old snapshot can bypass independent approval |
| Revoked permission or suspended agent | New bank-governed enrolment/consent as appropriate | History is retained; no time-travel reactivation |
| Dispatched, submitted, unresolved or settled payment | Bank reconciliation and, where appropriate, a separately authorised bank reversal/compensating transaction | The service does not pretend to recall or erase a bank operation |
| Audit history, feedback or points | Read and retain evidence; separately investigate an error | No deletion, rewrite or unrestricted rollback button |

### Pending payment cancellation

The cancellation endpoint checks the operator role, tenant, exact request hash and live payment status inside the same write transaction used by dispatch claims. If cancellation wins, the reservation is released once and dispatch cannot start. If dispatch wins, cancellation returns a conflict and the bank outcome must be reconciled. Repeating a successful operator cancellation does not release money twice. Advice arriving after cancellation cannot queue the payment again.

Cancellation is final for that stored request. A later business decision to pay requires a new properly authorised request; do not reuse the cancelled record as a hidden retry.

### Restoring account limits

Only an approved account-limits record is eligible as a source. Its exact hash must match, and the current account version must still match the operator's view. The service copies those limits into a new 15-minute proposal, records the source change ID and requires a different bank-issued reviewer. Approval checks the version again. A later freeze, policy change or competing approval makes an outdated request fail instead of overwriting newer state.

Restoring limits does not unfreeze the account, undo revocation, restore a budget, change old payment outcomes or redispatch cancelled payments. The previous approval record is not edited. Restoring an already-current policy is rejected as unnecessary. Previously approved policies still need a fresh risk judgment; old approval does not establish that the limits remain suitable today.

## API

| Endpoint | Role and behaviour |
| --- | --- |
| `POST /v1/timeline/search` | Staff/evaluator read-only search using a JSON body; all results are tenant-scoped |
| `GET /v1/accounts/{id}/controls` | Staff/evaluator reads one current account policy/version beyond the bounded overview |
| `GET /v1/control-changes/{id}` | Staff/evaluator reads and verifies one historical proposal |
| `POST /v1/payments/{id}/cancel` | Operator supplies `request_hash` and a 5–240 character `reason` |
| `POST /v1/control-changes/{id}/restore` | Operator supplies `source_hash`, `expected_version` and a 5–240 character `reason`; returns a new pending proposal |

Timeline filters are `actor`, `action`, `object_id`, `from_time`, `to_time`, `before_seq`, `snapshot_seq` and `limit`. Use the returned `next_before_seq` and original `snapshot_seq` with the same filters to continue. No caller-supplied tenant is accepted. Query-string parameters remain disabled; the search uses POST only to carry bounded filters and does not change state.

Recovery is scoped to authorised application operations. A database restore is a separate operational procedure requiring reconciliation of the complete recovery gap with the bank. See [operations](operations.md).
