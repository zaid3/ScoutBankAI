# Security model

ScoutBankAI enforces the scope of delegated agent actions routed through its API. A valid agent key establishes an enrolled actor, not honesty or human intent. A bank-signed consent receipt establishes what the bank attests was approved, not proof that every part of the customer's device or approval channel is uncompromised.

## Assets and trust

Protect issuer signing keys, agent private keys, bank gateway credentials, audit and nonce keys, the permission database, request state and the gateway's authoritative payment journal.

The bank issuer, approved gateway, host operating system, local database access, key provisioning and deployment configuration are trusted. Agent input and model output are untrusted. The model has no permission to register an agent, mint a customer approval, alter a policy or execute a payment.

## Threat coverage

| Threat | Implemented boundary | Remaining dependency |
| --- | --- | --- |
| Stolen opaque agent token | Proof of the registered private key is also required | Protect agent runtime and private key |
| Replayed signed request | Server nonce, bounded timestamps and persistent proof replay cache | Correct server time and retained database |
| Changed payment body or idempotency key | Both are bound into the proof | TLS and trustworthy client display |
| Agent expands its authority | Strict policy, bank-signed exact consent receipt, independent execution code | Secure bank approval channel |
| Model manipulation or failure | No bank tools; hard limits; invalid results require review | Evaluate the selected model's usefulness and false alarms |
| Concurrent overspending | Atomic reservation and stored business idempotency | Bank applies its own funds and aggregate controls |
| Cross-customer or cross-tenant access | Ownership and tenant checks on the API | Correct issuer-to-role mapping |
| Insider self-approval | Separate reviewer role and actor checks | Bank identity governance and independent staff |
| Lost bank response | Durable uncertainty and status lookup, no blind retries | Authoritative bank journal and reconciliation process |
| Compromised agent | Suspend its identity and revoke permissions | Detection and incident response supplied by the institution |
| Audit modification | Application append-only writes and keyed chain verification | External checkpoint retention, independent key protection |
| Malicious outbound destinations | Fixed connector origin, TLS verification, no redirects or caller URLs | Egress firewall and approved configuration |
| API abuse | Body/header limits, strict JSON and persistent request/velocity limits | Edge rate limits, DDoS protection and workload sizing |

## Not provided

This release does not identify every undeclared AI session, replace KYC/AML/sanctions controls, certify regulatory compliance, guarantee fraud prevention, perform credit decisions, move money without the bank's authorisation, reverse settled payments or secure systems outside the integrated path.

Local database files are not encrypted by this package. Use appropriate encrypted storage and managed key storage. Keys and customer access tokens must not appear in source control, model prompts, public demos or issue reports. The integrated API does not accept development tokens, and the development server refuses a public bind address.

The SQLite deployment is for one trusted installation. Distributed availability, infrastructure penetration testing, bank-specific threat modelling, operational recovery exercises and independent security review are deployment acceptance work, not inferred from passing unit tests.

## Reporting a vulnerability

Use the repository's private vulnerability reporting feature when enabled. Do not publish credentials, private customer information or details of a live institution in a public issue. Include a minimal reproduction against local fixtures, the affected version and the expected security boundary.

