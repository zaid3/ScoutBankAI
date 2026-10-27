# Integration with an existing bank

ScoutBankAI is an access and execution control service. The institution keeps its identity provider, customer channels, account ledger, payment engine, screening systems and settlement connections.

## Components and ownership

| Component | Owner | Connection |
| --- | --- | --- |
| Customer authentication and approval | Bank | Its existing application issues a signed receipt after approval |
| Staff authentication | Bank | Short-lived issuer-signed access token |
| Agent private key | Agent operator | Public key registration; private key stays with the agent |
| Delegated permission | Customer, through the bank | `/v1/mandates` with a policy-bound receipt |
| Policy enforcement and audit | ScoutBankAI | API and durable state store |
| Payment execution | Bank | Worker calls the fixed gateway adapter |
| Funds, financial crime checks and final status | Bank | Native payment controls and authoritative outcome |

## Integrate the bank issuer

Set `mode` to `integrated`. This disables development bearer tokens. Configure an HTTPS issuer, the `scoutbankai` audience and a pinned local JWKS file maintained by the institution. Keys require a unique `kid`, an explicit `RS256` or `ES256` algorithm and signature use. Rotate the public file atomically. Untrusted `jku`, `x5u` and embedded key headers are rejected.

Access tokens need `iss`, `aud`, `sub`, `tenant`, `role`, `iat` and `exp`. Maximum lifetime is 900 seconds. `sub` and `tenant` are opaque identifiers using letters, numbers, underscores or hyphens. Enable each tenant through the host administration command before accepting its tokens:

Operator and reviewer tokens must additionally contain `"scout_actor_type": "human"`. The bank issuer must reserve this assertion for its protected staff authentication flow. A service token, missing assertion or unsupported actor type is rejected for these roles. This is a verified issuer assertion, not biometric detection or proof that credentials were never shared.

```sh
scoutbankai enable-tenant --config /run/scout/config.json bank-one
```

The bank should map an existing staff identity to exactly one role per token:

| Role | API authority |
| --- | --- |
| `operator` | Register agents, account aliases and payees; pause; freeze; propose control changes; suspend; revoke; inspect evidence |
| `reviewer` | Approve or reject payments and control changes independently |
| `auditor` | Read the console and verify evidence |
| `customer` | Grant a permission with an exact consent receipt; issue tokens for an existing permission; revoke own permissions |

The agent uses a separate opaque DPoP token. No staff or customer bearer token can call the agent payment interface as an agent.

This service validates signed assertions. Authentication strength, staff lifecycle, MFA, customer identity and bank approval channels remain the issuer's responsibility. It does not infer that an authenticated session is necessarily being operated by a human.

## Record exact customer consent

The bank application collects the proposed `MandateRequest`, validates it against its own policies, displays the account, agent, recipients, permissions, limits and expiry to the customer, and runs its approval flow. It then signs a short-lived customer token with these additional claims:

```json
{
  "scout_action": "grant_mandate",
  "scout_policy_sha256": "SHA256_OF_CANONICAL_VALIDATED_POLICY",
  "auth_time": 1793059200,
  "jti": "ONE_UNIQUE_RANDOM_RECEIPT_IDENTIFIER"
}
```

The example timestamp is illustrative, not a valid current receipt. Compute the hash over all fields returned by `MandateRequest.model_dump()`, including defaults, using `scoutbankai.crypto.canonical`. This is the product's explicit receipt format, not a claim to implement the full OAuth Rich Authorization Requests protocol.

The API checks the exact policy hash, owning customer, issuer signature, tenant, recent approval time and single-use receipt identifier. A receipt expires for this purpose after five minutes; a small forward clock tolerance is allowed. Reusing it cannot create a second grant. Changing a recipient or increasing the budget requires fresh bank approval.

Bank-side approval must bind what the customer sees to what the issuer signs. The institution must not give an agent an unrestricted way to request these approval receipts. Customer session authentication alone does not establish transaction-specific consent.

## Register accounts and recipients

The operator creates immutable aliases with `/v1/accounts` and `/v1/payees`. Account registration binds the alias to a bank customer and currency. A customer cannot grant access to an account owned by another customer. Recipient aliases map to identifiers understood by the bank gateway.

New installations encrypt bank identifiers with the configured AES-256-GCM vault. Integrated writes and dispatch reject an unavailable vault or plaintext identifiers. One bank account identifier cannot be registered twice within a tenant. The institution must use a canonical bank identifier: distinct upstream strings for the same account cannot be recognised as aliases automatically. After registration, an operator proposes shared account limits and a different reviewer approves them. Requests fail closed until those limits exist.

This release does not edit an existing alias in place. A changed recipient must receive a new alias and a new customer permission, preventing old authorisations from silently pointing to a different recipient.

## Issue an agent token

`POST /v1/mandates/{id}/tokens` requires the owning customer's token and an active grant. Tokens last at most fifteen minutes and never outlive their grant. Only a hash of the opaque token is stored. Delivery to the selected agent must use the bank's authenticated channel. Do not put tokens in links, browser storage, prompts or logs.

Each payment includes a DPoP proof from the registered key. The SDK obtains a server nonce, signs the method, configured origin and path, token hash, request body hash and idempotency key, and submits the request. Replaying a proof is rejected. Retrying a business request requires a fresh proof and the original idempotency key.

## Connect the bank payment API

Implement [the adapter contract](bank-adapter-contract.md) inside the bank's approved gateway. Map its messages to the actual core banking or payment-provider APIs. ScoutBankAI does not require access to the core database.

For a UK Open Banking integration, the adapter must preserve the provider's own payment consent, customer authorisation, certificates, signing requirements, payment initiation schema, status model and idempotency semantics. A ScoutBankAI mandate does not replace that bank's consent. The current release does not ship a certified Open Banking PISP or assert out-of-the-box access to JPMorgan, Citi, a UK bank, Temenos or another named platform.

The generic HTTP connector is implemented and tested. Institution-specific mappings and credentials must be supplied and tested against that institution's authorised environment.

