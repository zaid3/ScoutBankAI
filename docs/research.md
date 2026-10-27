# Research and design decisions

Research reviewed on 27 October 2026. These sources explain the design context. They do not endorse, certify or validate ScoutBankAI. The [banking security review](banking-security-review.md) adds current news, public bank architecture and implementation coverage through 0.4.

## What the standards establish

| Primary source | Relevant finding | ScoutBankAI decision |
| --- | --- | --- |
| [IETF RFC 9449: DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) | A signed proof binds use of a token to a key and request context. Possession of a key alone is not an authorisation decision; ordinary DPoP does not bind a request body. | Verify the registered key, token hash, method, URI, freshness, nonce and replay identifier. Add explicit body and business-idempotency hash bindings. |
| [IETF RFC 9396: Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html) | Structured authorisation details express permissions more precisely than broad scope strings alone. | Store an exact account, recipient list, currency, limits and expiry. A bank-signed receipt must match the canonical validated policy. This custom receipt is not a full RAR implementation. |
| [OpenID FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) | High-value API security depends on a complete profile, including protected transport, sender-constrained tokens and authorisation flows. | Use verified HTTPS and mutual TLS at the bank gateway. Do not equate selected controls with implementation or certification of the full FAPI profile. |
| [Open Banking UK: Domestic Payments v4](https://openbankinguk.github.io/read-write-api-site3/v4.0/resources-and-data-models/pisp/domestic-payments.html) | Payment initiation has defined consent, execution and status resources. | Keep the bank's own consent and payment status authoritative. An institution adapter must map actual provider semantics; a ScoutBankAI grant does not replace provider consent. |
| [OWASP: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | Too much functionality, permission or autonomy can turn model errors and manipulation into damaging actions. | Give the advisory model no execution tools or credentials. Enforce limits in deterministic code and require independent review when needed. |
| [FCA: AI in financial services](https://www.fca.org.uk/publications/good-poor-practice/ai-financial-services) | Governance, testing, clear accountability, oversight and monitoring matter across the AI lifecycle. | Provide testable boundaries and recorded decisions. Require bank-specific validation and ownership before live use; a software test suite does not establish regulatory compliance. |

## The project's engineering contribution

ScoutBankAI combines these established ideas into a small, inspectable control service. The contribution is how the parts work together across failures, rather than a claim to have invented agent identity or payment authorisation.

The exact customer permission is carried from a signed approval receipt to a registered agent key, a signed request body, a transactional reservation, an independent review hash and a durable bank operation. If a worker crashes after committing its dispatch boundary, the operation becomes uncertain and is looked up by its original identity. A missing response cannot silently release the budget or trigger a second transfer.

The integration surface is deliberately narrow: an existing bank identity issuer and an existing payment gateway remain authoritative. Banks can inspect the code and tests without adopting a new agent framework or replacing their account ledger.

## What this research does not establish

This is not an exhaustive review of every GitHub repository or every banking system. Related work on delegated permissions, verifiable intent, agent identity and payment controls already exists. No first-in-the-world or patent novelty claim is made.

The tests demonstrate specified behaviour against controlled fixtures. They do not measure fraud reduction, bank adoption, commercial savings or resilience at a named bank's production volume. Those outcomes require deployment evidence. No named bank is presented as a customer, integration partner or endorser.

The system cannot reliably distinguish every hidden agent from every human behind an ordinary browser login. Its stronger claim is narrower: enrolled requests on its integrated path carry verifiable identity and a permission that can be checked before execution.
