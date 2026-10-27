# ScoutBankAI

**AI agent security and control for existing banking systems.**

ScoutBankAI sits between an authorised agent and a bank's APIs. It verifies the agent's key, checks the customer's delegated permission, reserves the permitted budget, and sends an accepted request through a separate bank worker. Every decision has a recorded outcome. If a bank response is lost, the payment remains unresolved until its status can be reconciled.

Created and maintained by **A Haque (zaid)**. [GitHub profile](https://github.com/zaid3).

## Release status

**0.2.0rc1 is an installable release candidate.** The API, agent client, operator console, durable payment state machine, consent checks, HTTP bank connector and optional model reviewer are implemented. This release adds shared account limits, independent approval of control changes, account isolation, an append-only reservation journal and encrypted bank identifiers. The verified suite contains 147 passing Python tests, including a real HTTPS and mutual TLS integration test. Browser checks cover control proposals, independent approvals, reservation verification, payment review, auditor export and desktop/mobile layout. See [verification results](docs/verification.md) for the exact scope.

Live bank acceptance has not been completed. The included development bank uses simulated money. The integrated connector makes actual HTTPS requests to an operator-configured bank gateway; that gateway must implement the documented contract and connect to the institution's authorised systems. This release is not FAPI-certified, a regulated bank, a replacement core ledger, or a universal connector to every bank.

## The problem

A customer login identifies an account session. It does not establish whether a person or software is operating that session, or prove that the customer approved a particular action.

ScoutBankAI gives an agent a separate identity and a bounded permission. Its integrated mode also requires a bank-signed receipt describing the exact permission approved by the customer. Ordinary customer session tokens cannot create new agent authority. The bank remains responsible for authenticating the customer and running its approval process.

## Which banking problems does it address?

| Banking problem | ScoutBankAI's response | Practical benefit |
| --- | --- | --- |
| An agent uses a customer's login, leaving the bank unclear about who is acting | Separate registered agent keys and proof-bound tokens | The integrated API can attribute the request to an enrolled agent without accepting the customer's password |
| A valid login is mistaken for permission to move money | A signed bank receipt binds the customer's approval to an exact account, recipient list, budget and expiry | The bank can check the scope of permission for every proposed action |
| An agent changes an amount or recipient while pursuing a task | The request body is signed and checked against the stored permission | Altered requests and actions outside the permission are rejected |
| Simultaneous agent requests exceed a spending budget | Budget checks and reservations occur in one database transaction | Parallel requests cannot spend the same remaining delegated budget |
| Multiple agents split spending across different permissions on the same account | Shared per-payment, rolling 24-hour, outstanding and rate limits | Separate grants cannot bypass that account's approved limits |
| One compromised administrator raises limits or resumes a paused bank | A proposal bound to its exact contents, an independent reviewer and a current configuration version | Sensitive changes require two distinct bank-attested human identities |
| A delayed instruction executes after conditions change | The worker rechecks current limits, account freezes and request age at dispatch | Stale or newly disallowed work is stopped before contacting the bank |
| Reservation records drift from payment outcomes | A balanced append-only reservation journal, startup verification and dispatch checks | State corruption can be detected before a bank request is sent |
| A timeout leaves the bank unsure whether a transfer succeeded | A durable payment record retains an unresolved state and uses authoritative status lookup | The worker avoids creating another transfer merely because a response was lost |
| A model approves its own mistake | Hard controls run separately; sensitive requests need an independent reviewer identity | A model's output cannot expand authority or directly execute a payment |
| A customer withdraws consent or an agent is compromised | Permission revocation, agent suspension and a bank pause control | Undispatched work can be stopped while existing bank operations are reconciled |
| Staff cannot reconstruct why an action happened | Permission, request, review, dispatch and outcome are recorded in one event chain | Operations teams have evidence for investigation and reconciliation |

These controls apply to the integrated API path. A bank still needs its own controls for account sessions outside that path, customer verification, fraud, sanctions, available funds and settlement.

## Engineering approach and innovation

The engineering contribution is an integrated control flow that carries a customer's precise permission through agent authentication, concurrent budget reservation, independent review and final bank outcome. Authority and payment state remain connected when a model fails, consent changes, a request is retried or a worker restarts.

The design makes three connections explicit:

* **Identity to authority:** an enrolled agent key is tied to a customer-approved permission, rather than inheriting all the power of a customer's login.
* **Authority to the exact action:** the permission, signed request body and review hash identify the amount, recipient and request being evaluated.
* **Action to financial outcome:** a durable state machine retains reservations until the bank confirms success or terminal failure. Missing responses remain unresolved.

The project builds on established cryptography, DPoP, delegated authorisation concepts and transactional storage. Its contribution is the implementation, integration boundary and testable failure handling. It does not claim to invent those standards or to be the first system with agent permissions. [Research and design decisions](docs/research.md) explain the sources and scope.

For banks, the intended value is a controlled route for authorised agents to use existing services, clearer operational evidence and fewer avoidable errors around permissions and retries. Benefits such as reduced fraud losses or lower operating costs require measurement in a bank deployment; the repository does not present unmeasured savings as results.

## What works

| Control | Behaviour |
| --- | --- |
| Agent identity | Registered P-256 public keys and proof-bound, short-lived access tokens |
| Request verification | ES256 DPoP checks for the key, token, method, destination, freshness and server nonce; additional body and idempotency bindings |
| Customer consent | Bank-signed, recent, single-use receipts bound to the exact permission in integrated mode |
| Payment permissions | Explicit account, recipient list, currency, per-payment limit, total budget, expiry and submission rate |
| Concurrent requests | Atomic budget reservations and persistent idempotency records in SQLite |
| Shared account limits | Approved limits span every agent and grant for the account; integrated mode denies requests until limits exist |
| Control approvals | Exact proposal hash, two distinct staff identities, 15-minute expiry and configuration version checks |
| Account isolation | Immediate freeze stops new work and cancels undispatched requests; reopening requires independent approval |
| Reservation journal | Balanced reserve, release and settlement entries; payment and budget consistency verification |
| Bank identifier encryption | AES-256-GCM with record-bound authentication, versioned keys and an explicit rotation command |
| Independent review | A separate reviewer role approves the exact stored request hash; it cannot expand the permission |
| AI supervision | Optional structured model assessment can require review; deterministic controls remain authoritative |
| Revocation | Customer permission revocation and operator agent suspension cancel undispatched work |
| Emergency pause | Stops new requests and dispatches while status reconciliation continues |
| Payment recovery | Durable dispatch boundary; uncertain results hold the reservation and are looked up without blind resubmission |
| Audit evidence | Append-only application writes, an HMAC-linked event chain and exportable checkpoints |
| Existing identity systems | Signed access tokens from a configured bank issuer, with a pinned issuer key set |
| Existing banking systems | Separate HTTPS/mTLS worker connector, fixed bank origin and a documented adapter contract |
| Operations | Configuration checks, consistent SQLite backups, audit checkpoints and a documented recovery procedure |
| Operator console | Actual recorded requests, review actions, agent suspension, revocation, pause, refresh and audit verification |

No bank passwords, card numbers, private agent keys or unrestricted remote tool URLs are accepted by the agent API. The model receives bounded payment metadata only and has no bank tools or execution credentials.

## Install and test

Use Python 3.11 or later. From the repository directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest -q
scoutbankai --help
```

## Try the full control flow

Use a new directory for each run:

```sh
scoutbankai demo --directory .state
scoutbankai serve --config .state/config.json
```

Open `http://127.0.0.1:8090`. Use the `operator` token in the private `.state/credentials.json` file to connect the console. Use the separate `reviewer` token for review actions. These development tokens expire after 24 hours. They are not bank credentials.

The demo runs the real permission and payment logic against a deterministic test bank. It records an allowed request, a limit violation, a review request, a lost response followed by reconciliation, and revocation of undispatched work. The console displays those stored events. It does not invent live activity.

## Run the HTTP bank integration locally

This path runs a separate bank HTTP service and the same worker used by the integrated deployment. Start with a fresh state directory:

```sh
scoutbankai init --directory .state-http
```

Run each long-running command in its own terminal:

```sh
scoutbankai serve --config .state-http/config.json
scoutbankai mock-bank --config .state-http/config.json
scoutbankai worker --config .state-http/config.json
```

Then submit a sample signed request:

```sh
scoutbankai sample --config .state-http/config.json
```

The worker sends it to the separate test bank over HTTP and records the returned outcome. Both development services bind to loopback. Stop the earlier demo server before starting another service on port 8090.

## Connect an existing bank

Follow [the integration guide](docs/bank-integration.md) and [the bank adapter contract](docs/bank-adapter-contract.md).

1. Configure the bank's issuer, audience and public signing keys. Map its approved staff and customer identities to ScoutBankAI roles and a bank tenant.
2. Connect the bank's customer approval flow to signed consent receipts. The receipt must bind the exact requested policy.
3. Register approved account and payee aliases, configure the vault keyring, and obtain independent approval for account limits. Staff tokens must include the bank's `scout_actor_type: human` assertion. Keep the bank's own account identifiers behind the worker boundary.
4. Map the bank's existing payment API to the adapter contract, including stable idempotency and authoritative status lookup.
5. Configure HTTPS, client certificates, bank access credentials, secrets storage, monitoring and backups. Run the integration acceptance checks against the bank's authorised test environment.

The connector is independent of the agent framework. An agent using LangGraph, CrewAI, an MCP client, a scheduled service or ordinary application code can call the same authenticated API. Framework-specific plugins are not required, and none of those products is an endorsed partner.

## Use the agent client

The bank supplies a permission-bound token after customer approval. The agent keeps its private key locally. This example assumes an already registered key and an active permission:

```python
import os
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from scoutbankai.client import ScoutClient

key = load_pem_private_key(Path(os.environ['SCOUT_AGENT_KEY_FILE']).read_bytes(), password=None)
with ScoutClient(os.environ['SCOUT_ORIGIN'], os.environ['SCOUT_AGENT_TOKEN'], key) as client:
    payment = client.create_payment({
        'mandate_id': os.environ['SCOUT_MANDATE_ID'],
        'payee_id': 'approved_supplier',
        'amount_minor': 5000,
        'currency': 'GBP',
        'reference': 'Invoice 101',
    }, idempotency_key='invoice_101_payment_v1')
    print(payment['id'], payment['status'])
```

Reuse the same idempotency key only for an identical business request. After an uncertain client response, reuse that key with a fresh proof to retrieve the same recorded operation. A changed body with that key is rejected. An accepted API request is not a settled payment.

## Optional AI reviewer

The default `rules` supervisor works without a model provider. To enable model review, configure:

```json
"supervisor": {
  "mode": "openai",
  "model": "YOUR_APPROVED_MODEL_ID",
  "token_env": "OPENAI_API_KEY"
}
```

Provide the key privately to the API process. Each new permitted payment can make one provider request and incur provider charges. The request uses structured output and `store: false`. It contains amount, currency, configured review threshold, recent request count and remaining delegated budget. Account identifiers, recipients, references, customer identities and banking credentials are excluded. `store: false` is not a promise of zero provider retention; approve the provider's actual terms and data handling for your deployment.

An unavailable provider, refusal or malformed result requires independent review. The model cannot approve a policy violation, change the recipient or amount, grant consent, release a reservation or call the bank. [The supervision model](docs/architecture.md) explains the boundary. Provider responses are tested with controlled fixtures; a live model evaluation is still required for the selected model and intended use.

## Operational boundaries

The [banking security review](docs/banking-security-review.md) maps current reported risks and public bank architecture to implemented controls. The [account security guide](docs/account-security.md) explains the new API, role boundaries, monetary journal and key rotation. Existing installations must follow the [0.2 upgrade procedure](docs/operations.md#upgrading-from-01).

The database is a single-installation SQLite store with transactional writes. This release does not provide distributed high availability, automated disaster recovery or a guaranteed service level. Deploy the API and worker on the same trusted host/storage boundary. Do not share a SQLite database over a network filesystem.

ScoutBankAI controls requests routed through it. It cannot identify every hidden agent using a customer's browser session or protect bank endpoints that bypass it. The bank's own fraud checks, sanctions screening, customer verification, available-funds checks and payment authorisation still apply.

A completed transfer is not automatically reversible. Revocation can stop undispatched work; a dispatched or unresolved request must be reconciled with the bank. An audit hash chain also requires independent checkpoint retention to detect removal of its tail.

## Documentation

* [Bank integration and identity mapping](docs/bank-integration.md)
* [Bank adapter API contract](docs/bank-adapter-contract.md)
* [Architecture and payment states](docs/architecture.md)
* [API reference](docs/api.md)
* [Threat model and security boundaries](SECURITY.md)
* [Research, standards and coverage](docs/research.md)
* [Deployment and recovery](docs/operations.md)
* [Verification results](docs/verification.md)
* [Banking security research and coverage](docs/banking-security-review.md)
* [Account controls, approvals and encryption](docs/account-security.md)

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

