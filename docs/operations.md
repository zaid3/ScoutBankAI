# Deployment and recovery

ScoutBankAI runs as an API process and a bank worker on one trusted installation. SQLite must be on local durable storage. Do not deploy multiple hosts against a shared network filesystem or infer high availability from multiple API workers.

## Configure an integrated installation

Install the package in a dedicated Python environment and run commands as a dedicated operating-system account. The following generates local audit, nonce and identifier-encryption keys. It does not create bank access credentials:

```sh
scoutbankai configure --directory /var/lib/scoutbankai \
  --origin https://agents.your-bank.example \
  --issuer https://identity.your-bank.example \
  --bank-url https://gateway.your-bank.example/scout
```

Replace the example domains with the institution's actual approved endpoints. The command refuses a nonempty destination. Provision the required files through the institution's secret-management process:

* `bank-jwks.json`: the bank issuer's public verification keys.
* `bank-client.crt` and `bank-client.key`: the worker's accepted client certificate and private key.
* `bank-token.key`: the bank gateway credential, containing only the token.

The configuration resolves file paths relative to its own directory. Set owner-only permissions on private keys, credentials, state and backups. Integrated settings reject group/world-accessible secret files on POSIX systems. If the gateway uses a private CA, add `connector.ca_file` with that CA bundle. Server verification is always enabled.

Run the local checks, enable an approved tenant and start the services:

```sh
scoutbankai check --config /var/lib/scoutbankai/config.json
scoutbankai enable-tenant --config /var/lib/scoutbankai/config.json bank-one
scoutbankai serve --config /var/lib/scoutbankai/config.json
scoutbankai worker --config /var/lib/scoutbankai/config.json
```

Run the final two commands in separate supervised processes. `check` verifies configuration, issuer key material, connector credentials, database integrity, the audit chain, cross-audit report bindings, the reservation journal and identifier decryption. It makes no bank or model request and is not a readiness certificate for a live deployment. `enable-tenant` is host administration; it must be restricted to authorised administrators. Register accounts and obtain independent approval of their shared policies before accepting payments in integrated mode.

## HTTPS and network boundaries

Put the API behind the bank's approved TLS reverse proxy. Preserve the configured `Host`, request path and security headers. Forward only to the loopback service; do not expose its HTTP port publicly. Use the same public origin in the SDK and configuration. Incoming origins are checked and cross-origin browser access is not enabled.

The proxy must reject ambiguous headers, limit request sizes and enforce connection and per-client limits before forwarding. The application does not trust `X-Forwarded-For`, so its IP rate limit sees the proxy address. Size or tune the edge and application limits for the approved workload. The built-in limits are conservative, not a throughput guarantee.

Restrict worker egress to the approved bank gateway. The optional model reviewer requires access to the configured provider's fixed API endpoint. TLS verification and redirects are not weakened to accommodate a failing connection.

Cross-audits default to local rules. Configure the optional model council and bounded per-process concurrency using [cross-audits.md](cross-audits.md). Two rounds make six provider requests; three make nine. Audit calls run during payment submission, so align proxy and client timeouts with measured latency. The SDK defaults to a 120-second read timeout. A client timeout must use the original business-idempotency key on retry. Provider failures, capacity limits and stale screening are held for human review, not automatically resubmitted.

API and worker code are separate processes, but this release trusts the shared host and database boundary. It does not provide hardware-enforced separation between them. Protect the host and use managed secrets, encrypted storage, OS-level service supervision and restricted administrator access.

## Service supervision

Run the API and worker under the institution's service manager. Restart on failure, allow graceful termination and alert on repeated crashes. A basic systemd worker unit can use:

```ini
[Unit]
Description=ScoutBankAI bank worker
After=network-online.target
Wants=network-online.target

[Service]
User=scoutbankai
Group=scoutbankai
ExecStart=/opt/scoutbankai/.venv/bin/scoutbankai worker --config /var/lib/scoutbankai/config.json
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/scoutbankai

[Install]
WantedBy=multi-user.target
```

For the API, use a separate unit with the `serve` command and the same protected state directory. Provision service accounts, installation paths and TLS before enabling either unit. The unit is deployment guidance, not a claim that the repository has been installed on a production host.

## Monitoring

`/healthz` checks API availability and basic database access. It does not prove that the worker, bank gateway or settlement network is available. Monitor the worker process separately.

Inspect payment state counts with `scoutbankai check`. Alert on growing `unknown`, `submitted`, `dispatching`, `screening` or `review` queues, old unresolved records, storage errors, failed checks and unexpected permission changes. Use the stored `created` and `updated` timestamps to implement institution-specific age thresholds. No alert destination is configured automatically.

The check also returns cross-audit mode and state counts. Monitor capacity-limited/interrupted runs, invalid/unavailable reports, review disagreements, labelled sample counts, score distributions, model latency and provider costs. A score is based on supplied human labels, not an independently measured production accuracy rate. Keep payment reviewers and audit evaluators separate.

The console shows bounded snapshots, not all-time totals. Use controlled database reporting for institution-wide metrics. Application access logs are disabled by default to avoid token or payment disclosure. Configure reverse-proxy logs to exclude authentication headers and bodies. Keep clocks synchronised.

## Pause and incident handling

An operator can pause new requests and dispatches in the console. The worker continues status reconciliation. Revoke affected permissions or suspend a compromised agent. A pause or revocation cannot recall a request that has already crossed the dispatch boundary, and cannot reverse settled money.

Use an account freeze to contain one affected account. It cancels undispatched work and leaves in-flight reconciliation active. In integrated mode, an independent reviewer must approve a current proposal before a paused bank can resume. Reopening a frozen account always requires that approval. See [account security](account-security.md).

If a bank operation is `unknown`, investigate the bank's authoritative journal using the stored payment ID and request hash. Do not manually change it to `queued`, give it a fresh business-idempotency key, or release the reservation because a status endpoint is unavailable. The bank must establish whether a payment exists and provide a trustworthy terminal outcome. A 404 alone is not proof that no payment occurred.

## Backups and independent checkpoints

```sh
scoutbankai audit --config /var/lib/scoutbankai/config.json --output checkpoint.json
scoutbankai backup --config /var/lib/scoutbankai/config.json \
  --directory /secure-backups/scoutbankai-2026-10-26 --anchor checkpoint.json
```

Choose a new backup directory for each run. The backup uses SQLite's online backup API to capture a consistent snapshot, checks database and audit integrity, and writes a manifest with a SHA-256 checksum and audit checkpoint. A backup without a completed manifest is incomplete. The command never replaces an existing directory.

The backup contains sensitive institution data. Encrypt it, restrict access and apply the bank's retention policy. Store keys separately through the secret-management process: this command intentionally does not copy them. Keep the manifest and checkpoints in independent protected storage. A checksum detects accidental corruption; it does not authenticate a manifest that an attacker can also replace. An independently retained audit checkpoint detects truncation through that point.

## Recovery from a snapshot

Recovery requires a supervised reconciliation exercise; it is not an automatic rollback button.

1. Stop dispatch and isolate the damaged installation. Preserve its database, WAL files and incident evidence.
2. Restore the snapshot into a new private directory, with the correct audit key and configuration. Check the manifest checksum and audit chain before running any worker. Use the checkpoint that belongs to this snapshot.
3. Keep API intake and dispatch stopped. Compare the bank journal, retained audit checkpoints and business requests across the **entire interval between the snapshot and the outage**. The old snapshot may be missing operations that actually settled.
4. Reconcile every nonterminal record and any missing post-snapshot operation through the institution's authoritative process. A later external checkpoint will correctly fail against an older snapshot. Do not discard that discrepancy or re-submit lost work with new identities.
5. Revoke stale grants and tokens through an institution-approved recovery procedure, obtain fresh customer authority where necessary, and resume only after the bank has accepted the reconciliation.

This release does not provide automatic database merging, recovery-gap reconstruction or disaster-recovery orchestration. Restoring a snapshot alone does not preserve exactly-once business execution. The gateway must retain its idempotency journal for the bank's complete recovery horizon.

## Upgrades and acceptance

Back up first, test the new package and schema against a copy, and retain the previous installation. An unsupported database schema version is rejected. This release uses schema version 3.

### Upgrading from 0.3

Schema 3 is unchanged. Stop intake/workers under the normal upgrade procedure, retain a verified backup and test the new package against a copy before resuming. Timeline search can read existing events; new control approvals record before/after state, but earlier missing details are not reconstructed. No policies, payments, grants or scores are rewound by the upgrade. The new restoration operation always creates a fresh proposal with independent approval. See [timeline recovery](timeline-recovery.md).

### Upgrading from 0.2

1. Stop intake and workers, take a verified backup and test 0.4 against a copy before upgrading the installation. Schema 2 is upgraded transactionally to schema 3, adding audit-run, report, feedback and score tables. Packages before 0.3 refuse schema 3.
2. Existing payment, permission, reservation and account-control records are retained. No past AI reports or scores are invented. Existing queued payments without completed audits move to human review before dispatch unless the exact payment already has an independent human approval. In-flight payments continue reconciliation; migration does not resubmit them.
3. The omitted `audit_council` setting defaults to two local rules rounds. Explicitly configure approved model IDs and the provider key only after evaluation. Provision the bank's separate `evaluator` role with a protected human assertion for scoring. Existing development state has no automatically added evaluator token; create a fresh disposable demo to exercise this role.
4. Run `check`, the tests against the institution's authorised gateway and an independent review before restarting intake and workers. Retain the original backup, configuration and keys for the recovery procedure.

### Upgrading from 0.1

1. Stop intake and workers. Take and verify a backup with the old package; retain the old keys and deployment separately.
2. Install 0.4 in a separate environment and test it against a copy. Opening a schema-1 database transactionally creates the new tables and derives reservation entries from existing payment state. A migration audit event identifies that reconstruction; it is not invented historical evidence. Packages before 0.3 refuse schema 3. Do not point them at the upgraded database. Apply the cross-audit and evaluator guidance above as well.
3. Provision an owner-only vault keyring and add `vault_keyring_file` to the configuration. Follow the keyring format and rotation process in [account security](account-security.md). Run `vault-reencrypt` while intake and workers are stopped to encrypt legacy bank identifiers. Preserve old backup keys and address plaintext remnants in old storage.
4. Update the issuer's protected operator/reviewer/evaluator flow to include `scout_actor_type: human`. Do not let agents choose this claim.
5. Register one canonical alias per bank account. Resolve any pre-existing duplicate aliases under the institution's migration process; do not silently merge account histories or change old mandates.
6. Start the API with dispatch stopped. An operator proposes limits for each account and a different reviewer approves them. Integrated mode fails closed without a policy. Run `check`, the authorised bank integration tests and an independent review before resuming dispatch.

Rollback requires the retained pre-upgrade snapshot and the full recovery-gap procedure if any activity occurred after it. It is not safe to restore an old snapshot and blindly replay requests.

Before live use, validate the institution's issuer and consent channel, gateway mappings, certificate and key rotation, bank rejection and timeout semantics, retention, recovery, workload capacity, monitoring, incident response and selected model behaviour. Obtain independent security and operational review. Repository test results are evidence for that review, not a substitute for institution acceptance.
