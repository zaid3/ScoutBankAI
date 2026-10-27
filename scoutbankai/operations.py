"""Host administration tools. No bank calls or secret values in command output."""
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import jwt

from . import __version__
from .bootstrap import private_write
from .config import Settings
from .connectors import HTTPBankAdapter
from .crypto import strict_json
from .store import verify_chain
from .journal import verify_financial_state
from .council import verify_audits
from .vault import new_keyring


def configure(directory, origin, issuer, bank_url):
    audit_key, nonce_key = secrets.token_bytes(32), secrets.token_bytes(32)
    Settings(database="scout.db", audit_key=audit_key, nonce_key=nonce_key,
             mode="integrated", origin=origin, issuer=issuer, jwks_file="bank-jwks.json",
             connector={"base_url": bank_url}).validate()
    path = Path(directory).resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(path.iterdir()):
        raise ValueError("Choose an empty configuration directory")
    path.chmod(0o700)
    private_write(path / "audit.key", audit_key)
    private_write(path / "nonce.key", nonce_key)
    private_write(path / "vault-keys.json", json.dumps(new_keyring()))
    config = {
        "mode": "integrated", "origin": origin, "issuer": issuer,
        "audience": "scoutbankai", "database": "scout.db", "jwks_file": "bank-jwks.json",
        "audit_key_file": "audit.key", "nonce_key_file": "nonce.key",
        "vault_keyring_file": "vault-keys.json",
        "connector": {"base_url": bank_url, "cert_file": "bank-client.crt",
                      "key_file": "bank-client.key", "token_file": "bank-token.key"},
        "supervisor": {"mode": "rules"},
        "audit_council": {"mode": "rules", "rounds": 2},
    }
    private_write(path / "config.json", json.dumps(config, indent=2) + "\n")
    return {"config": str(path / "config.json"), "status": "requires_bank_provisioning",
            "required_files": ["bank-jwks.json", "bank-client.crt", "bank-client.key", "bank-token.key"]}


def check(service):
    settings = service.settings
    if service.store.rows("PRAGMA integrity_check")[0]["integrity_check"] != "ok":
        raise ValueError("database integrity check failed")
    if settings.mode == "integrated":
        if not service.vault.active:
            raise ValueError("integrated mode requires a vault keyring")
        keys = strict_json(Path(settings.jwks_file).read_bytes()).get("keys", [])
        seen = set()
        if not keys:
            raise ValueError("issuer key set is empty")
        for key in keys:
            kid = key.get("kid")
            if (not isinstance(kid, str) or not kid or kid in seen or key.get("alg") not in {"RS256", "ES256"}
                    or key.get("use", "sig") != "sig" or any(p in key for p in ("d", "p", "q", "k"))):
                raise ValueError("issuer key set must contain distinct public signing keys")
            jwt.PyJWK.from_dict(key)
            seen.add(kid)
    bank = HTTPBankAdapter(settings.connector, settings.mode)
    try:
        bank._token()
    finally:
        bank.close()
    with service.store.transaction() as db:
        financial = verify_financial_state(db)
        cross_audits = verify_audits(db)
        for table in ("accounts", "payees"):
            for row in db.execute(f"SELECT id,tenant,bank_id FROM {table}"):
                service.vault.open(row["bank_id"], row["tenant"], table, row["id"])
    return {"status": "local_checks_passed", "mode": settings.mode, "version": __version__,
            "audit_checkpoint": service.store.verify_audit(),
            "reservation_journal": financial,
            "cross_audits": cross_audits,
            "vault": "AES-256-GCM" if service.vault.active else "not_configured",
            "cross_audit_states": service.store.rows("SELECT status,count(*) AS count FROM audit_runs GROUP BY status"),
            "cross_audit_mode": settings.audit_council["mode"],
            "payment_states": service.store.rows("SELECT status,count(*) AS count FROM payments GROUP BY status"),
            "network_contacted": False, "bank_acceptance": "requires_authorised_environment"}


def backup(service, directory, anchor=None):
    destination = Path(directory).resolve()
    # New destination only: never replace an existing or active database.
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = destination / "scout.db"
    private_write(database, b"")
    with closing(service.store.connect()) as source, closing(sqlite3.connect(database)) as target:
        source.backup(target, pages=100)
        target.row_factory = sqlite3.Row
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("backup database integrity check failed")
        checkpoint = verify_chain(target, service.settings.audit_key, anchor)
        financial = verify_financial_state(target)
        cross_audits = verify_audits(target)
        schema = target.execute("PRAGMA user_version").fetchone()[0]
        target.execute("PRAGMA journal_mode=DELETE")
    with database.open("rb") as file:
        checksum = hashlib.file_digest(file, "sha256").hexdigest()
    manifest = {"version": __version__, "schema": schema, "created_at": int(time.time()),
                "database": "scout.db", "sha256": checksum,
                "reservation_journal": financial,
                "cross_audits": cross_audits,
                "audit_checkpoint": checkpoint, "keys_included": False,
                "recovery": "Pause dispatch and reconcile the entire backup gap with the bank before resuming."}
    private_write(destination / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return manifest


def reencrypt_vault(service):
    """Host-only migration/rotation. Use a stopped installation and retained backup."""
    if not service.vault.active:
        raise ValueError("configure a vault keyring before migrating")
    changed = 0
    with service.store.transaction() as db:
        for table in ("accounts", "payees"):
            for row in db.execute(f"SELECT id,tenant,bank_id FROM {table}").fetchall():
                plaintext = service.vault.open(row["bank_id"], row["tenant"], table, row["id"], migration=True)
                ciphertext = service.vault.seal(plaintext, row["tenant"], table, row["id"])
                db.execute(f"UPDATE {table} SET bank_id=? WHERE tenant=? AND id=?", (ciphertext, row["tenant"], row["id"]))
                changed += 1
        for tenant in db.execute("SELECT id FROM tenants").fetchall():
            service.store.event(db, tenant[0], "vault_reencrypted", "host_operator", service.clock(), key_id=service.vault.active)
    return {"records_reencrypted": changed, "active_key_id": service.vault.active,
            "old_backups": "retain their original key versions; migrate storage separately"}
