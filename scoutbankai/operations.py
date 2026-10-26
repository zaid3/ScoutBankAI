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
    config = {
        "mode": "integrated", "origin": origin, "issuer": issuer,
        "audience": "scoutbankai", "database": "scout.db", "jwks_file": "bank-jwks.json",
        "audit_key_file": "audit.key", "nonce_key_file": "nonce.key",
        "connector": {"base_url": bank_url, "cert_file": "bank-client.crt",
                      "key_file": "bank-client.key", "token_file": "bank-token.key"},
        "supervisor": {"mode": "rules"},
    }
    private_write(path / "config.json", json.dumps(config, indent=2) + "\n")
    return {"config": str(path / "config.json"), "status": "requires_bank_provisioning",
            "required_files": ["bank-jwks.json", "bank-client.crt", "bank-client.key", "bank-token.key"]}


def check(service):
    settings = service.settings
    if service.store.rows("PRAGMA integrity_check")[0]["integrity_check"] != "ok":
        raise ValueError("database integrity check failed")
    if settings.mode == "integrated":
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
    return {"status": "local_checks_passed", "mode": settings.mode, "version": __version__,
            "audit_checkpoint": service.store.verify_audit(),
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
        target.execute("PRAGMA journal_mode=DELETE")
    with database.open("rb") as file:
        checksum = hashlib.file_digest(file, "sha256").hexdigest()
    manifest = {"version": __version__, "schema": 1, "created_at": int(time.time()),
                "database": "scout.db", "sha256": checksum,
                "audit_checkpoint": checkpoint, "keys_included": False,
                "recovery": "Pause dispatch and reconcile the entire backup gap with the bank before resuming."}
    private_write(destination / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return manifest
