import hashlib
import hmac
import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from .crypto import canonical
from .errors import BridgeError

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY, paused INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS principals(hash TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, owner TEXT NOT NULL, name TEXT NOT NULL, thumbprint TEXT NOT NULL, jwk TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS accounts(id TEXT NOT NULL, tenant TEXT NOT NULL, customer TEXT NOT NULL, bank_id TEXT NOT NULL, currency TEXT NOT NULL, PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS payees(id TEXT NOT NULL, tenant TEXT NOT NULL, bank_id TEXT NOT NULL, label TEXT NOT NULL, PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS mandates(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, customer TEXT NOT NULL, agent TEXT NOT NULL, account TEXT NOT NULL, policy TEXT NOT NULL, budget_remaining INTEGER NOT NULL CHECK(budget_remaining>=0), expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, tenant TEXT NOT NULL, agent TEXT NOT NULL, mandate TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS proofs(hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS consent_receipts(hash TEXT PRIMARY KEY, mandate TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, agent TEXT NOT NULL, mandate TEXT NOT NULL, account TEXT NOT NULL, payee TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0), currency TEXT NOT NULL, reference TEXT NOT NULL, idempotency TEXT NOT NULL, request_hash TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL, bank_id TEXT, reviewed_by TEXT, UNIQUE(tenant,agent,idempotency));
CREATE INDEX IF NOT EXISTS payments_work ON payments(status,updated);
CREATE INDEX IF NOT EXISTS payments_velocity ON payments(mandate,created);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, event TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TABLE IF NOT EXISTS rate_limits(bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS payments_tenant ON payments(tenant,created DESC,id);
CREATE INDEX IF NOT EXISTS audit_tenant ON audit(tenant,seq DESC);
CREATE INDEX IF NOT EXISTS agents_tenant ON agents(tenant);
CREATE INDEX IF NOT EXISTS mandates_tenant ON mandates(tenant);
CREATE INDEX IF NOT EXISTS proofs_expiry ON proofs(expires);
CREATE INDEX IF NOT EXISTS rate_limits_expiry ON rate_limits(expires);
"""


class Store:
    def __init__(self, path: str, audit_key: bytes):
        self.path, self.audit_key = str(path), audit_key
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(self.connect()) as db:
            if db.execute("PRAGMA user_version").fetchone()[0] not in {0, 1}:
                raise ValueError("unsupported database schema version")
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
            db.execute("PRAGMA user_version=1")
        Path(path).chmod(0o600)
        self.verify_audit()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def event(self, db, tenant: str, action: str, actor: str, now: int, **details):
        tail = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = tail[0] if tail else "0" * 64
        event = canonical({"tenant": tenant, "action": action, "actor": actor, "time": now, **details}).decode()
        signature = hmac.new(self.audit_key, (previous + event).encode(), hashlib.sha256).hexdigest()
        db.execute("INSERT INTO audit(tenant,event,previous,hash) VALUES(?,?,?,?)", (tenant, event, previous, signature))

    def verify_audit(self, anchor: dict | None = None):
        with closing(self.connect()) as db:
            return verify_chain(db, self.audit_key, anchor)

    def rows(self, query: str, params=()):
        db = self.connect()
        try:
            return [dict(row) for row in db.execute(query, params)]
        finally:
            db.close()


def verify_chain(db, audit_key, anchor=None):
    previous, count = "0" * 64, 0
    anchor_seen = anchor is None or anchor == {"seq": 0, "hash": previous}
    try:
        for row in db.execute("SELECT * FROM audit ORDER BY seq"):
            count += 1
            expected = hmac.new(audit_key, (previous + row["event"]).encode(), hashlib.sha256).hexdigest()
            if row["seq"] != count or row["previous"] != previous or not hmac.compare_digest(row["hash"], expected):
                raise BridgeError("audit_integrity_failure", 503)
            if json.loads(row["event"])["tenant"] != row["tenant"]:
                raise BridgeError("audit_integrity_failure", 503)
            previous = expected
            if anchor and row["seq"] == anchor.get("seq") and expected == anchor.get("hash"):
                anchor_seen = True
        if not anchor_seen:
            raise BridgeError("audit_anchor_missing", 503)
        return {"seq": count, "hash": previous}
    except (KeyError, TypeError, ValueError):
        raise BridgeError("audit_integrity_failure", 503) from None

