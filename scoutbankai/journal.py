"""Balanced reservation journal. The connected bank remains the money ledger."""
from .crypto import canonical, digest
from .errors import BridgeError

SCHEMA = """
CREATE TABLE IF NOT EXISTS journal(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 tenant TEXT NOT NULL, payment TEXT NOT NULL REFERENCES payments(id),
 kind TEXT NOT NULL CHECK(kind IN ('reserve','release','settle')),
 account TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0), currency TEXT NOT NULL,
 debit TEXT NOT NULL, credit TEXT NOT NULL, created INTEGER NOT NULL,
 CHECK(debit<>credit), UNIQUE(payment,kind));
CREATE INDEX IF NOT EXISTS journal_tenant ON journal(tenant,seq);
CREATE TRIGGER IF NOT EXISTS journal_no_update BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS journal_no_delete BEFORE DELETE ON journal BEGIN SELECT RAISE(ABORT,'append only'); END;
"""
BUCKETS = {"reserve": ("delegated_available", "payment_held"),
           "release": ("payment_held", "delegated_available"),
           "settle": ("payment_held", "bank_settled")}
LIVE = {"screening", "review", "queued", "dispatching", "submitted", "unknown"}


def record(db, row, kind, now):
    debit, credit = BUCKETS[kind]
    db.execute("INSERT INTO journal(tenant,payment,kind,account,amount,currency,debit,credit,created) VALUES(?,?,?,?,?,?,?,?,?)",
               (row["tenant"], row["id"], kind, row["account"], row["amount"], row["currency"], debit, credit, now))


def verify_payment(db, row):
    payload = {"mandate_id": row["mandate"], "payee_id": row["payee"], "amount_minor": row["amount"],
               "currency": row["currency"], "reference": row["reference"]}
    if digest(canonical(payload)) != row["request_hash"]:
        raise BridgeError("financial_integrity_failure", 503)
    expected = {"reserve"}
    if row["status"] == "settled":
        expected.add("settle")
    elif row["status"] in {"cancelled", "rejected"}:
        expected.add("release")
    elif row["status"] not in LIVE:
        raise BridgeError("financial_integrity_failure", 503)
    entries = db.execute("SELECT * FROM journal WHERE payment=?", (row["id"],)).fetchall()
    if {entry["kind"] for entry in entries} != expected or len(entries) != len(expected):
        raise BridgeError("financial_integrity_failure", 503)
    for entry in entries:
        if (any(entry[k] != row[k] for k in ("tenant", "account", "amount", "currency"))
                or (entry["debit"], entry["credit"]) != BUCKETS[entry["kind"]]):
            raise BridgeError("financial_integrity_failure", 503)


def verify_financial_state(db, tenant=None):
    import json
    query, args = (" WHERE tenant=?", (tenant,)) if tenant is not None else ("", ())
    count = 0
    for row in db.execute("SELECT * FROM payments" + query, args):
        verify_payment(db, row)
        count += 1
    for mandate in db.execute("SELECT * FROM mandates" + query, args):
        spent = db.execute("SELECT COALESCE(sum(amount),0) FROM payments WHERE mandate=? AND status NOT IN ('cancelled','rejected')", (mandate["id"],)).fetchone()[0]
        if mandate["budget_remaining"] + spent != json.loads(mandate["policy"])["budget_minor"]:
            raise BridgeError("financial_integrity_failure", 503)
    if db.execute("PRAGMA foreign_key_check").fetchone():
        raise BridgeError("financial_integrity_failure", 503)
    return {"integrity": "verified", "payments_checked": count,
            "scope": "delegated_reservations", "customer_balances": "held_by_connected_bank"}
