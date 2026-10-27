"""Tenant-scoped historical evidence. Reading history never restores authority."""
import hashlib
import hmac
import json
from contextlib import closing

from .errors import BridgeError

OBJECT_FIELDS = ("payment_id", "mandate_id", "agent_id", "account_id", "payee_id", "change_id")


def search(service, actor, query):
    if actor.role not in {"operator", "reviewer", "auditor", "evaluator"}:
        raise BridgeError("role_not_permitted", 403)
    with closing(service.store.connect()) as db:
        # One read snapshot prevents a moving tail during this page.
        db.execute("BEGIN")
        tail = db.execute("SELECT COALESCE(max(seq),0) FROM audit WHERE tenant=?", (actor.tenant,)).fetchone()[0]
        snapshot = min(tail, query.snapshot_seq) if query.snapshot_seq is not None else tail
        clauses, params = ["tenant=?", "seq<=?"], [actor.tenant, snapshot]
        if query.before_seq is not None:
            clauses.append("seq<?"); params.append(query.before_seq)
        for name in ("actor", "action"):
            value = getattr(query, name)
            if value is not None:
                clauses.append(f"json_extract(event,'$.{name}')=?"); params.append(value)
        if query.object_id is not None:
            clauses.append("(" + " OR ".join(f"json_extract(event,'$.{field}')=?" for field in OBJECT_FIELDS) + ")")
            params.extend([query.object_id] * len(OBJECT_FIELDS))
        if query.from_time is not None:
            clauses.append("json_extract(event,'$.time')>=?"); params.append(query.from_time)
        if query.to_time is not None:
            clauses.append("json_extract(event,'$.time')<=?"); params.append(query.to_time)
        params.append(query.limit + 1)
        rows = db.execute("SELECT seq,event,previous,hash FROM audit WHERE " + " AND ".join(clauses) + " ORDER BY seq DESC LIMIT ?", params).fetchall()
        events = []
        for row in rows[:query.limit]:
            signature = hmac.new(service.settings.audit_key, (row["previous"] + row["event"]).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, row["hash"]):
                raise BridgeError("audit_integrity_failure", 503)
            event = json.loads(row["event"])
            if event["tenant"] != actor.tenant:
                raise BridgeError("audit_integrity_failure", 503)
            events.append({"seq": row["seq"], **event, "hash": row["hash"], "previous_hash": row["previous"]})
    return {"events": events, "snapshot_seq": snapshot,
            "next_before_seq": events[-1]["seq"] if len(rows) > query.limit else None,
            "integrity": "returned_event_signatures_verified", "scope": "tenant_history",
            "history_is_read_only": True}
