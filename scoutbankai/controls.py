"""Deterministic account controls and two-person control changes."""
import json
import secrets

from .crypto import canonical, digest
from .errors import BridgeError
from .models import AccountLimits, ControlProposal

SCHEMA = """
CREATE TABLE IF NOT EXISTS account_controls(
 tenant TEXT NOT NULL, account TEXT NOT NULL, policy TEXT, version INTEGER NOT NULL DEFAULT 0,
 frozen INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant,account),
 FOREIGN KEY(tenant,account) REFERENCES accounts(tenant,id));
CREATE TABLE IF NOT EXISTS tenant_controls(tenant TEXT PRIMARY KEY REFERENCES tenants(id), version INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS control_changes(
 id TEXT PRIMARY KEY, tenant TEXT NOT NULL, payload TEXT NOT NULL, request_hash TEXT NOT NULL,
 proposer TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', reviewed_by TEXT);
CREATE INDEX IF NOT EXISTS control_changes_tenant ON control_changes(tenant,created DESC);
CREATE INDEX IF NOT EXISTS payments_account ON payments(tenant,account,created);
"""


class Controls:
    def __init__(self, service):
        self.service, self.store = service, service.store

    def require(self, actor, role):
        if actor.role != role:
            raise BridgeError("role_not_permitted", 403)
        if self.service.settings.mode == "integrated" and actor.actor_type != "human":
            raise BridgeError("bank_attested_human_required", 403)

    def account(self, db, tenant, account):
        if not db.execute("SELECT 1 FROM accounts WHERE tenant=? AND id=?", (tenant, account)).fetchone():
            raise BridgeError("account_not_found", 404)
        db.execute("INSERT OR IGNORE INTO account_controls(tenant,account) VALUES(?,?)", (tenant, account))
        return db.execute("SELECT * FROM account_controls WHERE tenant=? AND account=?", (tenant, account)).fetchone()

    def check(self, db, tenant, account, amount, *, dispatch=False, created=None):
        row = self.account(db, tenant, account)
        if row["frozen"]:
            raise BridgeError("account_frozen", 423)
        if row["policy"] is None:
            if self.service.settings.mode == "integrated":
                raise BridgeError("account_limits_required", 403)
            return False
        policy = AccountLimits(**json.loads(row["policy"]))
        if dispatch and (created is None or not 0 <= self.service.clock() - created <= policy.max_request_age_seconds):
            raise BridgeError("payment_request_expired", 403)
        totals = db.execute("""SELECT
          COALESCE(sum(CASE WHEN created>? AND status NOT IN ('cancelled','rejected') THEN amount ELSE 0 END),0) AS daily,
          COALESCE(sum(CASE WHEN status IN ('screening','review','queued','dispatching','submitted','unknown') THEN amount ELSE 0 END),0) AS pending,
          COALESCE(sum(CASE WHEN created>? THEN 1 ELSE 0 END),0) AS velocity
          FROM payments WHERE tenant=? AND account=?""",
          (self.service.clock() - 86400, self.service.clock() - 60, tenant, account)).fetchone()
        added = 0 if dispatch else amount
        for exceeded, code in (
            (amount > policy.per_payment_minor, "account_payment_limit_exceeded"),
            (totals["daily"] + added > policy.rolling_day_minor, "account_daily_limit_exceeded"),
            (totals["pending"] + added > policy.max_pending_minor, "account_pending_limit_exceeded"),
            (not dispatch and totals["velocity"] >= policy.max_payments_per_minute, "account_velocity_limit_exceeded"),
        ):
            if exceeded:
                raise BridgeError(code, 403)
        return policy.require_review

    def propose(self, actor, model):
        self.require(actor, "operator")
        with self.store.transaction() as db:
            if model.action == "resume_bank":
                db.execute("INSERT OR IGNORE INTO tenant_controls(tenant) VALUES(?)", (actor.tenant,))
                version = db.execute("SELECT version FROM tenant_controls WHERE tenant=?", (actor.tenant,)).fetchone()[0]
            else:
                version = self.account(db, actor.tenant, model.account_id)["version"]
                if model.action == "account_limits":
                    # Legacy releases allowed duplicate aliases. Do not activate account
                    # policies over ambiguous upstream identities after an upgrade.
                    seen = set()
                    for account in db.execute("SELECT id,bank_id FROM accounts WHERE tenant=?", (actor.tenant,)):
                        bank_id = self.service.vault.open(account["bank_id"], actor.tenant, "accounts", account["id"])
                        if bank_id in seen:
                            raise BridgeError("duplicate_bank_account_aliases", 409)
                        seen.add(bank_id)
            return self._record_proposal(db, actor, model, version)

    def _record_proposal(self, db, actor, model, version, restores=None):
        now, identifier = self.service.clock(), "chg_" + secrets.token_hex(12)
        payload = {**model.model_dump(), "tenant": actor.tenant, "expected_version": version,
                   "proposer": actor.subject, "created_at": now, "expires_at": now + 900}
        if restores:
            payload["restores_change_id"] = restores
        request_hash = digest(canonical(payload))
        db.execute("INSERT INTO control_changes(id,tenant,payload,request_hash,proposer,created,expires) VALUES(?,?,?,?,?,?,?)",
                   (identifier, actor.tenant, canonical(payload).decode(), request_hash, actor.subject, now, now + 900))
        self.store.event(db, actor.tenant, "control_change_proposed", actor.subject, now,
                         change_id=identifier, request_hash=request_hash, action_type=model.action,
                         account_id=model.account_id, reason=model.reason, restores_change_id=restores,
                         proposed_limits=model.limits.model_dump() if model.limits else None,
                         before_state=self._state(db, actor.tenant, payload))
        return {"id": identifier, "request_hash": request_hash, "status": "pending", "proposal": payload}

    def _state(self, db, tenant, payload):
        if payload["action"] == "resume_bank":
            return {"paused": bool(db.execute("SELECT paused FROM tenants WHERE id=?", (tenant,)).fetchone()[0]),
                    "version": db.execute("SELECT version FROM tenant_controls WHERE tenant=?", (tenant,)).fetchone()[0]}
        row = self.account(db, tenant, payload["account_id"])
        return {"limits": json.loads(row["policy"]) if row["policy"] else None,
                "frozen": bool(row["frozen"]), "version": row["version"],
                "currency": db.execute("SELECT currency FROM accounts WHERE tenant=? AND id=?", (tenant, payload["account_id"])).fetchone()[0]}

    def restore(self, actor, identifier, model):
        self.require(actor, "operator")
        with self.store.transaction() as db:
            source = db.execute("SELECT * FROM control_changes WHERE id=? AND tenant=?", (identifier, actor.tenant)).fetchone()
            if not source:
                raise BridgeError("control_change_not_found", 404)
            payload = json.loads(source["payload"])
            if (source["status"] != "approved" or source["request_hash"] != model.source_hash
                    or digest(canonical(payload)) != model.source_hash or payload["action"] != "account_limits"):
                raise BridgeError("control_restore_source_invalid", 409)
            account = self.account(db, actor.tenant, payload["account_id"])
            if account["version"] != model.expected_version:
                raise BridgeError("control_version_changed", 409)
            limits = AccountLimits(**payload["limits"])
            if account["policy"] and json.loads(account["policy"]) == limits.model_dump():
                raise BridgeError("control_limits_already_current", 409)
            proposal = ControlProposal(action="account_limits", account_id=payload["account_id"], limits=limits, reason=model.reason)
            return self._record_proposal(db, actor, proposal, account["version"], restores=identifier)

    def review(self, actor, identifier, model):
        self.require(actor, "reviewer")
        now = self.service.clock()
        with self.store.transaction() as db:
            change = db.execute("SELECT * FROM control_changes WHERE id=? AND tenant=?", (identifier, actor.tenant)).fetchone()
            if not change:
                raise BridgeError("control_change_not_found", 404)
            if change["proposer"] == actor.subject:
                raise BridgeError("independent_reviewer_required", 403)
            payload = json.loads(change["payload"])
            if (change["status"] != "pending" or change["expires"] <= now or change["request_hash"] != model.request_hash
                    or digest(canonical(payload)) != model.request_hash):
                raise BridgeError("control_change_state_changed", 409)
            before_state = self._state(db, actor.tenant, payload)
            if model.decision == "approve":
                if payload["action"] == "resume_bank":
                    changed = db.execute("UPDATE tenant_controls SET version=version+1 WHERE tenant=? AND version=?",
                                         (actor.tenant, payload["expected_version"])).rowcount
                    if changed:
                        db.execute("UPDATE tenants SET paused=0 WHERE id=?", (actor.tenant,))
                else:
                    row = self.account(db, actor.tenant, payload["account_id"])
                    changed = row["version"] == payload["expected_version"]
                    if changed:
                        if payload["action"] == "account_limits":
                            policy = canonical(AccountLimits(**payload["limits"]).model_dump()).decode()
                            db.execute("UPDATE account_controls SET policy=?,version=version+1 WHERE tenant=? AND account=?",
                                       (policy, actor.tenant, payload["account_id"]))
                        else:
                            db.execute("UPDATE account_controls SET frozen=0,version=version+1 WHERE tenant=? AND account=?",
                                       (actor.tenant, payload["account_id"]))
                if not changed:
                    raise BridgeError("control_version_changed", 409)
            status = "approved" if model.decision == "approve" else "rejected"
            db.execute("UPDATE control_changes SET status=?,reviewed_by=? WHERE id=?", (status, actor.subject, identifier))
            self.store.event(db, actor.tenant, "control_change_" + status, actor.subject, now,
                             change_id=identifier, request_hash=model.request_hash, action_type=payload["action"],
                             account_id=payload["account_id"], reason=payload["reason"],
                             restores_change_id=payload.get("restores_change_id"),
                             before_state=before_state, after_state=self._state(db, actor.tenant, payload))
        return {"id": identifier, "status": status, "reviewed_by": actor.subject}

    def freeze(self, actor, account):
        self.require(actor, "operator")
        with self.store.transaction() as db:
            self.account(db, actor.tenant, account)
            db.execute("UPDATE account_controls SET frozen=1,version=version+1 WHERE tenant=? AND account=?", (actor.tenant, account))
            for row in db.execute("SELECT * FROM payments WHERE tenant=? AND account=? AND status IN ('screening','review','queued')", (actor.tenant, account)).fetchall():
                self.service.cancel(db, row, "account_frozen", actor.subject)
            self.store.event(db, actor.tenant, "account_frozen", actor.subject, self.service.clock(), account_id=account)
        return {"account_id": account, "frozen": True, "in_flight_payments": "reconcile_with_bank"}

    def overview(self, actor):
        accounts = self.store.rows("SELECT c.tenant,c.account,c.policy,c.version,c.frozen,a.currency FROM account_controls c JOIN accounts a ON a.tenant=c.tenant AND a.id=c.account WHERE c.tenant=? ORDER BY c.account LIMIT 200", (actor.tenant,))
        changes = self.store.rows("SELECT * FROM control_changes WHERE tenant=? ORDER BY created DESC,id LIMIT 100", (actor.tenant,))
        return {"accounts": [{**r, "policy": json.loads(r["policy"]) if r["policy"] else None} for r in accounts],
                "changes": [{**r, "payload": json.loads(r["payload"])} for r in changes],
                "limits": {"accounts": 200, "changes": 100}}

    def account_detail(self, actor, account):
        rows = self.store.rows("SELECT c.account,c.policy,c.version,c.frozen,a.currency FROM account_controls c JOIN accounts a ON a.tenant=c.tenant AND a.id=c.account WHERE c.tenant=? AND c.account=?", (actor.tenant, account))
        if not rows:
            raise BridgeError("account_not_found", 404)
        row = rows[0]
        return {**row, "policy": json.loads(row["policy"]) if row["policy"] else None}

    def change_detail(self, actor, identifier):
        rows = self.store.rows("SELECT * FROM control_changes WHERE tenant=? AND id=?", (actor.tenant, identifier))
        if not rows:
            raise BridgeError("control_change_not_found", 404)
        row = rows[0]
        payload = json.loads(row["payload"])
        if digest(canonical(payload)) != row["request_hash"]:
            raise BridgeError("control_change_integrity_failure", 503)
        return {**row, "payload": payload}
