import json
import re
import secrets
import sqlite3
import time

from .auth import Authenticator
from .crypto import canonical, digest, make_nonce, thumbprint, verify_proof
from .errors import BridgeError
from .models import Advisory
from .store import Store
from .supervisor import OpenAISupervisor, RuleSupervisor
from .controls import Controls
from .journal import record, verify_payment
from .vault import Vault

PENDING = ("screening", "review", "queued")


class Service:
    def __init__(self, settings, supervisor=None, clock=None):
        self.settings = settings.validate()
        self.clock = clock or (lambda: int(time.time()))
        self.store = Store(settings.database, settings.audit_key)
        self.auth = Authenticator(settings, self.store, self.clock)
        self.controls = Controls(self)
        self.vault = Vault(settings.vault_keyring_file, allow_plaintext=settings.mode == "development")
        cfg = settings.supervisor
        self.supervisor = supervisor or (OpenAISupervisor(cfg.get("model", ""), cfg.get("token_env", "OPENAI_API_KEY"))
                                         if cfg.get("mode") == "openai" else RuleSupervisor())

    def register_agent(self, principal, model):
        key_hash = thumbprint(model.public_jwk)
        agent_id = "agt_" + secrets.token_hex(12)
        with self.store.transaction() as db:
            db.execute("INSERT INTO agents(id,tenant,owner,name,thumbprint,jwk) VALUES(?,?,?,?,?,?)",
                       (agent_id, principal.tenant, model.owner, model.name, key_hash, canonical(model.public_jwk).decode()))
            self.store.event(db, principal.tenant, "agent_registered", principal.subject, self.clock(), agent_id=agent_id, key_thumbprint=key_hash)
        return {"id": agent_id, "key_thumbprint": key_hash, "identity": "registered_agent"}

    def register_account(self, principal, model):
        with self.store.transaction() as db:
            for existing in db.execute("SELECT id,bank_id FROM accounts WHERE tenant=?", (principal.tenant,)):
                if self.vault.open(existing["bank_id"], principal.tenant, "accounts", existing["id"]) == model.bank_id:
                    raise BridgeError("bank_account_already_registered", 409)
            bank_id = self.vault.seal(model.bank_id, principal.tenant, "accounts", model.id)
            try:
                db.execute("INSERT INTO accounts VALUES(?,?,?,?,?)", (model.id, principal.tenant, model.customer, bank_id, model.currency))
            except sqlite3.IntegrityError:
                raise BridgeError("account_already_registered", 409) from None
            self.store.event(db, principal.tenant, "account_registered", principal.subject, self.clock(), account_id=model.id)
            self.controls.account(db, principal.tenant, model.id)
        return {"id": model.id}

    def register_payee(self, principal, model):
        with self.store.transaction() as db:
            bank_id = self.vault.seal(model.bank_id, principal.tenant, "payees", model.id)
            try:
                db.execute("INSERT INTO payees VALUES(?,?,?,?)", (model.id, principal.tenant, bank_id, model.label))
            except sqlite3.IntegrityError:
                raise BridgeError("payee_already_registered", 409) from None
            self.store.event(db, principal.tenant, "payee_registered", principal.subject, self.clock(), payee_id=model.id)
        return {"id": model.id}

    def create_mandate(self, principal, model):
        now, mandate_id = self.clock(), "mnd_" + secrets.token_hex(12)
        if not now < model.expires_at <= now + 86400 * 30:
            raise BridgeError("invalid_mandate_expiry")
        if self.settings.mode == "integrated":
            if (principal.consent_hash != digest(canonical(model.model_dump()))
                    or principal.consent_time is None or not -10 <= now - principal.consent_time <= 300
                    or not principal.consent_id):
                raise BridgeError("bank_consent_receipt_required", 403)
        with self.store.transaction() as db:
            if self.settings.mode == "integrated":
                receipt_hash = digest(principal.tenant + ":" + principal.subject + ":" + principal.consent_id)
                try:
                    db.execute("INSERT INTO consent_receipts VALUES(?,?)", (receipt_hash, mandate_id))
                except sqlite3.IntegrityError:
                    raise BridgeError("consent_receipt_already_used", 409) from None
            account = db.execute("SELECT * FROM accounts WHERE tenant=? AND id=? AND customer=?", (principal.tenant, model.account_id, principal.subject)).fetchone()
            agent = db.execute("SELECT id FROM agents WHERE tenant=? AND id=? AND active=1", (principal.tenant, model.agent_id)).fetchone()
            if not account or not agent:
                raise BridgeError("account_or_agent_not_available", 403)
            if account["currency"] != model.currency:
                raise BridgeError("currency_mismatch")
            for payee in model.payees:
                if not db.execute("SELECT id FROM payees WHERE tenant=? AND id=?", (principal.tenant, payee)).fetchone():
                    raise BridgeError("unregistered_payee")
            db.execute("INSERT INTO mandates(id,tenant,customer,agent,account,policy,budget_remaining,expires) VALUES(?,?,?,?,?,?,?,?)",
                       (mandate_id, principal.tenant, principal.subject, model.agent_id, model.account_id,
                        canonical(model.model_dump()).decode(), model.budget_minor, model.expires_at))
            self.store.event(db, principal.tenant, "mandate_granted", principal.subject, now, mandate_id=mandate_id,
                             agent_id=model.agent_id, policy=model.model_dump())
        return {"id": mandate_id, "status": "active", "expires_at": model.expires_at}

    def mint_token(self, principal, mandate_id):
        now, token = self.clock(), secrets.token_urlsafe(48)
        with self.store.transaction() as db:
            mandate = db.execute("SELECT * FROM mandates WHERE id=? AND tenant=? AND customer=? AND revoked=0 AND expires>?",
                                 (mandate_id, principal.tenant, principal.subject, now)).fetchone()
            if not mandate or not db.execute("SELECT id FROM agents WHERE id=? AND active=1", (mandate["agent"],)).fetchone():
                raise BridgeError("mandate_not_available", 403)
            expiry = min(now + 900, mandate["expires"])
            db.execute("INSERT INTO tokens VALUES(?,?,?,?,?)", (digest(token), principal.tenant, mandate["agent"], mandate_id, expiry))
            self.store.event(db, principal.tenant, "agent_token_issued", principal.subject, now, mandate_id=mandate_id, expires_at=expiry)
        return {"access_token": token, "token_type": "DPoP", "expires_at": expiry}

    def _live_token(self, db, token):
        if not token or len(token) > 128:
            raise BridgeError("invalid_agent_token", 401)
        row = db.execute("SELECT t.*,a.thumbprint,m.policy,m.budget_remaining FROM tokens t JOIN agents a ON a.id=t.agent JOIN mandates m ON m.id=t.mandate WHERE t.hash=? AND t.expires>? AND a.active=1 AND m.revoked=0 AND m.expires>?",
                         (digest(token), self.clock(), self.clock())).fetchone()
        if not row:
            raise BridgeError("invalid_agent_token", 401)
        return row

    def nonce(self, token):
        with self.store.transaction() as db:
            self._live_token(db, token)
        return make_nonce(self.settings.nonce_key, token, self.clock())

    def _verified(self, db, token, encoded_proof, method, path, raw, idempotency=""):
        row = self._live_token(db, token)
        proof_hash = verify_proof(encoded_proof, token, row["thumbprint"], method, self.settings.origin + path,
                                  raw, idempotency, self.settings.nonce_key, self.clock())
        db.execute("DELETE FROM proofs WHERE expires<?", (self.clock(),))
        try:
            db.execute("INSERT INTO proofs VALUES(?,?)", (proof_hash, self.clock() + 120))
        except sqlite3.IntegrityError:
            raise BridgeError("replayed_proof", 401) from None
        return row

    def create_payment(self, token, encoded_proof, raw, idempotency, model):
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", idempotency):
            raise BridgeError("invalid_idempotency_key")
        now, payment_id, failure, cached = self.clock(), "pay_" + secrets.token_hex(12), None, None
        request_hash = digest(canonical(model.model_dump()))
        with self.store.transaction() as db:
            actor = self._verified(db, token, encoded_proof, "POST", "/v1/payments", raw, idempotency)
            policy = json.loads(actor["policy"])
            try:
                if actor["mandate"] != model.mandate_id:
                    raise BridgeError("wrong_mandate", 403)
                if "payments:create" not in policy["permissions"]:
                    raise BridgeError("scope_not_permitted", 403)
                existing = db.execute("SELECT * FROM payments WHERE tenant=? AND agent=? AND idempotency=?",
                                      (actor["tenant"], actor["agent"], idempotency)).fetchone()
                if existing:
                    if existing["request_hash"] != request_hash:
                        raise BridgeError("idempotency_conflict", 409)
                    cached = self.public_payment(existing)
                else:
                    if db.execute("SELECT paused FROM tenants WHERE id=?", (actor["tenant"],)).fetchone()[0]:
                        raise BridgeError("bank_paused", 423)
                    if model.currency != policy["currency"]:
                        raise BridgeError("currency_not_permitted", 403)
                    if model.payee_id not in policy["payees"]:
                        raise BridgeError("payee_not_permitted", 403)
                    if model.amount_minor > policy["per_payment_minor"]:
                        raise BridgeError("payment_limit_exceeded", 403)
                    count = db.execute("SELECT count(*) FROM payments WHERE mandate=? AND created>?", (model.mandate_id, now - 60)).fetchone()[0]
                    if count >= policy["max_payments_per_minute"]:
                        raise BridgeError("velocity_limit_exceeded", 429)
                    account_review = self.controls.check(db, actor["tenant"], policy["account_id"], model.amount_minor)
                    changed = db.execute("UPDATE mandates SET budget_remaining=budget_remaining-? WHERE id=? AND budget_remaining>=?",
                                         (model.amount_minor, model.mandate_id, model.amount_minor)).rowcount
                    if not changed:
                        raise BridgeError("budget_exceeded", 403)
                    db.execute("INSERT INTO payments(id,tenant,agent,mandate,account,payee,amount,currency,reference,idempotency,request_hash,status,reason,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (payment_id, actor["tenant"], actor["agent"], model.mandate_id, policy["account_id"], model.payee_id,
                                model.amount_minor, model.currency, model.reference, idempotency, request_hash, "screening", "supervision_pending", now, now))
                    record(db, db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone(), "reserve", now)
                    self.store.event(db, actor["tenant"], "payment_reserved", actor["agent"], now,
                                     payment_id=payment_id, request_hash=request_hash, amount_minor=model.amount_minor)
            except BridgeError as exc:
                failure = exc
                self.store.event(db, actor["tenant"], "payment_denied", actor["agent"], now, reason=exc.code, request_hash=request_hash)
        if failure:
            raise failure
        if cached:
            return cached
        context = {"amount_minor": model.amount_minor, "currency": model.currency,
                   "review_above_minor": policy["review_above_minor"], "payments_last_minute": count,
                   "remaining_budget_minor": actor["budget_remaining"] - model.amount_minor}
        try:
            advice = self.supervisor.assess(context)
            if not isinstance(advice, Advisory):
                raise ValueError("invalid advice")
        except Exception:
            advice = Advisory(require_review=True, reason="provider_unavailable")
        with self.store.transaction() as db:
            payment = db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
            if payment["status"] == "screening":
                mandate = db.execute("SELECT * FROM mandates WHERE id=?", (model.mandate_id,)).fetchone()
                if mandate["revoked"] or mandate["expires"] <= self.clock():
                    self.cancel(db, payment, "authority_expired", "supervisor")
                else:
                    review = account_review or advice.require_review or model.amount_minor > policy["review_above_minor"]
                    status = "review" if review else "queued"
                    reason = "account_review_required" if account_review else ("threshold_review" if model.amount_minor > policy["review_above_minor"] else advice.reason)
                    db.execute("UPDATE payments SET status=?,reason=?,updated=? WHERE id=?", (status, reason, self.clock(), payment_id))
                    self.store.event(db, actor["tenant"], "supervision_completed", self.supervisor.name, self.clock(),
                                     payment_id=payment_id, status=status, reason=reason)
            return self.public_payment(db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone())

    @staticmethod
    def public_payment(row):
        return {key: row[key] for key in ("id", "mandate", "account", "payee", "amount", "currency", "reference", "request_hash", "status", "reason", "created", "updated", "bank_id", "reviewed_by")}

    def get_agent_payment(self, token, encoded_proof, payment_id):
        with self.store.transaction() as db:
            actor = self._verified(db, token, encoded_proof, "GET", "/v1/payments/" + payment_id, b"")
            if "payments:read" not in json.loads(actor["policy"])["permissions"]:
                raise BridgeError("scope_not_permitted", 403)
            row = db.execute("SELECT * FROM payments WHERE id=? AND tenant=? AND agent=? AND mandate=?",
                             (payment_id, actor["tenant"], actor["agent"], actor["mandate"])).fetchone()
            if not row:
                raise BridgeError("payment_not_found", 404)
            return self.public_payment(row)

    def cancel(self, db, payment, reason, actor):
        if payment["status"] not in PENDING:
            return
        verify_payment(db, payment)
        record(db, payment, "release", self.clock())
        db.execute("UPDATE payments SET status='cancelled',reason=?,updated=? WHERE id=?", (reason, self.clock(), payment["id"]))
        db.execute("UPDATE mandates SET budget_remaining=budget_remaining+? WHERE id=?", (payment["amount"], payment["mandate"]))
        self.store.event(db, payment["tenant"], "payment_cancelled", actor, self.clock(), payment_id=payment["id"], reason=reason)

    def review(self, principal, payment_id, model):
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM payments WHERE id=? AND tenant=?", (payment_id, principal.tenant)).fetchone()
            if not row:
                raise BridgeError("payment_not_found", 404)
            if row["status"] != "review" or row["request_hash"] != model.request_hash:
                raise BridgeError("review_state_changed", 409)
            mandate = db.execute("SELECT * FROM mandates WHERE id=?", (row["mandate"],)).fetchone()
            owner = db.execute("SELECT owner FROM agents WHERE id=?", (row["agent"],)).fetchone()[0]
            if principal.subject in {row["agent"], mandate["customer"], owner}:
                raise BridgeError("independent_reviewer_required", 403)
            if model.decision == "reject" or mandate["revoked"] or mandate["expires"] <= self.clock():
                self.cancel(db, row, "review_rejected" if model.decision == "reject" else "authority_expired", principal.subject)
            else:
                db.execute("UPDATE payments SET status='queued',reason='review_approved',reviewed_by=?,updated=? WHERE id=?",
                           (principal.subject, self.clock(), payment_id))
                self.store.event(db, principal.tenant, "review_approved", principal.subject, self.clock(), payment_id=payment_id, request_hash=model.request_hash)
            return self.public_payment(db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone())

    def revoke(self, principal, mandate_id):
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM mandates WHERE id=? AND tenant=?", (mandate_id, principal.tenant)).fetchone()
            if not row or (principal.role == "customer" and row["customer"] != principal.subject):
                raise BridgeError("mandate_not_found", 404)
            db.execute("UPDATE mandates SET revoked=1 WHERE id=?", (mandate_id,))
            for payment in db.execute("SELECT * FROM payments WHERE mandate=? AND status IN ('screening','review','queued')", (mandate_id,)).fetchall():
                self.cancel(db, payment, "mandate_revoked", principal.subject)
            self.store.event(db, principal.tenant, "mandate_revoked", principal.subject, self.clock(), mandate_id=mandate_id)
        return {"status": "revoked", "in_flight_payments": "reconcile_with_bank"}

    def suspend(self, principal, agent_id):
        with self.store.transaction() as db:
            changed = db.execute("UPDATE agents SET active=0 WHERE id=? AND tenant=?", (agent_id, principal.tenant)).rowcount
            if not changed:
                raise BridgeError("agent_not_found", 404)
            for payment in db.execute("SELECT * FROM payments WHERE agent=? AND tenant=? AND status IN ('screening','review','queued')", (agent_id, principal.tenant)).fetchall():
                self.cancel(db, payment, "agent_suspended", principal.subject)
            self.store.event(db, principal.tenant, "agent_suspended", principal.subject, self.clock(), agent_id=agent_id)
        return {"status": "suspended"}

    def pause(self, principal, paused):
        if not paused and self.settings.mode == "integrated":
            raise BridgeError("independent_resume_approval_required", 403)
        with self.store.transaction() as db:
            db.execute("INSERT INTO tenant_controls(tenant,version) VALUES(?,1) ON CONFLICT(tenant) DO UPDATE SET version=version+1", (principal.tenant,))
            db.execute("UPDATE tenants SET paused=? WHERE id=?", (int(paused), principal.tenant))
            self.store.event(db, principal.tenant, "bank_paused" if paused else "bank_resumed", principal.subject, self.clock())
        return {"paused": paused}

    def overview(self, principal):
        tenant = principal.tenant
        payments = self.store.rows("SELECT * FROM payments WHERE tenant=? ORDER BY created DESC,id LIMIT 200", (tenant,))
        audit = self.store.rows("SELECT seq,event,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 100", (tenant,))
        mandates = self.store.rows("SELECT id,agent,customer,budget_remaining,expires,revoked FROM mandates WHERE tenant=? ORDER BY rowid DESC LIMIT 200", (tenant,))
        return {"product": "ScoutBankAI", "mode": self.settings.mode, "updated_at": self.clock(),
                "paused": bool(self.store.rows("SELECT paused FROM tenants WHERE id=?", (tenant,))[0]["paused"]),
                "supervisor": self.supervisor.name,
                "agents": self.store.rows("SELECT id,name,owner,active,thumbprint FROM agents WHERE tenant=? ORDER BY rowid DESC LIMIT 200", (tenant,)),
                "payments": [self.public_payment(p) for p in payments], "mandates": mandates,
                "audit": [{"seq": x["seq"], **json.loads(x["event"]), "hash": x["hash"]} for x in audit],
                "limits": {"payments": 200, "audit": 100, "agents": 200, "mandates": 200}}

