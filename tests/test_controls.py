import json
import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest

from scoutbankai.auth import Principal
from scoutbankai.bootstrap import sample_authority, submit_sample
from scoutbankai.connectors import MemoryBank
from scoutbankai.crypto import canonical, new_key, proof
from scoutbankai.errors import BridgeError
from scoutbankai.models import Advisory, MandateRequest, PaymentRequest
from scoutbankai.worker import Worker

from conftest import bearer, post_payment, request_payment


def test_valid_payment_is_queued_then_settled(env):
    response = post_payment(env)
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "queued"
    bank = MemoryBank()
    Worker(env["service"], bank).dispatch_one()
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "settled"
    assert bank.submissions == 1


@pytest.mark.parametrize("changes,amount,code", [
    ({"payee_id": "unapproved"}, 5000, "payee_not_permitted"),
    ({"currency": "USD"}, 5000, "currency_not_permitted"),
    ({"mandate_id": "another_mandate"}, 5000, "wrong_mandate"),
    ({}, 50001, "payment_limit_exceeded"),
])
def test_policy_denials_are_audited_and_do_not_reserve(env, changes, amount, code):
    response = post_payment(env, amount=amount, changes=changes)
    assert response.status_code == 403
    assert response.json()["error"] == code
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 100000
    assert env["service"].store.rows("SELECT event FROM audit ORDER BY seq DESC LIMIT 1")[0]["event"].find("payment_denied") >= 0


@pytest.mark.parametrize("amount", [0, -1, 1.1, True, "100", 10**30])
def test_money_requires_positive_bounded_integer(env, amount):
    assert post_payment(env, amount=amount).status_code == 422


@pytest.mark.parametrize("mutation", ["key", "method", "url", "body", "idempotency", "old", "future", "nonce"])
def test_proof_binds_request_and_freshness(env, mutation):
    now = env["service"].clock()
    override = {"method": {"method": "GET"}, "url": {"url": "https://elsewhere.example/v1/payments"},
                "body": {"body": b"{}"}, "idempotency": {"idempotency_key": "other-idempotency-123"},
                "old": {"now": now - 61}, "future": {"now": now + 61}, "nonce": {"nonce": "forged"}}
    response = post_payment(env, key=new_key() if mutation == "key" else None, claims=override.get(mutation))
    assert response.status_code == 401, response.text
    assert not env["service"].store.rows("SELECT * FROM payments")


def test_same_proof_cannot_replay(env):
    raw, headers = request_payment(env)
    assert env["client"].post("/v1/payments", content=raw, headers=headers).status_code == 202
    response = env["client"].post("/v1/payments", content=raw, headers=headers)
    assert response.json()["error"] == "replayed_proof"


def test_fresh_proof_same_idempotency_returns_same_payment(env):
    idem = secrets.token_urlsafe(24)
    first = post_payment(env, idem=idem).json()
    second = post_payment(env, idem=idem).json()
    assert first["id"] == second["id"]
    assert len(env["service"].store.rows("SELECT * FROM payments")) == 1


def test_idempotency_cannot_change_amount(env):
    idem = secrets.token_urlsafe(24)
    post_payment(env, idem=idem)
    response = post_payment(env, idem=idem, amount=5001)
    assert response.status_code == 409
    assert response.json()["error"] == "idempotency_conflict"


def test_customer_login_cannot_impersonate_agent(env):
    raw, _ = request_payment(env)
    response = env["client"].post("/v1/payments", content=raw, headers={**bearer(env, "customer"), "Content-Type": "application/json"})
    assert response.status_code == 401
    assert response.json()["error"] == "agent_identity_required"


def test_multiple_agents_cannot_spend_same_budget_concurrently(env):
    service, authority = env["service"], env["a"]
    def attempt(_):
        try:
            return submit_sample(service, authority, amount=10000)["id"]
        except BridgeError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(attempt, range(20)))
    assert sum(x.startswith("pay_") for x in results) == 10
    assert results.count("budget_exceeded") == 10
    assert service.store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 0


def test_concurrent_same_idempotency_charges_once(env):
    idem = secrets.token_urlsafe(24)
    with ThreadPoolExecutor(max_workers=8) as pool:
        payments = list(pool.map(lambda _: submit_sample(env["service"], env["a"], idempotency=idem), range(8)))
    assert len({p["id"] for p in payments}) == 1
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 95000


def test_customer_cannot_grant_another_customers_account(env):
    service, a = env["service"], env["a"]
    policy = json.loads(service.store.rows("SELECT policy FROM mandates")[0]["policy"])
    with pytest.raises(BridgeError, match="account_or_agent_not_available"):
        service.create_mandate(Principal(a["customer"].tenant, "other-customer", "customer"), MandateRequest(**policy))


def test_tenant_separation(env):
    other = Principal("other-bank", "reviewer-other", "reviewer")
    with env["service"].store.transaction() as db:
        db.execute("INSERT INTO tenants VALUES('other-bank',0)")
    post_payment(env)
    overview = env["service"].overview(other)
    assert overview["payments"] == overview["agents"] == overview["mandates"] == overview["audit"] == []


def test_review_requires_separate_role_and_exact_hash(env):
    p = post_payment(env, amount=25000).json()
    assert p["status"] == "review"
    endpoint = "/v1/payments/" + p["id"] + "/review"
    data = {"decision": "approve", "request_hash": p["request_hash"]}
    assert env["client"].post(endpoint, json=data, headers=bearer(env, "operator")).status_code == 403
    assert env["client"].post(endpoint, json={**data, "request_hash": "0" * 64}, headers=bearer(env, "reviewer")).status_code == 409
    response = env["client"].post(endpoint, json=data, headers=bearer(env, "reviewer"))
    assert response.json()["status"] == "queued"
    assert response.json()["reviewed_by"] == "reviewer-sample"


def test_rejection_refunds_once(env):
    p = post_payment(env, amount=25000).json()
    endpoint = "/v1/payments/" + p["id"] + "/review"
    data = {"decision": "reject", "request_hash": p["request_hash"]}
    assert env["client"].post(endpoint, json=data, headers=bearer(env, "reviewer")).status_code == 200
    assert env["client"].post(endpoint, json=data, headers=bearer(env, "reviewer")).status_code == 409
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 100000


def test_revocation_cancels_pending_and_blocks_token(env):
    post_payment(env)
    raw, headers = request_payment(env)
    endpoint = "/v1/mandates/" + env["a"]["mandate"] + "/revoke"
    assert env["client"].post(endpoint, headers=bearer(env, "customer")).status_code == 200
    assert env["client"].post("/v1/payments", content=raw, headers=headers).status_code == 401
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "cancelled"
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 100000


def test_pause_blocks_dispatch_and_new_requests(env):
    post_payment(env)
    env["client"].post("/v1/pause", json={"paused": True}, headers=bearer(env, "operator"))
    bank = MemoryBank()
    assert Worker(env["service"], bank).dispatch_one() is None
    assert post_payment(env).status_code == 423
    assert bank.submissions == 0


def test_suspension_cancels_queued(env):
    post_payment(env)
    env["client"].post("/v1/agents/" + env["a"]["agent"] + "/suspend", headers=bearer(env, "operator"))
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "cancelled"


def test_supervisor_cannot_override_hard_limit(env):
    class Unwise:
        name = "test"
        calls = 0
        def assess(self, context):
            self.calls += 1
            return Advisory(require_review=False, reason="routine")
    supervisor = Unwise()
    env["service"].supervisor = supervisor
    assert post_payment(env, amount=60000).status_code == 403
    assert supervisor.calls == 0
    assert post_payment(env, amount=25000).json()["status"] == "review"


def test_supervisor_failure_holds_payment(env):
    class Failed:
        name = "failed"
        def assess(self, context):
            raise TimeoutError()
    env["service"].supervisor = Failed()
    p = post_payment(env).json()
    assert p["status"] == "review" and p["reason"] == "provider_unavailable"


def test_revoke_during_supervision_cannot_requeue(env):
    class Revoker:
        name = "test"
        def assess(self, context):
            env["service"].revoke(env["a"]["customer"], env["a"]["mandate"])
            return Advisory(require_review=False, reason="routine")
    env["service"].supervisor = Revoker()
    assert post_payment(env).json()["status"] == "cancelled"


def test_read_payment_requires_same_agent_and_scope(env):
    p = post_payment(env).json()
    service, a = env["service"], env["a"]
    path = "/v1/payments/" + p["id"]
    signed = proof(a["key"], a["token"], "GET", service.settings.origin + path, b"", service.nonce(a["token"]))
    response = env["client"].get(path, headers={"Authorization": "DPoP " + a["token"], "DPoP": signed})
    assert response.status_code == 200
    other = sample_authority(service, env["credentials"])
    signed = proof(other["key"], other["token"], "GET", service.settings.origin + path, b"", service.nonce(other["token"]))
    assert env["client"].get(path, headers={"Authorization": "DPoP " + other["token"], "DPoP": signed}).status_code == 404

