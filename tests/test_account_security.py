import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import jwt
import pytest

from scoutbankai.auth import Principal
from scoutbankai.bootstrap import submit_sample
from scoutbankai.connectors import MemoryBank
from scoutbankai.crypto import new_key, public_jwk
from scoutbankai.errors import BridgeError
from scoutbankai.models import AccountRegistration, AgentRegistration, ControlProposal, MandateRequest, ReviewRequest
from scoutbankai.worker import Worker

from conftest import bearer, post_payment
from test_security import integrated_auth


def propose(env, **overrides):
    body = {"action": "account_limits", "account_id": env["a"]["account"], "reason": "Bank risk policy update",
            "limits": {"per_payment_minor": 10000, "rolling_day_minor": 15000,
                       "max_pending_minor": 15000, "max_payments_per_minute": 100, "require_review": False}}
    body.update(overrides)
    result = env["client"].post("/v1/control-changes", json=body, headers=bearer(env, "operator"))
    assert result.status_code == 201, result.text
    return result.json()


def approve(env, change, decision="approve"):
    return env["client"].post("/v1/control-changes/" + change["id"] + "/review", headers=bearer(env, "reviewer"),
                              json={"decision": decision, "request_hash": change["request_hash"]})


def test_limits_require_an_independent_identity_and_exact_change(env):
    change = propose(env)
    service, operator = env["service"], env["a"]["operator"]
    model = ReviewRequest(decision="approve", request_hash=change["request_hash"])
    with pytest.raises(BridgeError, match="independent_reviewer_required"):
        service.controls.review(replace(operator, role="reviewer"), change["id"], model)
    bad = env["client"].post(f"/v1/control-changes/{change['id']}/review", headers=bearer(env, "reviewer"),
                              json={"decision": "approve", "request_hash": "0" * 64})
    assert bad.status_code == 409
    assert approve(env, change).status_code == 200
    assert approve(env, change).status_code == 409
    assert post_payment(env, amount=10001).json()["error"] == "account_payment_limit_exceeded"


def test_competing_changes_and_expired_approvals_do_not_overwrite_policy(env):
    first, stale = propose(env), propose(env)
    assert approve(env, first).status_code == 200
    assert approve(env, stale).json()["error"] == "control_version_changed"
    expired = propose(env)
    now = env["service"].clock()
    env["service"].clock = lambda: now + 901
    assert approve(env, expired).json()["error"] == "control_change_state_changed"


def test_rejected_change_has_no_effect(env):
    change = propose(env)
    assert approve(env, change, "reject").json()["status"] == "rejected"
    assert post_payment(env, amount=11000).status_code == 202


@pytest.mark.parametrize("role", ["customer", "auditor", "reviewer"])
def test_non_operator_cannot_change_limits_or_freeze(env, role):
    body = {"action": "resume_bank", "reason": "Not authorised"}
    assert env["client"].post("/v1/control-changes", json=body, headers=bearer(env, role)).status_code == 403
    assert env["client"].post(f"/v1/accounts/{env['a']['account']}/freeze", headers=bearer(env, role)).status_code == 403


def test_cross_tenant_change_review_is_hidden(env):
    change = propose(env)
    with pytest.raises(BridgeError, match="control_change_not_found"):
        env["service"].controls.review(Principal("other-bank", "other", "reviewer"), change["id"],
                                      ReviewRequest(decision="approve", request_hash=change["request_hash"]))


def second_agent(env):
    service, a = env["service"], env["a"]
    key = new_key()
    agent = service.register_agent(a["operator"], AgentRegistration(name="Second agent", owner=a["customer"].subject, public_jwk=public_jwk(key)))
    policy = json.loads(service.store.rows("SELECT policy FROM mandates WHERE id=?", (a["mandate"],))[0]["policy"])
    policy["agent_id"] = agent["id"]
    mandate = service.create_mandate(a["customer"], MandateRequest(**policy))
    token = service.mint_token(a["customer"], mandate["id"])["access_token"]
    return {**a, "key": key, "agent": agent["id"], "mandate": mandate["id"], "token": token}


def test_agents_with_different_grants_share_atomic_account_limits(env):
    assert approve(env, propose(env)).status_code == 200
    other = second_agent(env)
    def submit(i):
        try:
            return submit_sample(env["service"], env["a"] if i % 2 else other, amount=5000)["status"]
        except BridgeError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(submit, range(12)))
    assert results.count("queued") == 3
    assert results.count("account_daily_limit_exceeded") == 9
    assert env["service"].store.rows("SELECT sum(amount) AS total FROM payments")[0]["total"] == 15000


def test_settlement_still_consumes_rolling_daily_limit(env):
    approve(env, propose(env))
    assert post_payment(env, amount=10000).status_code == 202
    Worker(env["service"], MemoryBank()).dispatch_one()
    assert post_payment(env, amount=10000).json()["error"] == "account_daily_limit_exceeded"


def test_aged_unknown_payments_still_consume_outstanding_limit(env):
    approve(env, propose(env))
    post_payment(env, amount=10000)
    Worker(env["service"], MemoryBank("lost_response")).dispatch_one()
    with env["service"].store.transaction() as db:
        db.execute("UPDATE payments SET created=created-90000")
    assert post_payment(env, amount=10000).json()["error"] == "account_pending_limit_exceeded"


def test_frozen_account_cancels_only_undispatched_and_reconciles_in_flight(env):
    in_flight = post_payment(env).json()
    bank = MemoryBank("lost_response")
    worker = Worker(env["service"], bank)
    worker.dispatch_one()
    queued = post_payment(env).json()
    assert env["client"].post(f"/v1/accounts/{env['a']['account']}/freeze", headers=bearer(env, "operator")).status_code == 200
    assert post_payment(env).json()["error"] == "account_frozen"
    worker.reconcile(force=True)
    states = {r["id"]: r["status"] for r in env["service"].store.rows("SELECT id,status FROM payments")}
    assert states == {in_flight["id"]: "settled", queued["id"]: "cancelled"}
    assert bank.submissions == 1


def test_repeat_freeze_invalidates_old_unfreeze_approval(env):
    endpoint = f"/v1/accounts/{env['a']['account']}/freeze"
    env["client"].post(endpoint, headers=bearer(env, "operator"))
    change = propose(env, action="unfreeze_account", limits=None)
    env["client"].post(endpoint, headers=bearer(env, "operator"))
    assert approve(env, change).json()["error"] == "control_version_changed"
    assert approve(env, propose(env, action="unfreeze_account", limits=None)).status_code == 200
    assert post_payment(env).status_code == 202


def test_integrated_resume_needs_second_person_and_newer_pause_invalidates_approval(env):
    service, operator = env["service"], env["a"]["operator"]
    service.settings.mode = "integrated"
    service.pause(operator, True)
    with pytest.raises(BridgeError, match="independent_resume_approval_required"):
        service.pause(operator, False)
    proposal = ControlProposal(action="resume_bank", reason="Incident investigated and contained")
    change = service.controls.propose(operator, proposal)
    service.pause(operator, True)
    reviewer = Principal(operator.tenant, "independent", "reviewer")
    with pytest.raises(BridgeError, match="control_version_changed"):
        service.controls.review(reviewer, change["id"], ReviewRequest(decision="approve", request_hash=change["request_hash"]))
    change = service.controls.propose(operator, proposal)
    service.controls.review(reviewer, change["id"], ReviewRequest(decision="approve", request_hash=change["request_hash"]))
    assert service.store.rows("SELECT paused FROM tenants")[0]["paused"] == 0


def test_new_policy_is_rechecked_before_dispatch(env):
    p = post_payment(env, amount=15000).json()
    approve(env, propose(env))
    bank = MemoryBank()
    Worker(env["service"], bank).dispatch_one()
    assert bank.submissions == 0
    assert env["service"].store.rows("SELECT status FROM payments WHERE id=?", (p["id"],))[0]["status"] == "cancelled"


def test_new_review_requirement_prevents_existing_queue_from_bypassing_it(env):
    p = post_payment(env).json()
    change = propose(env, limits={"per_payment_minor": 10000, "rolling_day_minor": 15000, "max_pending_minor": 15000})
    approve(env, change)
    bank = MemoryBank()
    Worker(env["service"], bank).dispatch_one()
    assert bank.submissions == 0
    assert env["service"].store.rows("SELECT status FROM payments WHERE id=?", (p["id"],))[0]["status"] == "review"


def test_integrated_account_without_approved_limits_fails_closed(env):
    service = env["service"]
    service.settings.mode = "integrated"
    with pytest.raises(BridgeError, match="account_limits_required"):
        submit_sample(service, env["a"])
    assert not service.store.rows("SELECT * FROM payments")


def test_alias_cannot_duplicate_bank_account_to_bypass_shared_limits(env):
    service, a = env["service"], env["a"]
    bank_id = service.vault.open(service.store.rows("SELECT bank_id FROM accounts")[0]["bank_id"], a["operator"].tenant, "accounts", a["account"])
    with pytest.raises(BridgeError, match="bank_account_already_registered"):
        service.register_account(a["operator"], AccountRegistration(id="duplicate", customer=a["customer"].subject, bank_id=bank_id, currency="GBP"))


def test_stale_queued_request_expires_without_bank_dispatch(env):
    approve(env, propose(env))
    post_payment(env)
    now = env["service"].clock()
    env["service"].clock = lambda: now + 901
    bank = MemoryBank()
    Worker(env["service"], bank).dispatch_one()
    assert bank.submissions == 0
    assert env["service"].store.rows("SELECT status,reason FROM payments")[0] == {"status": "cancelled", "reason": "payment_request_expired"}


@pytest.mark.parametrize("actor_type", [None, "unknown", "service", {}, True, "missing"])
@pytest.mark.parametrize("role", ["operator", "reviewer", "evaluator"])
def test_issuer_must_explicitly_attest_staff_human_identity(env, tmp_path, actor_type, role):
    auth, key, claims = integrated_auth(env, tmp_path)
    claims["role"] = role
    claims["scout_actor_type"] = actor_type
    if actor_type == "missing":
        claims.pop("scout_actor_type")
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "bank-key-1"})
    with pytest.raises(BridgeError, match="unauthenticated"):
        auth.authenticate(token, {role})


def test_legacy_duplicate_aliases_cannot_activate_new_account_policy(env):
    service, a = env["service"], env["a"]
    existing = service.store.rows("SELECT * FROM accounts")[0]
    plaintext = service.vault.open(existing["bank_id"], existing["tenant"], "accounts", existing["id"])
    encrypted = service.vault.seal(plaintext, existing["tenant"], "accounts", "legacy_duplicate")
    with service.store.transaction() as db:
        db.execute("INSERT INTO accounts VALUES(?,?,?,?,?)", ("legacy_duplicate", existing["tenant"], existing["customer"], encrypted, "GBP"))
    model = ControlProposal(action="account_limits", account_id=a["account"], reason="Post upgrade policy",
                            limits={"per_payment_minor": 1000, "rolling_day_minor": 1000, "max_pending_minor": 1000})
    with pytest.raises(BridgeError, match="duplicate_bank_account_aliases"):
        service.controls.propose(a["operator"], model)
