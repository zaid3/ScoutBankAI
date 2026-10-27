import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event

import pytest

from scoutbankai.connectors import MemoryBank
from scoutbankai.errors import BridgeError
from scoutbankai.journal import verify_financial_state
from scoutbankai.models import Advisory, CancelPaymentRequest, RestoreControlRequest, ReviewRequest, TimelineQuery
from scoutbankai.timeline import search
from scoutbankai.worker import Worker
from scoutbankai.bootstrap import submit_sample

from conftest import bearer, post_payment
from test_account_security import approve, propose


def history(env, **query):
    result = env["client"].post("/v1/timeline/search", json=query, headers=bearer(env, "auditor"))
    assert result.status_code == 200, result.text
    return result.json()


def cancellation(payment):
    return {"request_hash": payment["request_hash"], "reason": "Operator confirmed this request should be stopped."}


def restore_body(env, change):
    account = env["client"].get(f"/v1/accounts/{env['a']['account']}/controls", headers=bearer(env, "operator")).json()
    return {"source_hash": change["request_hash"], "expected_version": account["version"], "reason": "Restore the earlier approved limits after independent review."}


def two_policies(env):
    first = propose(env)
    assert approve(env, first).status_code == 200
    second = propose(env, limits={"per_payment_minor": 5000, "rolling_day_minor": 10000, "max_pending_minor": 10000})
    assert approve(env, second).status_code == 200
    return first, second


def test_timeline_pages_beyond_snapshot_without_duplicates_or_new_arrivals(env):
    service = env["service"]
    with service.store.transaction() as db:
        for i in range(123):
            service.store.event(db, env["a"]["operator"].tenant, "fixture_history", "history-worker", 1000 + i,
                                account_id=env["a"]["account"], reason="Controlled history fixture")
    first = history(env, actor="history-worker", limit=50)
    with service.store.transaction() as db:
        service.store.event(db, env["a"]["operator"].tenant, "fixture_history", "history-worker", 2000)
    events, page = first["events"], first
    while page["next_before_seq"]:
        page = history(env, actor="history-worker", limit=50, snapshot_seq=first["snapshot_seq"], before_seq=page["next_before_seq"])
        events += page["events"]
    assert len(events) == len({e["seq"] for e in events}) == 123
    assert all(e["time"] < 2000 for e in events)
    assert history(env, actor="history-worker")["events"][0]["time"] == 2000
    assert all(e["hash"] and e["previous_hash"] for e in events)


def test_timeline_filters_exact_actor_action_object_and_time(env):
    p = post_payment(env).json()
    matches = history(env, object_id=p["id"], actor="policy", action="cross_audit_report", from_time=p["created"], to_time=p["updated"])["events"]
    assert len(matches) == 2
    assert {e["round"] for e in matches} == {1, 2}
    assert all(e["model"] == "rules-v1" and e["mode"] == "rules" for e in matches)
    assert history(env, actor="' OR 1=1 --")["events"] == []


def test_timeline_never_exposes_another_tenant_or_customer_role(env):
    post_payment(env)
    foreign = replace(env["a"]["operator"], tenant="other-bank")
    assert search(env["service"], foreign, TimelineQuery())["events"] == []
    for role in ("operator", "reviewer", "auditor", "evaluator"):
        assert env["client"].post("/v1/timeline/search", json={}, headers=bearer(env, role)).status_code == 200
    assert env["client"].post("/v1/timeline/search", json={}, headers=bearer(env, "customer")).status_code == 403


@pytest.mark.parametrize("query", [{"limit": 101}, {"limit": True}, {"before_seq": -1}, {"from_time": 20, "to_time": 10},
                                    {"object_id": "../private"}, {"action": "bad action"}, {"tenant": "other-bank"}])
def test_timeline_rejects_invalid_or_unbounded_queries(env, query):
    assert env["client"].post("/v1/timeline/search", json=query, headers=bearer(env, "auditor")).status_code == 422


def test_timeline_detects_changed_event_signature(env):
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET hash=? WHERE seq=(SELECT max(seq) FROM audit)", ("0" * 64,))
    assert env["client"].post("/v1/timeline/search", json={}, headers=bearer(env, "auditor")).status_code == 503


@pytest.mark.parametrize("amount", [5000, 25000])
def test_cancel_queued_or_held_payment_releases_once_and_keeps_evidence(env, amount):
    p = post_payment(env, amount=amount).json()
    url = f"/v1/payments/{p['id']}/cancel"
    for _ in range(2):
        result = env["client"].post(url, json=cancellation(p), headers=bearer(env, "operator"))
        assert result.status_code == 200 and result.json()["status"] == "cancelled"
    service = env["service"]
    assert service.store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 100000
    events = history(env, object_id=p["id"])["events"]
    assert sum(e["action"] == "payment_cancellation_requested" for e in events) == 1
    assert any(e["action"] == "payment_reserved" for e in events)
    assert Worker(service, MemoryBank()).dispatch_one() is None
    with service.store.transaction() as db: verify_financial_state(db)


def test_cancel_during_screening_cannot_be_undone_by_late_advice(env):
    started, release = Event(), Event()
    class Blocking:
        name = "controlled-blocking"
        def assess(self, context):
            started.set()
            assert release.wait(5)
            return Advisory(require_review=False, reason="routine")
    service = env["service"]
    service.supervisor = Blocking()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(submit_sample, service, env["a"])
        try:
            assert started.wait(5)
            p = service.store.rows("SELECT * FROM payments")[0]
            service.cancel_payment(env["a"]["operator"], p["id"], CancelPaymentRequest(**cancellation(p)))
        finally:
            release.set()
        assert future.result()["status"] == "cancelled"
    assert service.store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 100000


@pytest.mark.parametrize("outcome", ["settled", "accepted", "lost_response", "rejected"])
def test_cancel_never_rewinds_dispatched_or_terminal_bank_outcomes(env, outcome):
    p = post_payment(env).json()
    service, bank = env["service"], MemoryBank(outcome)
    Worker(service, bank).dispatch_one()
    before = service.store.rows("SELECT status,reason FROM payments")
    budget = service.store.rows("SELECT budget_remaining FROM mandates")
    result = env["client"].post(f"/v1/payments/{p['id']}/cancel", json=cancellation(p), headers=bearer(env, "operator"))
    assert result.status_code == 409
    assert service.store.rows("SELECT status,reason FROM payments") == before
    assert service.store.rows("SELECT budget_remaining FROM mandates") == budget
    assert bank.submissions == 1


def test_cancellation_requires_operator_exact_request_and_tenant(env):
    p = post_payment(env).json()
    url = f"/v1/payments/{p['id']}/cancel"
    for role in ("customer", "reviewer", "auditor", "evaluator"):
        assert env["client"].post(url, json=cancellation(p), headers=bearer(env, role)).status_code == 403
    assert env["client"].post(url, json={**cancellation(p), "request_hash": "0" * 64}, headers=bearer(env, "operator")).status_code == 409
    with pytest.raises(BridgeError, match="payment_not_found"):
        env["service"].cancel_payment(replace(env["a"]["operator"], tenant="other-bank"), p["id"], CancelPaymentRequest(**cancellation(p)))


def test_cancel_dispatch_race_has_one_financial_outcome(env):
    p = post_payment(env).json()
    service, bank, barrier = env["service"], MemoryBank(), Barrier(2)
    def cancel():
        barrier.wait()
        try: return service.cancel_payment(env["a"]["operator"], p["id"], CancelPaymentRequest(**cancellation(p)))["status"]
        except BridgeError as exc: return exc.code
    def dispatch():
        barrier.wait()
        return Worker(service, bank).dispatch_one()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1, f2 = pool.submit(cancel), pool.submit(dispatch)
        f1.result(); f2.result()
    status = service.store.rows("SELECT status FROM payments")[0]["status"]
    assert (status, bank.submissions) in {("cancelled", 0), ("settled", 1)}
    with service.store.transaction() as db: verify_financial_state(db)


def test_restore_is_new_independent_approval_and_keeps_history_and_freeze(env):
    first, second = two_policies(env)
    service, operator = env["service"], env["a"]["operator"]
    service.controls.freeze(operator, env["a"]["account"])
    old_source = service.controls.change_detail(operator, first["id"])
    result = env["client"].post(f"/v1/control-changes/{first['id']}/restore", json=restore_body(env, first), headers=bearer(env, "operator"))
    assert result.status_code == 201
    change = result.json()
    assert change["proposal"]["restores_change_id"] == first["id"]
    assert service.controls.account_detail(operator, env["a"]["account"])["policy"]["per_payment_minor"] == 5000
    with pytest.raises(BridgeError, match="independent_reviewer_required"):
        service.controls.review(replace(operator, role="reviewer"), change["id"], ReviewRequest(decision="approve", request_hash=change["request_hash"]))
    assert approve(env, change).status_code == 200
    current = service.controls.account_detail(operator, env["a"]["account"])
    assert current["policy"]["per_payment_minor"] == 10000 and current["frozen"] == 1
    assert service.controls.change_detail(operator, first["id"]) == old_source
    event = history(env, object_id=change["id"], action="control_change_approved")["events"][0]
    assert event["before_state"]["limits"]["per_payment_minor"] == 5000
    assert event["after_state"]["limits"]["per_payment_minor"] == 10000
    assert event["restores_change_id"] == first["id"]


def test_restore_rejects_stale_version_hash_current_policy_and_wrong_role(env):
    first, second = two_policies(env)
    url = f"/v1/control-changes/{first['id']}/restore"
    body = restore_body(env, first)
    for role in ("customer", "reviewer", "auditor", "evaluator"):
        assert env["client"].post(url, json=body, headers=bearer(env, role)).status_code == 403
    for changes in ({"expected_version": 0}, {"source_hash": "0" * 64}):
        assert env["client"].post(url, json={**body, **changes}, headers=bearer(env, "operator")).status_code == 409
    assert env["client"].post(f"/v1/control-changes/{second['id']}/restore", json=restore_body(env, second), headers=bearer(env, "operator")).json()["error"] == "control_limits_already_current"
    pending = env["client"].post(url, json=body, headers=bearer(env, "operator")).json()
    approve(env, propose(env))
    assert approve(env, pending).json()["error"] == "control_version_changed"


@pytest.mark.parametrize("decision", [None, "reject"])
def test_unapproved_limits_are_not_a_restoration_source(env, decision):
    change = propose(env)
    if decision: approve(env, change, decision)
    result = env["client"].post(f"/v1/control-changes/{change['id']}/restore", json=restore_body(env, change), headers=bearer(env, "operator"))
    assert result.json()["error"] == "control_restore_source_invalid"


def test_control_detail_and_restore_do_not_cross_tenants(env):
    first, second = two_policies(env)
    actor = replace(env["a"]["operator"], tenant="other-bank")
    controls = env["service"].controls
    for fn in (lambda: controls.account_detail(actor, env["a"]["account"]),
               lambda: controls.change_detail(actor, first["id"]),
               lambda: controls.restore(actor, first["id"], RestoreControlRequest(**restore_body(env, first)))):
        with pytest.raises(BridgeError) as exc: fn()
        assert exc.value.status == 404
