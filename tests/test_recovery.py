from concurrent.futures import ThreadPoolExecutor

from scoutbankai.bootstrap import submit_sample
from scoutbankai.connectors import BankResult, MemoryBank
from scoutbankai.service import Service
from scoutbankai.worker import Worker

from conftest import post_payment


def test_lost_bank_response_reconciles_without_resubmission(env):
    p = post_payment(env).json()
    bank = MemoryBank("lost_response")
    worker = Worker(env["service"], bank)
    worker.dispatch_one()
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "unknown"
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 95000
    worker.dispatch_one()
    assert bank.submissions == 1
    worker.reconcile(force=True)
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "settled"
    assert bank.submissions == 1


def test_unknown_is_durable_after_restart(env):
    post_payment(env)
    bank = MemoryBank("lost_response")
    Worker(env["service"], bank).dispatch_one()
    restarted = Service(env["settings"])
    assert restarted.store.rows("SELECT status FROM payments")[0]["status"] == "unknown"
    Worker(restarted, bank).reconcile(force=True)
    assert restarted.store.rows("SELECT status FROM payments")[0]["status"] == "settled"


def test_concurrent_workers_only_dispatch_once(env):
    post_payment(env)
    bank = MemoryBank()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: Worker(env["service"], bank).dispatch_one(), range(8)))
    assert bank.submissions == 1


def test_rejected_bank_payment_returns_reservation_once(env):
    post_payment(env)
    bank = MemoryBank("rejected")
    worker = Worker(env["service"], bank)
    worker.dispatch_one()
    worker.reconcile(force=True)
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 100000


def test_expired_consent_is_rechecked_at_dispatch(env):
    post_payment(env)
    now = env["service"].clock()
    env["service"].clock = lambda: now + 3601
    bank = MemoryBank()
    Worker(env["service"], bank).dispatch_one()
    assert bank.submissions == 0
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "cancelled"


def test_revocation_does_not_claim_to_reverse_dispatched_payment(env):
    post_payment(env)
    bank = MemoryBank("lost_response")
    worker = Worker(env["service"], bank)
    worker.dispatch_one()
    env["service"].revoke(env["a"]["customer"], env["a"]["mandate"])
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "unknown"
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 95000
    worker.reconcile(force=True)
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "settled"


def test_reconciliation_continues_while_bank_paused(env):
    post_payment(env)
    bank = MemoryBank("lost_response")
    worker = Worker(env["service"], bank)
    worker.dispatch_one()
    env["service"].pause(env["a"]["operator"], True)
    worker.reconcile(force=True)
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "settled"


def test_crash_before_network_call_does_not_cause_blind_retry(env):
    post_payment(env)
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("UPDATE payments SET status='dispatching',updated=?", (service.clock() - 120,))
    bank = MemoryBank()
    worker = Worker(service, bank)
    worker.reconcile(force=True)
    assert service.store.rows("SELECT status FROM payments")[0]["status"] == "unknown"
    assert worker.dispatch_one() is None
    assert bank.submissions == 0


def test_interrupted_supervisor_requires_review(env):
    post_payment(env)
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("UPDATE payments SET status='screening',updated=?", (service.clock() - 120,))
    Worker(service, MemoryBank()).recover_screening()
    row = service.store.rows("SELECT status,reason FROM payments")[0]
    assert row == {"status": "review", "reason": "supervision_interrupted"}


def test_pending_bank_outcome_retains_budget(env):
    post_payment(env)
    bank = MemoryBank("accepted")
    worker = Worker(env["service"], bank)
    worker.dispatch_one()
    worker.reconcile(force=True)
    assert env["service"].store.rows("SELECT status FROM payments")[0]["status"] == "submitted"
    assert env["service"].store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 95000

