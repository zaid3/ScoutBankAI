import base64
import json
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from scoutbankai.connectors import MemoryBank
from scoutbankai.errors import BridgeError
from scoutbankai.journal import verify_financial_state
from scoutbankai.operations import backup, reencrypt_vault
from scoutbankai.service import Service
from scoutbankai.vault import Vault
from scoutbankai.worker import Worker

from conftest import bearer, post_payment


@pytest.mark.parametrize("outcome,expected", [("settled", {"reserve", "settle"}), ("rejected", {"reserve", "release"}),
                                               ("lost_response", {"reserve"}), ("accepted", {"reserve"})])
def test_reservation_journal_tracks_authoritative_outcome(env, outcome, expected):
    post_payment(env)
    worker = Worker(env["service"], MemoryBank(outcome))
    worker.dispatch_one()
    assert {r["kind"] for r in env["service"].store.rows("SELECT kind FROM journal")} == expected
    response = env["client"].get("/v1/journal/verify", headers=bearer(env, "auditor"))
    assert response.json()["payments_checked"] == 1
    assert response.json()["integrity"] == "verified"


def test_concurrent_reconciliation_cannot_double_settle_journal(env):
    post_payment(env)
    bank = MemoryBank("lost_response")
    worker = Worker(env["service"], bank)
    worker.dispatch_one()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: worker.reconcile(force=True), range(8)))
    assert [r["kind"] for r in env["service"].store.rows("SELECT kind FROM journal ORDER BY seq")] == ["reserve", "settle"]
    assert bank.submissions == 1


def test_cancelled_payment_has_one_balanced_release(env):
    post_payment(env)
    service, a = env["service"], env["a"]
    service.revoke(a["customer"], a["mandate"])
    service.revoke(a["customer"], a["mandate"])
    rows = service.store.rows("SELECT kind,debit,credit,amount FROM journal ORDER BY seq")
    assert len(rows) == 2
    assert rows[0]["debit"] == rows[1]["credit"]
    assert rows[0]["credit"] == rows[1]["debit"]
    assert rows[0]["amount"] == rows[1]["amount"]


@pytest.mark.parametrize("mutation", ["UPDATE journal SET amount=1", "DELETE FROM journal"])
def test_journal_is_append_only(env, mutation):
    post_payment(env)
    with pytest.raises(sqlite3.IntegrityError, match="append only"):
        with env["service"].store.transaction() as db:
            db.execute(mutation)


def test_payment_corruption_is_blocked_before_any_bank_request(env):
    post_payment(env)
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("UPDATE payments SET amount=6000")
    bank = MemoryBank()
    with pytest.raises(BridgeError, match="financial_integrity_failure"):
        Worker(service, bank).dispatch_one()
    assert bank.submissions == 0
    assert env["client"].get("/v1/journal/verify", headers=bearer(env, "auditor")).status_code == 503


def test_journal_corruption_and_budget_drift_are_detected(env):
    post_payment(env)
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("UPDATE mandates SET budget_remaining=budget_remaining+1")
    with pytest.raises(BridgeError, match="financial_integrity_failure"):
        with service.store.transaction() as db:
            verify_financial_state(db)
    with service.store.transaction() as db:
        db.execute("UPDATE mandates SET budget_remaining=budget_remaining-1")
        db.execute("DROP TRIGGER journal_no_update")
        db.execute("UPDATE journal SET amount=1")
    with pytest.raises(BridgeError, match="financial_integrity_failure"):
        backup(service, Path(service.settings.database).parent / "bad-backup")


def test_schema_one_migration_preserves_existing_payment_and_budget(env):
    post_payment(env)
    service = env["service"]
    Worker(service, MemoryBank()).dispatch_one()
    before = service.store.rows("SELECT * FROM payments")
    with service.store.transaction() as db:
        db.execute("DROP TABLE journal")
        db.execute("PRAGMA user_version=1")
    restarted = Service(env["settings"])
    assert restarted.store.rows("SELECT * FROM payments") == before
    with restarted.store.transaction() as db:
        assert verify_financial_state(db)["payments_checked"] == 1
    assert restarted.store.rows("PRAGMA user_version")[0]["user_version"] == 2
    assert any("reservation_journal_migrated" in r["event"] for r in restarted.store.rows("SELECT event FROM audit"))
    Service(env["settings"])
    assert len(restarted.store.rows("SELECT * FROM journal")) == 2


def test_bank_identifiers_are_encrypted_and_bound_to_record_context(env):
    service, a = env["service"], env["a"]
    row = service.store.rows("SELECT * FROM accounts")[0]
    plaintext = service.vault.open(row["bank_id"], row["tenant"], "accounts", row["id"])
    assert row["bank_id"].startswith("sbv1.") and "sample-checking" not in row["bank_id"]
    assert service.vault.seal(plaintext, row["tenant"], "accounts", row["id"]) != row["bank_id"]
    for tenant, table, identifier in (("other", "accounts", row["id"]), (row["tenant"], "payees", row["id"]), (row["tenant"], "accounts", "other")):
        with pytest.raises(BridgeError, match="vault_integrity_failure"):
            service.vault.open(row["bank_id"], tenant, table, identifier)
    assert plaintext not in env["client"].get("/v1/overview", headers=bearer(env, "operator")).text


def test_corrupt_ciphertext_blocks_dispatch_without_releasing_reservation(env):
    post_payment(env)
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("UPDATE accounts SET bank_id=bank_id || 'bad'")
    bank = MemoryBank()
    with pytest.raises(BridgeError, match="vault_integrity_failure"):
        Worker(service, bank).dispatch_one()
    assert bank.submissions == 0
    assert service.store.rows("SELECT status FROM payments")[0]["status"] == "queued"
    assert service.store.rows("SELECT budget_remaining FROM mandates")[0]["budget_remaining"] == 95000


def test_missing_or_removed_key_does_not_fall_back_to_plaintext(env):
    row = env["service"].store.rows("SELECT * FROM accounts")[0]
    with pytest.raises(BridgeError, match="vault_integrity_failure"):
        Vault(allow_plaintext=True).open(row["bank_id"], row["tenant"], "accounts", row["id"])
    with pytest.raises(BridgeError, match="unencrypted_bank_identifier"):
        Vault().open("sample-checking", "bank", "accounts", "account")
    with pytest.raises(BridgeError, match="vault_not_configured"):
        Vault().seal("sample-checking", "bank", "accounts", "account")


def test_rotation_reencrypts_records_and_old_backup_keeps_original_keys(env, tmp_path):
    service = env["service"]
    post_payment(env)
    backup(service, tmp_path / "backup")
    keyfile = Path(env["settings"].vault_keyring_file)
    keyring = json.loads(keyfile.read_text())
    keyring["active"] = "key2"
    keyring["keys"]["key2"] = base64.b64encode(secrets.token_bytes(32)).decode()
    keyfile.write_text(json.dumps(keyring))
    restarted = Service(env["settings"])
    assert reencrypt_vault(restarted)["records_reencrypted"] == 2
    assert restarted.store.rows("SELECT bank_id FROM accounts")[0]["bank_id"].startswith("sbv1.key2.")
    with sqlite3.connect(tmp_path / "backup" / "scout.db") as db:
        old = db.execute("SELECT bank_id FROM accounts").fetchone()[0]
    a = env["a"]
    assert restarted.vault.open(old, a["operator"].tenant, "accounts", a["account"]).startswith("sample-checking")
    assert Worker(restarted, MemoryBank()).dispatch_one()


def test_plaintext_upgrade_is_explicit_and_transactional(env):
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("UPDATE accounts SET bank_id='legacy-bank-id'")
    result = reencrypt_vault(service)
    assert result["records_reencrypted"] == 2
    assert service.store.rows("SELECT bank_id FROM accounts")[0]["bank_id"].startswith("sbv1.")


def test_key_file_permissions_are_checked(env):
    import os
    if os.name != "posix":
        pytest.skip("POSIX permissions")
    keyfile = Path(env["settings"].vault_keyring_file)
    keyfile.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        Vault(str(keyfile))
