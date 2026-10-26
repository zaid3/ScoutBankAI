import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from scoutbankai.config import Settings
from scoutbankai.errors import BridgeError
from scoutbankai.operations import backup, check, configure
from scoutbankai.store import Store

from conftest import post_payment
from test_security import integrated_auth


def test_backup_is_consistent_verifiable_and_does_not_copy_keys(env, tmp_path):
    post_payment(env)
    service = env["service"]
    anchor = service.store.verify_audit()
    directory = tmp_path / "backup"
    manifest = backup(service, directory, anchor)
    assert manifest["sha256"] == hashlib.sha256((directory / "scout.db").read_bytes()).hexdigest()
    assert set(p.name for p in directory.iterdir()) == {"scout.db", "manifest.json"}
    restored = Store(str(directory / "scout.db"), service.settings.audit_key)
    assert restored.verify_audit(anchor) == manifest["audit_checkpoint"]
    assert restored.rows("SELECT status FROM payments") == [{"status": "queued"}]
    assert check(service)["network_contacted"] is False
    with pytest.raises(FileExistsError):
        backup(service, directory)


def test_backup_rejects_missing_external_anchor(env, tmp_path):
    with pytest.raises(BridgeError, match="audit_anchor_missing"):
        backup(env["service"], tmp_path / "backup", {"seq": 10000, "hash": "a" * 64})
    assert not (tmp_path / "backup" / "manifest.json").exists()


def test_newer_database_schema_is_not_modified(tmp_path):
    database = tmp_path / "future.db"
    with sqlite3.connect(database) as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(ValueError, match="unsupported database schema"):
        Store(str(database), b"a" * 32)
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == 0


def test_integrated_config_has_no_development_credentials(tmp_path):
    directory = tmp_path / "integrated"
    result = configure(directory, "https://control.bank.example", "https://issuer.bank.example", "https://gateway.bank.example")
    assert result["status"] == "requires_bank_provisioning"
    assert not (directory / "credentials.json").exists()
    config = json.loads((directory / "config.json").read_text())
    config["connector"].pop("key_file")
    config["connector"].pop("token_file")
    (directory / "config.json").write_text(json.dumps(config))
    settings = Settings.load(str(directory / "config.json"))
    assert settings.connector["cert_file"] == str(directory / "bank-client.crt")
    assert settings.audit_key != settings.nonce_key
    if os.name == "posix":
        (directory / "audit.key").chmod(0o644)
        with pytest.raises(ValueError, match="owner-only"):
            Settings.load(str(directory / "config.json"))


@pytest.mark.parametrize("role", [[], {}, 1, None])
def test_malformed_signed_role_fails_closed(env, tmp_path, role):
    import jwt
    auth, key, claims = integrated_auth(env, tmp_path)
    token = jwt.encode({**claims, "role": role}, key, algorithm="RS256", headers={"kid": "bank-key-1"})
    with pytest.raises(BridgeError, match="unauthenticated"):
        auth.authenticate(token, {"operator"})


@pytest.mark.parametrize("header", ["Authorization", "DPoP", "Idempotency-Key", "Origin"])
def test_ambiguous_security_headers_are_rejected(env, header):
    response = env["client"].get("/v1/overview", headers=[(header, "value1"), (header, "value2")])
    assert response.status_code == 400
    assert response.json()["error"] == "duplicate_header"
