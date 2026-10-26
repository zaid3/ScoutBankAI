import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from scoutbankai.auth import Authenticator
from scoutbankai.config import Settings
from scoutbankai.crypto import canonical, digest, new_key, public_jwk, strict_json
from scoutbankai.errors import BridgeError
from scoutbankai.store import Store

from conftest import bearer, post_payment, request_payment


def test_no_credentials_appear_in_overview_or_audit(env):
    post_payment(env)
    response = env["client"].get("/v1/overview", headers=bearer(env, "auditor"))
    assert response.status_code == 200
    for secret in [env["a"]["token"], *env["credentials"].values()]:
        assert secret not in response.text


def test_auditor_cannot_pause_or_register(env):
    response = env["client"].post("/v1/pause", json={"paused": True}, headers=bearer(env, "auditor"))
    assert response.status_code == 403


def test_invalid_origin_and_host_are_rejected(env):
    assert env["client"].get("/healthz", headers={"Origin": "https://evil.example"}).status_code == 403
    assert env["client"].get("/healthz", headers={"Host": "evil.example"}).status_code == 400


def test_duplicate_json_and_oversized_bodies_are_rejected(env):
    headers = {**bearer(env, "operator"), "Content-Type": "application/json"}
    assert env["client"].post("/v1/pause", content=b'{"paused":true,"paused":false}', headers=headers).status_code == 400
    assert env["client"].post("/v1/pause", content=b"x" * 32769, headers=headers).status_code == 413


def test_no_cache_and_csp_on_sensitive_responses(env):
    response = env["client"].get("/v1/overview", headers=bearer(env, "operator"))
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_persistent_token_rate_limit(env):
    statuses = [env["client"].get("/v1/overview", headers=bearer(env, "operator")).status_code for _ in range(121)]
    assert statuses[-1] == 429


def test_audit_mutation_is_detected_without_triggers(env):
    service = env["service"]
    with service.store.transaction() as db:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET event='{}' WHERE seq=1")
    with pytest.raises(BridgeError, match="audit_integrity_failure"):
        service.store.verify_audit()


def test_external_checkpoint_detects_tail_deletion(env):
    post_payment(env)
    store = env["service"].store
    anchor = store.verify_audit()
    with store.transaction() as db:
        db.execute("DROP TRIGGER audit_no_delete")
        db.execute("DELETE FROM audit WHERE seq=?", (anchor["seq"],))
    with pytest.raises(BridgeError, match="audit_anchor_missing"):
        store.verify_audit(anchor)


def test_new_service_fails_on_damaged_audit(env):
    store = env["service"].store
    with store.transaction() as db:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET hash=? WHERE seq=1", ("0" * 64,))
    with pytest.raises(BridgeError):
        Store(store.path, store.audit_key)


def integrated_auth(env, tmp_path):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": "bank-key-1", "alg": "RS256", "use": "sig"})
    path = tmp_path / "bank-jwks.json"
    path.write_text(json.dumps({"keys": [public]}))
    cfg = Settings(database=env["settings"].database, audit_key=env["settings"].audit_key,
                   nonce_key=env["settings"].nonce_key, mode="integrated", origin="https://scout.bank.example",
                   issuer="https://identity.bank.example", audience="scoutbankai", jwks_file=str(path),
                   connector={"base_url": "https://gateway.bank.example"}).validate()
    auth = Authenticator(cfg, env["service"].store, lambda: int(time.time()))
    now = int(time.time())
    claims = {"iss": cfg.issuer, "aud": cfg.audience, "sub": "staff-1", "role": "operator", "tenant": "sample-bank", "iat": now, "exp": now + 600}
    return auth, private, claims


def test_integrated_mode_accepts_bank_issuer(env, tmp_path):
    auth, key, claims = integrated_auth(env, tmp_path)
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "bank-key-1"})
    assert auth.authenticate(token, {"operator"}).subject == "staff-1"
    with pytest.raises(BridgeError):
        auth.authenticate(env["credentials"]["operator"], {"operator"})


@pytest.mark.parametrize("patch", [{"iss": "https://attacker.example"}, {"aud": "another-app"}, {"exp": 1}, {"role": "customer"}, {"tenant": "disabled-bank"}, {"exp": int(time.time()) + 3600}])
def test_integrated_mode_rejects_wrong_issuer_audience_role_lifetime(env, tmp_path, patch):
    auth, key, claims = integrated_auth(env, tmp_path)
    token = jwt.encode({**claims, **patch}, key, algorithm="RS256", headers={"kid": "bank-key-1"})
    with pytest.raises(BridgeError):
        auth.authenticate(token, {"operator"})


def test_integrated_config_requires_https_and_independent_secrets(env):
    s = env["settings"]
    with pytest.raises(ValueError):
        Settings(database=s.database, audit_key=s.audit_key, nonce_key=s.audit_key).validate()
    with pytest.raises(ValueError):
        Settings(database=s.database, audit_key=s.audit_key, nonce_key=s.nonce_key, mode="integrated").validate()

