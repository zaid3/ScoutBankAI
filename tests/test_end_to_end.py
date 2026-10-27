"""Real loopback TCP, verified TLS and mutual TLS; all funds are simulated."""
import ipaddress
import json
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scoutbankai.api import create_app
from scoutbankai.client import ScoutClient
from scoutbankai.config import Settings
from scoutbankai.connectors import HTTPBankAdapter
from scoutbankai.crypto import canonical, digest, new_key, public_jwk
from scoutbankai.mock_bank import create_mock_bank
from scoutbankai.models import MandateRequest
from scoutbankai.service import Service
from scoutbankai.worker import Worker


@contextmanager
def server(app, **tls):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(app, log_level="error", access_log=False, **tls)
    instance = uvicorn.Server(config)
    thread = threading.Thread(target=instance.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not instance.started and time.monotonic() < deadline and thread.is_alive():
            time.sleep(0.01)
        assert instance.started, "local test service did not start"
        yield f"{'https' if tls else 'http'}://127.0.0.1:{port}"
    finally:
        instance.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "local test service did not stop"


@pytest.fixture
def certificates(tmp_path):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ScoutBankAI ephemeral test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                      crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths = {"ca": str(ca_path)}
    for name, usage in (("server", ExtendedKeyUsageOID.SERVER_AUTH), ("client", ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                   .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                               data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                               crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
        if name == "server":
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        for kind, raw in (("crt", cert.public_bytes(serialization.Encoding.PEM)),
                          ("key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
            path = tmp_path / f"{name}.{kind}"
            path.write_bytes(raw)
            path.chmod(0o600)
            paths[f"{name}_{kind}"] = str(path)
    return paths


def test_signed_consent_sdk_and_worker_over_real_https_with_mtls(tmp_path, certificates, monkeypatch):
    original_context = ssl.create_default_context
    def strict_context(*args, **kwargs):
        context = original_context(*args, **kwargs)
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        return context
    # Exercise strict validation on every supported Python version, including pre-3.13.
    monkeypatch.setattr(ssl, "create_default_context", strict_context)
    pki = certificates
    bank_token = tmp_path / "bank-token.key"
    bank_token.write_text(secrets.token_urlsafe(48))
    bank_db = tmp_path / "bank.db"
    bank_app = create_mock_bank(str(bank_db), str(bank_token))
    tls = {"ssl_certfile": pki["server_crt"], "ssl_keyfile": pki["server_key"]}
    with server(bank_app, **tls, ssl_ca_certs=pki["ca"], ssl_cert_reqs=ssl.CERT_REQUIRED) as bank_url:
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(issuer_key.public_key()))
        issuer_public.update(kid="test-issuer", alg="RS256", use="sig")
        jwks = tmp_path / "issuer.json"
        jwks.write_text(json.dumps({"keys": [issuer_public]}))
        from scoutbankai.bootstrap import private_write
        from scoutbankai.vault import new_keyring
        vault_file = tmp_path / "vault.json"
        private_write(vault_file, json.dumps(new_keyring()))
        connector = {"base_url": bank_url, "ca_file": pki["ca"], "cert_file": pki["client_crt"],
                     "key_file": pki["client_key"], "token_file": str(bank_token)}
        cfg = Settings(database=str(tmp_path / "scout.db"), audit_key=secrets.token_bytes(32),
                       nonce_key=secrets.token_bytes(32), mode="integrated", origin="https://127.0.0.1",
                       issuer="https://issuer.bank.example", jwks_file=str(jwks), connector=connector, vault_keyring_file=str(vault_file))
        service = Service(cfg)
        with service.store.transaction() as db:
            db.execute("INSERT INTO tenants(id) VALUES('test-bank')")
        app = create_app(cfg, service)
        with server(app, **tls) as origin:
            cfg.origin = origin
            def bearer(role, **extra):
                now = int(time.time())
                claims = {"iss": cfg.issuer, "aud": cfg.audience, "tenant": "test-bank", "sub": role + "-1",
                          "role": role, "iat": now, "exp": now + 300, "scout_actor_type": "human", **extra}
                return {"Authorization": "Bearer " + jwt.encode(claims, issuer_key, algorithm="RS256", headers={"kid": "test-issuer"})}
            with httpx.Client(base_url=origin, verify=ssl.create_default_context(cafile=pki["ca"]), trust_env=False) as control:
                agent_key = new_key()
                registered = control.post("/v1/agents", headers=bearer("operator"), json={"name": "Invoice agent", "owner": "agent-owner", "public_jwk": public_jwk(agent_key)})
                assert registered.status_code == 201
                assert control.post("/v1/accounts", headers=bearer("operator"), json={"id": "checking", "customer": "customer-1", "bank_id": "sample-checking", "currency": "GBP"}).status_code == 201
                assert control.post("/v1/payees", headers=bearer("operator"), json={"id": "supplier", "bank_id": "sample-supplier", "label": "Supplier"}).status_code == 201
                proposal = control.post("/v1/control-changes", headers=bearer("operator"), json={
                    "action": "account_limits", "account_id": "checking", "reason": "Approved bank risk policy",
                    "limits": {"per_payment_minor": 50000, "rolling_day_minor": 100000,
                               "max_pending_minor": 100000, "require_review": False}})
                assert proposal.status_code == 201
                change = proposal.json()
                assert control.post(f"/v1/control-changes/{change['id']}/review", headers=bearer("reviewer"),
                    json={"decision": "approve", "request_hash": change["request_hash"]}).status_code == 200
                policy = MandateRequest(agent_id=registered.json()["id"], account_id="checking", payees=["supplier"],
                    permissions=["payments:create", "payments:read"], currency="GBP", per_payment_minor=50000,
                    budget_minor=100000, review_above_minor=20000, expires_at=int(time.time()) + 3600).model_dump()
                assert control.post("/v1/mandates", headers=bearer("customer"), json=policy).status_code == 403
                receipt = bearer("customer", scout_action="grant_mandate", scout_policy_sha256=digest(canonical(policy)),
                                 auth_time=int(time.time()), jti=secrets.token_urlsafe(24))
                granted = control.post("/v1/mandates", headers=receipt, json=policy)
                assert granted.status_code == 201
                assert control.post("/v1/mandates", headers=receipt, json=policy).status_code == 409
                mandate = granted.json()["id"]
                token = control.post(f"/v1/mandates/{mandate}/tokens", headers=bearer("customer")).json()["access_token"]
                with ScoutClient(origin, token, agent_key, ca_file=pki["ca"]) as agent:
                    payload = {"mandate_id": mandate, "payee_id": "supplier", "amount_minor": 5000, "currency": "GBP", "reference": "Invoice 101"}
                    payment = agent.create_payment(payload, "invoice_101_payment_v1")
                    assert payment["status"] == "queued"
                    assert agent.create_payment(payload, "invoice_101_payment_v1")["id"] == payment["id"]
                    bank = HTTPBankAdapter(connector)
                    try:
                        worker = Worker(service, bank)
                        assert worker.dispatch_one() == payment["id"]
                        assert agent.get_payment(payment["id"])["status"] == "settled"
                        assert worker.dispatch_one() is None
                    finally:
                        bank.close()
                overview = control.get("/v1/overview", headers=bearer("auditor"))
                assert overview.status_code == 200
                assert overview.headers["strict-transport-security"] == "max-age=31536000"
                assert overview.json()["mandates"][0]["budget_remaining"] == 95000
                assert control.get("/v1/journal/verify", headers=bearer("auditor")).json()["integrity"] == "verified"
                assert service.store.rows("SELECT bank_id FROM accounts")[0]["bank_id"].startswith("sbv1.")
        with sqlite3.connect(bank_db) as db:
            assert db.execute("SELECT count(*) FROM records").fetchone()[0] == 1
            assert db.execute("SELECT amount FROM balance").fetchone()[0] == 9995000
        # The actual TLS handshake must reject callers without a client certificate.
        with httpx.Client(verify=ssl.create_default_context(cafile=pki["ca"]), trust_env=False, timeout=3) as unsigned:
            with pytest.raises(httpx.HTTPError):
                unsigned.get(bank_url + "/payments/by-idempotency/missing")
        # A trusted client certificate must not bypass server certificate verification.
        bad = HTTPBankAdapter({k: v for k, v in connector.items() if k != "ca_file"})
        try:
            assert bad.lookup({"id": "missing", "request_hash": "a" * 64}).status == "unknown"
        finally:
            bad.close()
