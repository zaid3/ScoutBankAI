import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .auth import Principal
from .config import Settings
from .crypto import canonical, digest, new_key, proof, public_jwk
from .models import AccountRegistration, AgentRegistration, MandateRequest, PaymentRequest, PayeeRegistration
from .service import Service


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(data.encode() if isinstance(data, str) else data)


def initialize(directory, origin="http://127.0.0.1:8090", tenant="sample-bank"):
    path = Path(directory).resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(path.iterdir()):
        raise ValueError("Choose an empty state directory; existing state is never overwritten")
    path.chmod(0o700)
    private_write(path / "audit.key", secrets.token_bytes(32))
    private_write(path / "nonce.key", secrets.token_bytes(32))
    config = {"database": "scout.db", "audit_key_file": "audit.key", "nonce_key_file": "nonce.key",
              "origin": origin, "mode": "development",
              "connector": {"base_url": "http://127.0.0.1:8091", "token_file": str(path / "bank-token.key")},
              "supervisor": {"mode": "rules"}}
    private_write(path / "config.json", json.dumps(config, indent=2))
    private_write(path / "bank-token.key", secrets.token_urlsafe(48))
    settings = Settings.load(str(path / "config.json"))
    service = Service(settings)
    credentials = {}
    with service.store.transaction() as db:
        db.execute("INSERT INTO tenants(id) VALUES(?)", (tenant,))
        for role in ("operator", "customer", "reviewer", "auditor"):
            token = secrets.token_urlsafe(48)
            subject = role + "-sample"
            db.execute("INSERT INTO principals VALUES(?,?,?,?,?)", (digest(token), tenant, subject, role, service.clock() + 86400))
            credentials[role] = token
    private_write(path / "credentials.json", json.dumps(credentials, indent=2))
    return settings, service, credentials


def sample_authority(service, credentials, budget=100_000, limit=50_000, review=20_000):
    operator = service.auth.authenticate(credentials["operator"], {"operator"})
    customer = service.auth.authenticate(credentials["customer"], {"customer"})
    suffix = secrets.token_hex(4)
    key = new_key()
    agent = service.register_agent(operator, AgentRegistration(name="Invoice assistant", owner=customer.subject, public_jwk=public_jwk(key)))
    account = "account_" + suffix
    payee = "supplier_" + suffix
    service.register_account(operator, AccountRegistration(id=account, customer=customer.subject, bank_id="sample-checking", currency="GBP"))
    service.register_payee(operator, PayeeRegistration(id=payee, bank_id="sample-supplier", label="Sample supplier"))
    mandate = service.create_mandate(customer, MandateRequest(agent_id=agent["id"], account_id=account,
        permissions=["payments:create", "payments:read"], payees=[payee], currency="GBP",
        per_payment_minor=limit, budget_minor=budget, review_above_minor=review,
        expires_at=service.clock() + 3600, max_payments_per_minute=100))
    token = service.mint_token(customer, mandate["id"])["access_token"]
    return {"key": key, "agent": agent["id"], "mandate": mandate["id"], "token": token,
            "payee": payee, "account": account, "operator": operator, "customer": customer}


def submit_sample(service, authority, amount=5000, idempotency=None, **changes):
    model = PaymentRequest(mandate_id=authority["mandate"], payee_id=authority["payee"], amount_minor=amount,
                           currency="GBP", reference="Sample invoice", **changes)
    raw = canonical(model.model_dump())
    idem = idempotency or secrets.token_urlsafe(24)
    encoded = proof(authority["key"], authority["token"], "POST", service.settings.origin + "/v1/payments", raw,
                    service.nonce(authority["token"]), idem, now=service.clock())
    return service.create_payment(authority["token"], encoded, raw, idem, model)

