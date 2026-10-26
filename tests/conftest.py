import secrets

import pytest
from fastapi.testclient import TestClient

from scoutbankai.api import create_app
from scoutbankai.bootstrap import initialize, sample_authority
from scoutbankai.crypto import canonical, proof


@pytest.fixture
def env(tmp_path):
    settings, service, credentials = initialize(tmp_path / "state", origin="http://testserver")
    authority = sample_authority(service, credentials)
    client = TestClient(create_app(settings, service))
    return {"settings": settings, "service": service, "credentials": credentials, "a": authority, "client": client}


def request_payment(env, amount=5000, *, changes=None, token=None, key=None, idem=None, claims=None):
    a, service = env["a"], env["service"]
    body = {"mandate_id": a["mandate"], "payee_id": a["payee"], "amount_minor": amount, "currency": "GBP", "reference": "Invoice 101"}
    body.update(changes or {})
    raw = canonical(body)
    token = token or a["token"]
    idem = idem or secrets.token_urlsafe(24)
    nonce = service.nonce(token)
    arguments = {"key": key or a["key"], "token": token, "method": "POST", "url": service.settings.origin + "/v1/payments",
                 "body": raw, "nonce": nonce, "idempotency_key": idem, "now": service.clock()}
    arguments.update(claims or {})
    signed = proof(**arguments)
    headers = {"Authorization": "DPoP " + token, "DPoP": signed, "Idempotency-Key": idem, "Content-Type": "application/json"}
    return raw, headers


def post_payment(env, **kwargs):
    body, headers = request_payment(env, **kwargs)
    return env["client"].post("/v1/payments", content=body, headers=headers)


def bearer(env, role):
    return {"Authorization": "Bearer " + env["credentials"][role]}

