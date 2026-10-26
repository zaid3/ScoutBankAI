import json

import httpx
import pytest

from scoutbankai.connectors import HTTPBankAdapter
from scoutbankai.models import Advisory
from scoutbankai.supervisor import OpenAISupervisor


WIRE = {"id": "pay_123", "tenant": "bank1", "request_hash": "a" * 64, "debtor_account": "owned-account", "creditor_account": "verified-payee", "amount_minor": 5000, "currency": "GBP", "reference": "Invoice"}


def adapter(monkeypatch, handler):
    monkeypatch.setenv("SCOUT_BANK_TOKEN", "bank-owned-credential")
    return HTTPBankAdapter({"base_url": "https://bank.example/v1"}, transport=httpx.MockTransport(handler))


def test_bank_adapter_uses_separate_credentials_and_stable_idempotency(monkeypatch):
    def handler(request):
        assert str(request.url) == "https://bank.example/v1/payments"
        assert request.headers["Authorization"] == "Bearer bank-owned-credential"
        assert request.headers["Idempotency-Key"] == WIRE["id"]
        assert json.loads(request.content) == WIRE
        return httpx.Response(201, json={"status": "settled", "bank_id": "tx_1", "idempotency_key": WIRE["id"], "request_hash": WIRE["request_hash"]})
    with_adapter = adapter(monkeypatch, handler)
    assert with_adapter.submit(WIRE).status == "settled"
    with_adapter.close()


@pytest.mark.parametrize("status_code", [301, 302, 400, 401, 404, 409, 429, 500, 503])
def test_unconfirmed_http_response_never_releases_money(monkeypatch, status_code):
    a = adapter(monkeypatch, lambda req: httpx.Response(status_code, headers={"location": "https://untrusted.example"}, json={"status": "rejected"}))
    assert a.submit(WIRE).status == "unknown"
    a.close()


@pytest.mark.parametrize("bad", [{"request_hash": "wrong"}, {"idempotency_key": "wrong"}, {"status": "anything"}, {"bank_id": "https://bad.example"}])
def test_bank_response_is_bound_to_exact_request(monkeypatch, bad):
    result = {"status": "settled", "bank_id": "tx_1", "idempotency_key": WIRE["id"], "request_hash": WIRE["request_hash"], **bad}
    a = adapter(monkeypatch, lambda req: httpx.Response(200, json=result))
    assert a.submit(WIRE).status == "unknown"
    a.close()


def test_oversized_bank_response_is_unknown(monkeypatch):
    a = adapter(monkeypatch, lambda req: httpx.Response(200, content=b"x" * 65537))
    assert a.submit(WIRE).status == "unknown"
    a.close()


def test_missing_bank_token_fails_closed(monkeypatch):
    monkeypatch.delenv("SCOUT_BANK_TOKEN", raising=False)
    a = HTTPBankAdapter({"base_url": "https://bank.example"}, transport=httpx.MockTransport(lambda req: pytest.fail("no credential should mean no network call")))
    assert a.submit(WIRE).status == "unknown"
    a.close()


@pytest.mark.parametrize("url", ["http://bank.example", "https://user:pass@bank.example", "https://bank.example?token=secret", "file:///etc/passwd"])
def test_integrated_connector_rejects_insecure_origins(url):
    with pytest.raises(ValueError):
        HTTPBankAdapter({"base_url": url}, transport=httpx.MockTransport(lambda req: None))


def test_model_is_advisory_and_receives_no_tokens(monkeypatch):
    monkeypatch.setenv("TEST_MODEL_TOKEN", "model-key")
    def handler(request):
        data = json.loads(request.content)
        assert data["store"] is False
        assert "tools" not in data
        assert "private" not in data["input"] and "token" not in data["input"]
        return httpx.Response(200, json={"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": '{"require_review":true,"reason":"unusual_pattern"}'}]}]})
    advisor = OpenAISupervisor("configured-model", "TEST_MODEL_TOKEN", httpx.MockTransport(handler))
    assert advisor.assess({"amount_minor": 5000}).require_review is True


@pytest.mark.parametrize("body", [{"status": "incomplete"}, {"status": "completed", "output": []}, {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": '{"require_review":false,"reason":"routine","execute":true}'}]}]}])
def test_invalid_model_output_requires_review(monkeypatch, body):
    monkeypatch.setenv("TEST_MODEL_TOKEN", "model-key")
    advisor = OpenAISupervisor("configured-model", "TEST_MODEL_TOKEN", httpx.MockTransport(lambda req: httpx.Response(200, json=body)))
    assert advisor.assess({}).reason == "provider_unavailable"

