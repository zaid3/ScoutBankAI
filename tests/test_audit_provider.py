import json

import httpx
import pytest

from scoutbankai.auditors import OpenAIAuditor
from scoutbankai.crypto import canonical, digest


CONTEXT = {"amount_minor": 5000, "currency": "GBP", "review_above_minor": 10000,
           "payments_last_minute": 1, "remaining_budget_minor": 95000,
           "account_requires_review": False, "supervisor_requires_review": False}
PACKET = {"role": "policy", "round": 1, "context": CONTEXT,
          "context_hash": digest(canonical(CONTEXT)), "peers": []}
REPORT = {"context_hash": PACKET["context_hash"], "require_review": False, "finding_codes": [],
          "summary": "No threshold trigger in the supplied metadata.", "peer_checks": []}


def envelope(report):
    return {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps(report)}]}]}


def test_model_audit_uses_fixed_origin_strict_schema_and_no_bank_authority(monkeypatch):
    monkeypatch.setenv("SCOUT_TEST_AUDITOR_TOKEN", "fixture-only-key")
    def handler(request):
        assert str(request.url) == "https://api.openai.com/v1/responses"
        assert request.headers["Authorization"] == "Bearer fixture-only-key"
        body = json.loads(request.content)
        assert body["model"] == "approved-test-model" and body["store"] is False
        assert body["text"]["format"]["strict"] is True and "tools" not in body
        assert body["text"]["format"]["schema"]["additionalProperties"] is False
        assert json.loads(body["input"]) == PACKET
        assert "fixture-only-key" not in body["input"]
        return httpx.Response(200, json=envelope(REPORT))
    provider = OpenAIAuditor("policy", "approved-test-model", "SCOUT_TEST_AUDITOR_TOKEN", httpx.MockTransport(handler))
    assert provider.assess(PACKET).model_dump() == REPORT


def test_missing_model_key_does_not_make_a_network_request(monkeypatch):
    monkeypatch.delenv("SCOUT_TEST_AUDITOR_TOKEN", raising=False)
    provider = OpenAIAuditor("policy", "model", "SCOUT_TEST_AUDITOR_TOKEN", httpx.MockTransport(lambda r: pytest.fail("no key, no network")))
    with pytest.raises(RuntimeError, match="audit_provider_unavailable"):
        provider.assess(PACKET)


@pytest.mark.parametrize("body", [
    {"status": "incomplete"}, {"status": "completed", "output": []},
    {"status": "completed", "output": [{"type": "message", "content": [{"type": "refusal", "refusal": "Cannot assess"}]}]},
    envelope({**REPORT, "execute_payment": True}), envelope({**REPORT, "require_review": "false"}),
    envelope({**REPORT, "require_review": True}), envelope({**REPORT, "finding_codes": ["invented_code"]}),
])
def test_invalid_or_refused_model_audit_is_rejected(monkeypatch, body):
    monkeypatch.setenv("SCOUT_TEST_AUDITOR_TOKEN", "fixture-only-key")
    provider = OpenAIAuditor("policy", "model", "SCOUT_TEST_AUDITOR_TOKEN", httpx.MockTransport(lambda r: httpx.Response(200, json=body)))
    with pytest.raises(ValueError):
        provider.assess(PACKET)


@pytest.mark.parametrize("response", [httpx.Response(302, headers={"Location": "https://unapproved.invalid/"}),
                                      httpx.Response(429), httpx.Response(503),
                                      httpx.Response(200, content=b"x" * 100001),
                                      httpx.Response(200, content=b'{"status":"completed","status":"incomplete"}')])
def test_redirect_errors_oversize_and_ambiguous_json_fail_closed(monkeypatch, response):
    monkeypatch.setenv("SCOUT_TEST_AUDITOR_TOKEN", "fixture-only-key")
    calls = []
    def handler(request):
        calls.append(request)
        return response
    provider = OpenAIAuditor("policy", "model", "SCOUT_TEST_AUDITOR_TOKEN", httpx.MockTransport(handler))
    with pytest.raises((ValueError, httpx.HTTPError)):
        provider.assess(PACKET)
    assert len(calls) == 1
