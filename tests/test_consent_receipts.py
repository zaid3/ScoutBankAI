import json
import secrets
from dataclasses import replace

import pytest

from scoutbankai.crypto import canonical, digest
from scoutbankai.errors import BridgeError
from scoutbankai.models import MandateRequest


def integrated_policy(env):
    service = env["service"]
    policy = MandateRequest(**json.loads(service.store.rows("SELECT policy FROM mandates")[0]["policy"]))
    # Exercise the integrated service boundary; issuer-signature checks have separate tests.
    service.settings.mode = "integrated"
    principal = replace(env["a"]["customer"], consent_hash=digest(canonical(policy.model_dump())),
                        consent_time=service.clock(), consent_id=secrets.token_urlsafe(24))
    return service, policy, principal


def test_plain_customer_session_cannot_grant_agent_authority(env):
    service, policy, _ = integrated_policy(env)
    with pytest.raises(BridgeError, match="bank_consent_receipt_required"):
        service.create_mandate(env["a"]["customer"], policy)


def test_signed_exact_consent_can_be_consumed_only_once(env):
    service, policy, principal = integrated_policy(env)
    assert service.create_mandate(principal, policy)["status"] == "active"
    with pytest.raises(BridgeError, match="consent_receipt_already_used"):
        service.create_mandate(principal, policy)


def test_consent_cannot_expand_budget(env):
    service, policy, principal = integrated_policy(env)
    larger = policy.model_copy(update={"budget_minor": policy.budget_minor + 1})
    with pytest.raises(BridgeError, match="bank_consent_receipt_required"):
        service.create_mandate(principal, larger)


@pytest.mark.parametrize("seconds", [-301, 11])
def test_old_or_future_consent_is_rejected(env, seconds):
    service, policy, principal = integrated_policy(env)
    with pytest.raises(BridgeError, match="bank_consent_receipt_required"):
        service.create_mandate(replace(principal, consent_time=service.clock() + seconds), policy)

