from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$")]
Money = Annotated[int, Field(strict=True, ge=1, le=1_000_000_000_000)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AgentRegistration(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=80)]
    public_jwk: dict
    owner: Identifier


class AccountRegistration(StrictModel):
    id: Identifier
    customer: Identifier
    bank_id: Identifier
    currency: Literal["GBP", "EUR", "USD"]


class PayeeRegistration(StrictModel):
    id: Identifier
    bank_id: Identifier
    label: Annotated[str, Field(min_length=1, max_length=80)]


class MandateRequest(StrictModel):
    agent_id: Identifier
    account_id: Identifier
    permissions: Annotated[list[Literal["payments:create", "payments:read"]], Field(min_length=1, max_length=2)]
    payees: Annotated[list[Identifier], Field(min_length=1, max_length=100)]
    currency: Literal["GBP", "EUR", "USD"]
    per_payment_minor: Money
    budget_minor: Money
    review_above_minor: Money
    expires_at: Annotated[int, Field(strict=True, gt=0)]
    max_payments_per_minute: Annotated[int, Field(strict=True, ge=1, le=100)] = 10

    @model_validator(mode="after")
    def limits(self):
        if self.per_payment_minor > self.budget_minor:
            raise ValueError("per_payment_minor must not exceed budget_minor")
        if len(set(self.payees)) != len(self.payees) or len(set(self.permissions)) != len(self.permissions):
            raise ValueError("duplicate payees or permissions")
        return self


class PaymentRequest(StrictModel):
    mandate_id: Identifier
    payee_id: Identifier
    amount_minor: Money
    currency: Literal["GBP", "EUR", "USD"]
    reference: Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 ._/-]+$")]


class ReviewRequest(StrictModel):
    decision: Literal["approve", "reject"]
    request_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class PauseRequest(StrictModel):
    paused: bool


class Advisory(StrictModel):
    require_review: bool
    reason: Literal["routine", "unusual_pattern", "insufficient_context", "provider_unavailable"]

