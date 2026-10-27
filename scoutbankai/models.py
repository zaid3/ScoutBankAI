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


class CancelPaymentRequest(StrictModel):
    request_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    reason: Annotated[str, Field(min_length=5, max_length=240)]


class RestoreControlRequest(StrictModel):
    source_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    expected_version: Annotated[int, Field(ge=0)]
    reason: Annotated[str, Field(min_length=5, max_length=240)]


class TimelineQuery(StrictModel):
    actor: Annotated[str, Field(min_length=1, max_length=160)] | None = None
    action: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,95}$")] | None = None
    object_id: Identifier | None = None
    from_time: Annotated[int, Field(ge=0, le=253402300799)] | None = None
    to_time: Annotated[int, Field(ge=0, le=253402300799)] | None = None
    before_seq: Annotated[int, Field(ge=1)] | None = None
    snapshot_seq: Annotated[int, Field(ge=0)] | None = None
    limit: Annotated[int, Field(ge=1, le=100)] = 50

    @model_validator(mode="after")
    def ordered_dates(self):
        if self.from_time is not None and self.to_time is not None and self.from_time > self.to_time:
            raise ValueError("from_time must not follow to_time")
        return self


class Advisory(StrictModel):
    require_review: bool
    reason: Literal["routine", "unusual_pattern", "insufficient_context", "provider_unavailable"]


class AccountLimits(StrictModel):
    per_payment_minor: Money
    rolling_day_minor: Money
    max_pending_minor: Money
    max_payments_per_minute: Annotated[int, Field(strict=True, ge=1, le=1000)] = 10
    max_request_age_seconds: Annotated[int, Field(strict=True, ge=30, le=3600)] = 900
    require_review: bool = True

    @model_validator(mode="after")
    def consistent(self):
        if self.per_payment_minor > min(self.rolling_day_minor, self.max_pending_minor):
            raise ValueError("per-payment limit cannot exceed the aggregate limits")
        return self


class ControlProposal(StrictModel):
    action: Literal["account_limits", "resume_bank", "unfreeze_account"]
    account_id: Identifier | None = None
    limits: AccountLimits | None = None
    reason: Annotated[str, Field(min_length=5, max_length=240)]

    @model_validator(mode="after")
    def correct_target(self):
        if self.action == "resume_bank":
            if self.account_id is not None or self.limits is not None:
                raise ValueError("resume applies only to the tenant")
        elif self.account_id is None or ((self.action == "account_limits") != (self.limits is not None)):
            raise ValueError("account and limits must match the requested action")
        return self

