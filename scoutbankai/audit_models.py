"""Bounded data contracts for cross-audits and independent evaluation."""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .models import Money, StrictModel

AuditRole = Literal["policy", "evidence", "challenge"]
ROLES = ("policy", "evidence", "challenge")
Finding = Literal["threshold_exceeded", "account_review_required", "supervisor_review_required",
                  "budget_near_limit", "high_velocity", "unusual_pattern", "insufficient_context", "peer_disagreement"]
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CouncilConfig(StrictModel):
    mode: Literal["rules", "openai"] = "rules"
    rounds: Annotated[int, Field(ge=2, le=3)] = 2
    models: dict[str, str] = Field(default_factory=dict)
    token_env: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,79}$")] = "OPENAI_API_KEY"
    max_concurrent_audits: Annotated[int, Field(ge=1, le=8)] = 4

    @model_validator(mode="after")
    def explicit_models(self):
        if self.mode == "openai" and (set(self.models) != set(ROLES) or any(not m.strip() or len(m) > 128 for m in self.models.values())):
            raise ValueError("configure an explicit approved model for each audit role")
        if self.mode == "rules" and self.models:
            raise ValueError("rules mode does not use model IDs")
        return self


class AuditContext(StrictModel):
    amount_minor: Money
    currency: Literal["GBP", "EUR", "USD"]
    review_above_minor: Money
    payments_last_minute: Annotated[int, Field(ge=0, le=1000)]
    remaining_budget_minor: Annotated[int, Field(ge=0, le=1_000_000_000_000)]
    account_requires_review: bool
    supervisor_requires_review: bool


class PeerCheck(StrictModel):
    role: AuditRole
    report_hash: Hash
    verdict: Literal["supported", "challenge", "uncertain"]


class AuditReport(StrictModel):
    context_hash: Hash
    require_review: bool
    finding_codes: Annotated[list[Finding], Field(max_length=8)]
    summary: Annotated[str, Field(min_length=1, max_length=320)]
    peer_checks: Annotated[list[PeerCheck], Field(max_length=2)]

    @model_validator(mode="after")
    def coherent(self):
        if len(self.finding_codes) != len(set(self.finding_codes)):
            raise ValueError("duplicate findings")
        if self.require_review != bool(self.finding_codes):
            raise ValueError("review decision must have a finding")
        if any(p.verdict != "supported" for p in self.peer_checks) and "peer_disagreement" not in self.finding_codes:
            raise ValueError("peer challenge must remain visible")
        return self


class AuditFeedback(StrictModel):
    result_hash: Hash
    review_required: bool
    confirmed_findings: Annotated[list[Finding], Field(max_length=8)]
    evidence_reference: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_./:# -]{4,159}$")]
    explanation: Annotated[str, Field(min_length=10, max_length=500)]

    @model_validator(mode="after")
    def coherent(self):
        if len(self.confirmed_findings) != len(set(self.confirmed_findings)):
            raise ValueError("duplicate labels")
        if self.review_required != bool(self.confirmed_findings):
            raise ValueError("review label must have a confirmed finding")
        return self
