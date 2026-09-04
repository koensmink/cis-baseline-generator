from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cis_pdf2csv.source_identity import SourceIdentity


class AssessmentStatus(str, Enum):
    DECLARED_COMPLIANT = "declared_compliant"
    DECLARED_NON_COMPLIANT = "declared_non_compliant"
    POTENTIAL_CONFLICT = "potential_conflict"
    NOT_APPLICABLE = "not_applicable"
    NOT_MEASURABLE = "not_measurable"
    MANUAL_EVIDENCE_REQUIRED = "manual_evidence_required"
    EXCEPTION_ACTIVE = "exception_active"


class ValueComparison(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"
    NOT_PERFORMED = "not_performed"


class ExceptionDecision(str, Enum):
    EXCEPTION_ACTIVE = "exception_active"
    NOT_APPLICABLE = "not_applicable"


class ExceptionRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    control_id: str = Field(min_length=1)
    decision: ExceptionDecision
    rationale: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    expires_at: datetime
    benchmark_name: str | None = None
    benchmark_version: str | None = None
    compensating_controls: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_timezone(self) -> ExceptionRecord:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must include a timezone offset")
        return self


class ControlAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_identity: SourceIdentity
    control_id: str
    title: str
    profile: str
    assessment: str
    status: AssessmentStatus
    comparison: ValueComparison
    desired_value: str | None = None
    observed_values: tuple[str, ...] = ()
    observed_setting_identities: tuple[str, ...] = ()
    policy_ids: tuple[str, ...] = ()
    policy_names: tuple[str, ...] = ()
    mapping_status: str
    mapping_identifier: str | None = None
    reason_codes: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    exception: ExceptionRecord | None = None


class BaselineAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.0"
    assessed_at_utc: str
    current_state_sha256: str
    current_state_status: str
    current_state_source: str
    effective_state_observed: bool
    controls: tuple[ControlAssessment, ...]
    status_counts: dict[str, int]
    warnings: tuple[str, ...] = ()
