from __future__ import annotations

import json
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from ...provenance import Confidence
from ..schema import (
    ThreatApplicabilityScope,
    ThreatSeverity,
    ThreatSourceType,
)
from .provenance import AdvisoryDocumentProvenance, AIInterpretationProvenance


class DeterministicModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", protected_namespaces=())

    def to_deterministic_json(self) -> str:
        def canonical(value: object) -> object:
            if isinstance(value, dict):
                return {key: canonical(item) for key, item in value.items()}
            if isinstance(value, list):
                items = [canonical(item) for item in value]
                return sorted(
                    items,
                    key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
                )
            return value

        return json.dumps(
            canonical(self.model_dump(mode="json")),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n"


class ThreatActivityState(str, Enum):
    UNKNOWN = "unknown"
    THEORETICAL = "theoretical"
    OBSERVED = "observed"
    ACTIVELY_EXPLOITED = "actively_exploited"


class AdvisoryContentFormat(str, Enum):
    PLAIN_TEXT = "plain_text"
    MARKDOWN = "markdown"
    HTML_TEXT = "html_text"
    JSON_TEXT = "json_text"


class EvidenceSupportType(str, Enum):
    EXPLICITLY_STATED = "explicitly_stated"
    STRONGLY_IMPLIED = "strongly_implied"
    INFERRED = "inferred"
    EXTERNAL_MODEL_KNOWLEDGE = "external_model_knowledge"


class ThreatAdvisoryDocument(DeterministicModel):
    document_id: str = Field(min_length=1)
    source_type: ThreatSourceType
    source_name: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    published_at: datetime | None = None
    retrieved_at: datetime | None = None
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    title: str = Field(min_length=1)
    content: str = Field(min_length=1)
    content_format: AdvisoryContentFormat
    provenance: AdvisoryDocumentProvenance


class InterpretationEvidenceAssertion(DeterministicModel):
    assertion_id: str = Field(min_length=1)
    assertion_type: str = Field(min_length=1)
    value: str = Field(min_length=1)
    source_locator: str = Field(min_length=1)
    evidence_excerpt_hash: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    support_type: EvidenceSupportType
    confidence: Confidence
    explicitly_stated: bool
    inference_required: bool


class AIContractFindingSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class AIContractFinding(DeterministicModel):
    code: str = Field(min_length=1)
    severity: AIContractFindingSeverity
    object_id: str = Field(min_length=1)
    message: str = Field(min_length=1)
    assertion_id: str | None = None

    @property
    def blocking(self) -> bool:
        return self.severity == AIContractFindingSeverity.ERROR


class ProposedThreatInterpretation(DeterministicModel):
    """Untrusted AI output. Validation never implies approval or participation."""

    interpretation_id: str = Field(min_length=1)
    interpretation_revision: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    model_provider: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    model_version: str = Field(min_length=1)
    prompt_id: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    generated_at: datetime
    input_document_id: str = Field(min_length=1)
    input_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    source_type: ThreatSourceType
    source_name: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    published_at: datetime | None = None
    observed_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    proposed_confidence: Confidence
    proposed_severity: ThreatSeverity
    proposed_activity_state: ThreatActivityState
    proposed_threat_scenario_ids: tuple[str, ...] = ()
    proposed_technique_ids: tuple[str, ...] = ()
    proposed_attack_path_ids: tuple[str, ...] = ()
    proposed_affected_technology_families: tuple[str, ...] = ()
    proposed_targeted_asset_classes: tuple[str, ...] = ()
    proposed_applicability_scope: ThreatApplicabilityScope
    evidence_assertions: tuple[InterpretationEvidenceAssertion, ...] = ()
    uncertainty_notes: tuple[str, ...] = ()
    unsupported_claims: tuple[str, ...] = ()
    provenance: AIInterpretationProvenance
    contract_findings: tuple[AIContractFinding, ...] = ()


class InterpretationValidationResult(DeterministicModel):
    interpretation_id: str
    capped_confidence: Confidence
    findings: tuple[AIContractFinding, ...] = ()

    @property
    def blocking(self) -> bool:
        return any(item.blocking for item in self.findings)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REVISION = "needs_revision"


class ApprovalModification(DeterministicModel):
    field_name: str = Field(min_length=1)
    value: str
    rationale: str = Field(min_length=1)


class ThreatInterpretationApproval(DeterministicModel):
    approval_id: str = Field(min_length=1)
    interpretation_id: str = Field(min_length=1)
    interpretation_revision: str = Field(min_length=1)
    threat_context_id: str | None = None
    threat_context_revision: str = "1"
    status: ApprovalStatus = ApprovalStatus.PENDING
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    accepted_assertion_ids: tuple[str, ...] = ()
    rejected_assertion_ids: tuple[str, ...] = ()
    modifications: tuple[ApprovalModification, ...] = ()
    rationale: str = "Pending human review."


__all__ = [
    "AIContractFinding",
    "AIContractFindingSeverity",
    "AdvisoryContentFormat",
    "ApprovalModification",
    "ApprovalStatus",
    "DeterministicModel",
    "EvidenceSupportType",
    "InterpretationEvidenceAssertion",
    "InterpretationValidationResult",
    "ProposedThreatInterpretation",
    "ThreatActivityState",
    "ThreatAdvisoryDocument",
    "ThreatInterpretationApproval",
]
