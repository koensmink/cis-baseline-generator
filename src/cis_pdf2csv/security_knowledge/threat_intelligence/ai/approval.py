from __future__ import annotations

from datetime import datetime

from ...provenance import Confidence, LifecycleStatus
from ..provenance import ThreatContextProvenance, ThreatEvidenceProvenance
from ..schema import (
    ThreatApplicabilityScope,
    ThreatContext,
    ThreatEvidence,
    ThreatEvidenceType,
    ThreatSeverity,
)
from .schema import (
    AIContractFinding,
    AIContractFindingSeverity,
    ApprovalStatus,
    InterpretationValidationResult,
    ProposedThreatInterpretation,
    ThreatAdvisoryDocument,
    ThreatInterpretationApproval,
)


class InterpretationApprovalError(ValueError):
    code = "AI_INTERPRETATION_NOT_APPROVED"


_MODIFIABLE = {
    "title",
    "summary",
    "proposed_confidence",
    "proposed_severity",
    "valid_from",
    "valid_until",
    "proposed_applicability_scope",
}


def build_threat_context_from_approved_interpretation(
    interpretation: ProposedThreatInterpretation,
    document: ThreatAdvisoryDocument,
    approval: ThreatInterpretationApproval,
    validation: InterpretationValidationResult,
) -> ThreatContext:
    """Convert only an explicitly approved, non-blocking proposal."""
    approval_findings = validate_interpretation_approval(
        interpretation, approval, validation
    )
    if approval_findings:
        raise InterpretationApprovalError(
            f"{approval_findings[0].code}: {approval_findings[0].message}"
        )
    if (
        approval.status != ApprovalStatus.APPROVED
        or approval.interpretation_id != interpretation.interpretation_id
        or approval.interpretation_revision != interpretation.interpretation_revision
        or validation.interpretation_id != interpretation.interpretation_id
        or validation.blocking
        or not approval.reviewed_by
        or approval.reviewed_at is None
        or not approval.threat_context_id
    ):
        raise InterpretationApprovalError(
            "AI_INTERPRETATION_NOT_APPROVED: conversion requires matching explicit approval and non-blocking validation"
        )
    if set(approval.accepted_assertion_ids) & set(approval.rejected_assertion_ids):
        raise InterpretationApprovalError("accepted and rejected assertions overlap")
    assertion_index = {item.assertion_id: item for item in interpretation.evidence_assertions}
    if not set(approval.accepted_assertion_ids).issubset(assertion_index):
        raise InterpretationApprovalError("approval references an unknown assertion")
    invalid_modifications = sorted(
        item.field_name for item in approval.modifications if item.field_name not in _MODIFIABLE
    )
    if invalid_modifications:
        raise InterpretationApprovalError(
            f"approval contains forbidden modifications: {', '.join(invalid_modifications)}"
        )

    modifications = {item.field_name: item.value for item in approval.modifications}
    accepted = [assertion_index[value] for value in sorted(set(approval.accepted_assertion_ids))]

    def accepted_values(kind: str) -> tuple[str, ...]:
        return tuple(sorted({item.value for item in accepted if item.assertion_type == kind}))

    confidence = _minimum(
        Confidence(modifications.get("proposed_confidence", interpretation.proposed_confidence.value)),
        validation.capped_confidence,
    )
    evidence = tuple(
        ThreatEvidence(
            evidence_type=ThreatEvidenceType.ANALYST_ASSERTION,
            source=document.source_name,
            external_reference=f"{document.document_id}:{item.source_locator}:{item.assertion_id}",
            assertion=f"{item.assertion_type}={item.value}",
            confidence=_minimum(item.confidence, confidence),
            published_at=document.published_at,
            retrieved_at=document.retrieved_at,
            provenance=ThreatEvidenceProvenance(
                collection_method=f"approved_ai_proposal:{interpretation.interpretation_id}:{approval.approval_id}",
                source_revision=document.provenance.source_revision,
                retrieved_at=document.retrieved_at,
                analyst=approval.reviewed_by,
            ),
        )
        for item in accepted
    )
    return ThreatContext(
        threat_context_id=approval.threat_context_id,
        title=modifications.get("title", interpretation.title),
        description=modifications.get("summary", interpretation.summary),
        source_type=document.source_type,
        source_name=document.source_name,
        source_reference=document.source_reference,
        observed_at=interpretation.observed_at,
        published_at=document.published_at,
        valid_from=_datetime_modification(modifications, "valid_from", interpretation.valid_from),
        valid_until=_datetime_modification(modifications, "valid_until", interpretation.valid_until),
        confidence=confidence,
        severity=ThreatSeverity(
            modifications.get("proposed_severity", interpretation.proposed_severity.value)
        ),
        lifecycle_status=LifecycleStatus.ACTIVE,
        threat_scenario_ids=accepted_values("threat_scenario_id"),
        technique_ids=accepted_values("technique_id"),
        attack_path_ids=accepted_values("attack_path_id"),
        targeted_asset_classes=accepted_values("targeted_asset_class"),
        affected_technology_families=accepted_values("affected_technology_family"),
        applicability_scope=ThreatApplicabilityScope(
            modifications.get(
                "proposed_applicability_scope",
                interpretation.proposed_applicability_scope.value,
            )
        ),
        evidence=evidence,
        provenance=ThreatContextProvenance(
            authority=approval.reviewed_by,
            creation_method=(
                f"approved_interpretation:document={document.document_id};"
                f"interpretation={interpretation.interpretation_id};approval={approval.approval_id}"
            ),
            model_version=interpretation.schema_version,
            object_version=approval.threat_context_revision,
            created_at=approval.reviewed_at,
        ),
    )


def validate_interpretation_approval(
    interpretation: ProposedThreatInterpretation,
    approval: ThreatInterpretationApproval,
    validation: InterpretationValidationResult,
) -> tuple[AIContractFinding, ...]:
    reasons: list[str] = []
    if approval.status != ApprovalStatus.APPROVED:
        reasons.append(f"approval status is {approval.status.value}")
    if approval.interpretation_id != interpretation.interpretation_id:
        reasons.append("interpretation identity does not match")
    if approval.interpretation_revision != interpretation.interpretation_revision:
        reasons.append("interpretation revision does not match")
    if validation.interpretation_id != interpretation.interpretation_id:
        reasons.append("validation identity does not match")
    if validation.blocking:
        reasons.append("validation has blocking findings")
    if not approval.reviewed_by or approval.reviewed_at is None:
        reasons.append("reviewer identity and review time are required")
    if not approval.threat_context_id:
        reasons.append("target ThreatContext identity is required")
    if not reasons:
        return ()
    return (
        AIContractFinding(
            code="AI_INTERPRETATION_NOT_APPROVED",
            severity=AIContractFindingSeverity.ERROR,
            object_id=interpretation.interpretation_id,
            message="; ".join(sorted(reasons)) + ".",
        ),
    )


def _datetime_modification(
    modifications: dict[str, str], field: str, original: datetime | None
) -> datetime | None:
    value = modifications.get(field)
    return datetime.fromisoformat(value) if value is not None else original


def _minimum(left: Confidence, right: Confidence) -> Confidence:
    order = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    return left if order[left] <= order[right] else right


__all__ = [
    "InterpretationApprovalError",
    "build_threat_context_from_approved_interpretation",
    "validate_interpretation_approval",
]
