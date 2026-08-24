from __future__ import annotations

import json
from datetime import datetime
from hashlib import sha256

from pydantic import Field

from ...catalog.registry import SecurityKnowledgeCatalog
from ...identifiers import build_threat_context_id
from ..schema import ThreatContext
from .approval import (
    InterpretationApprovalError,
    build_threat_context_from_approved_interpretation,
    material_assertion_ids,
    validate_interpretation_approval,
)
from .contract import DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT
from .provenance import AdvisoryDocumentProvenance
from .schema import (
    AIContractFinding,
    ApprovalModification,
    ApprovalStatus,
    DeterministicModel,
    InterpretationValidationResult,
    ProposedThreatInterpretation,
    ThreatAdvisoryReference,
    ThreatInterpretationApproval,
)
from .validation import (
    validate_interpretation_catalog_references,
    validate_interpretation_payload,
)


class ProposalAuditWarning(DeterministicModel):
    code: str
    message: str


class ProposedInterpretationArtifact(DeterministicModel):
    provider: str
    model: str
    model_version: str | None = None
    request_id: str | None = None
    contract_id: str
    contract_version: str
    prompt_id: str
    prompt_version: str
    document_id: str
    document_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_version: str
    catalog_vocabulary_hash: str
    generation_parameter_identity: str
    raw_response_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    interpretation: ProposedThreatInterpretation
    validation: InterpretationValidationResult
    provider_warnings: tuple[ProposalAuditWarning, ...] = ()
    preflight_findings: tuple[AIContractFinding, ...] = ()


class ApprovalBlockedError(InterpretationApprovalError):
    code = "AI_INTERPRETATION_APPROVAL_BLOCKED"


class ApprovalWorkflowResult(DeterministicModel):
    artifact_hash: str
    approval: ThreatInterpretationApproval
    validation: InterpretationValidationResult
    threat_context: ThreatContext | None = None


def build_approval_id(
    interpretation: ProposedThreatInterpretation,
    *,
    reviewer: str,
    reviewed_at: datetime,
    status: ApprovalStatus,
    accepted_assertion_ids: tuple[str, ...],
    rejected_assertion_ids: tuple[str, ...],
    modifications: tuple[ApprovalModification, ...],
) -> str:
    payload = {
        "accepted": sorted(set(accepted_assertion_ids)),
        "interpretation_id": interpretation.interpretation_id,
        "interpretation_revision": interpretation.interpretation_revision,
        "modifications": sorted(
            (item.model_dump(mode="json") for item in modifications),
            key=lambda item: (item["field_name"], item["value"], item["rationale"]),
        ),
        "rejected": sorted(set(rejected_assertion_ids)),
        "reviewed_at": reviewed_at.isoformat(),
        "reviewer": reviewer,
        "status": status.value,
    }
    digest = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"AIAPP-{digest[:20].upper()}"


def review_proposed_interpretation(
    artifact: ProposedInterpretationArtifact,
    *,
    reviewer: str,
    reviewed_at: datetime,
    status: ApprovalStatus,
    accepted_assertion_ids: tuple[str, ...],
    rejected_assertion_ids: tuple[str, ...],
    modifications: tuple[ApprovalModification, ...],
    rationale: str,
    catalog: SecurityKnowledgeCatalog,
) -> ApprovalWorkflowResult:
    if not reviewer.strip():
        raise ValueError("reviewer identity is required")
    if reviewed_at.tzinfo is None or reviewed_at.utcoffset() is None:
        raise ValueError("reviewed_at must be timezone-aware")
    interpretation = artifact.interpretation
    _validate_artifact_identity(artifact)
    parsed, payload_findings = validate_interpretation_payload(
        interpretation.model_dump(mode="json")
    )
    if parsed is None:
        raise ValueError("proposal interpretation no longer satisfies the Phase 4A schema")
    current_catalog_findings = validate_interpretation_catalog_references(parsed, catalog)
    combined_findings = _merge_findings(
        artifact.validation.findings,
        payload_findings,
        current_catalog_findings,
    )
    validation = InterpretationValidationResult(
        interpretation_id=interpretation.interpretation_id,
        capped_confidence=artifact.validation.capped_confidence,
        findings=combined_findings,
    )
    accepted = tuple(sorted(set(accepted_assertion_ids)))
    rejected = tuple(sorted(set(rejected_assertion_ids)))
    ordered_modifications = tuple(
        sorted(
            modifications,
            key=lambda item: (item.field_name, item.value, item.rationale),
        )
    )
    approval_id = build_approval_id(
        interpretation,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
        status=status,
        accepted_assertion_ids=accepted,
        rejected_assertion_ids=rejected,
        modifications=ordered_modifications,
    )
    threat_context_id = (
        build_threat_context_id("approved-ai", approval_id)
        if status == ApprovalStatus.APPROVED
        else None
    )
    approval = ThreatInterpretationApproval(
        approval_id=approval_id,
        interpretation_id=interpretation.interpretation_id,
        interpretation_revision=interpretation.interpretation_revision,
        threat_context_id=threat_context_id,
        status=status,
        reviewed_by=reviewer,
        reviewed_at=reviewed_at,
        accepted_assertion_ids=accepted,
        rejected_assertion_ids=rejected,
        modifications=ordered_modifications,
        rationale=rationale,
    )
    artifact_hash = sha256(artifact.to_deterministic_json().encode()).hexdigest()
    _validate_decision_ids(interpretation, approval)
    if status != ApprovalStatus.APPROVED:
        return ApprovalWorkflowResult(
            artifact_hash=artifact_hash,
            approval=approval,
            validation=validation,
        )
    approval_findings = validate_interpretation_approval(
        interpretation, approval, validation
    )
    if approval_findings:
        raise ApprovalBlockedError(approval_findings[0].message)
    reference = ThreatAdvisoryReference(
        document_id=artifact.document_id,
        source_type=interpretation.source_type,
        source_name=interpretation.source_name,
        source_reference=interpretation.source_reference,
        content_hash=artifact.document_hash,
        published_at=interpretation.published_at,
        provenance=AdvisoryDocumentProvenance(
            supplied_by="cis-threat-interpret",
            collection_method="content_not_retained_in_proposal_artifact",
        ),
    )
    context = build_threat_context_from_approved_interpretation(
        interpretation, reference, approval, validation
    )
    return ApprovalWorkflowResult(
        artifact_hash=artifact_hash,
        approval=approval,
        validation=validation,
        threat_context=context,
    )


def _validate_decision_ids(
    interpretation: ProposedThreatInterpretation,
    approval: ThreatInterpretationApproval,
) -> None:
    known = {item.assertion_id for item in interpretation.evidence_assertions}
    accepted = set(approval.accepted_assertion_ids)
    rejected = set(approval.rejected_assertion_ids)
    if accepted & rejected:
        raise ValueError("the same assertion cannot be accepted and rejected")
    unknown = sorted((accepted | rejected) - known)
    if unknown:
        raise ValueError(f"unknown assertion IDs: {', '.join(unknown)}")


def _validate_artifact_identity(artifact: ProposedInterpretationArtifact) -> None:
    item = artifact.interpretation
    errors: list[str] = []
    if artifact.validation.interpretation_id != item.interpretation_id:
        errors.append("validation interpretation ID mismatch")
    if artifact.document_id != item.input_document_id:
        errors.append("document ID mismatch")
    if artifact.document_hash != item.input_hash:
        errors.append("document hash mismatch")
    if artifact.document_hash != item.provenance.input_document_hash:
        errors.append("provenance input hash mismatch")
    if artifact.provider != item.model_provider or artifact.model != item.model_name:
        errors.append("provider/model metadata mismatch")
    if artifact.contract_id != item.provenance.contract_id:
        errors.append("contract ID mismatch")
    if artifact.contract_version != item.provenance.contract_version:
        errors.append("contract version mismatch")
    if artifact.prompt_id != item.prompt_id or artifact.prompt_version != item.prompt_version:
        errors.append("prompt metadata mismatch")
    contract = DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT
    if artifact.contract_id != contract.contract_id or artifact.contract_version != contract.contract_version:
        errors.append("unsupported contract version")
    if errors:
        raise ValueError("invalid proposal artifact: " + "; ".join(sorted(errors)))


def _merge_findings(
    *groups: tuple[AIContractFinding, ...],
) -> tuple[AIContractFinding, ...]:
    indexed = {
        (item.code, item.severity.value, item.object_id, item.assertion_id, item.message): item
        for group in groups
        for item in group
    }
    return tuple(indexed[key] for key in sorted(indexed))


def material_decisions(
    artifact: ProposedInterpretationArtifact,
) -> tuple[str, ...]:
    return tuple(sorted(material_assertion_ids(artifact.interpretation)))


__all__ = [
    "ApprovalBlockedError",
    "ApprovalWorkflowResult",
    "ProposalAuditWarning",
    "ProposedInterpretationArtifact",
    "build_approval_id",
    "material_decisions",
    "review_proposed_interpretation",
]
