from __future__ import annotations

import json
from pathlib import Path

from .approval_workflow import (
    ApprovalWorkflowResult,
    ProposedInterpretationArtifact,
)
from .schema import (
    DeterministicModel,
    InterpretationValidationResult,
    ThreatInterpretationApproval,
)


class ThreatApprovalRecord(DeterministicModel):
    proposal_artifact_hash: str
    document_id: str
    document_hash: str
    raw_response_hash: str
    contract_id: str
    contract_version: str
    prompt_id: str
    prompt_version: str
    approval: ThreatInterpretationApproval
    validation: InterpretationValidationResult


class ThreatApprovalSummary(DeterministicModel):
    interpretation_id: str
    interpretation_revision: str
    decision: str
    reviewer: str
    reviewed_at: str
    accepted_assertions: int
    rejected_assertions: int
    modifications: int
    threat_context_created: bool
    blocking_findings: int


def write_approval_artifacts(
    artifact: ProposedInterpretationArtifact,
    result: ApprovalWorkflowResult,
    output: Path,
) -> tuple[Path, Path, ThreatApprovalSummary]:
    approval_path = output.with_name(f"{output.stem}-approval.json")
    summary_path = output.with_name(f"{output.stem}-approval-summary.json")
    record = ThreatApprovalRecord(
        proposal_artifact_hash=result.artifact_hash,
        document_id=artifact.document_id,
        document_hash=artifact.document_hash,
        raw_response_hash=artifact.raw_response_hash,
        contract_id=artifact.contract_id,
        contract_version=artifact.contract_version,
        prompt_id=artifact.prompt_id,
        prompt_version=artifact.prompt_version,
        approval=result.approval,
        validation=result.validation,
    )
    summary = ThreatApprovalSummary(
        interpretation_id=result.approval.interpretation_id,
        interpretation_revision=result.approval.interpretation_revision,
        decision=result.approval.status.value,
        reviewer=result.approval.reviewed_by or "",
        reviewed_at=(
            result.approval.reviewed_at.isoformat()
            if result.approval.reviewed_at is not None
            else ""
        ),
        accepted_assertions=len(result.approval.accepted_assertion_ids),
        rejected_assertions=len(result.approval.rejected_assertion_ids),
        modifications=len(result.approval.modifications),
        threat_context_created=result.threat_context is not None,
        blocking_findings=sum(item.blocking for item in result.validation.findings),
    )
    if result.threat_context is not None:
        output.write_text(result.threat_context.to_deterministic_json(), encoding="utf-8")
    _write_json(approval_path, record)
    _write_json(summary_path, summary)
    return approval_path, summary_path, summary


def _write_json(path: Path, model: DeterministicModel) -> None:
    path.write_text(
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


__all__ = [
    "ThreatApprovalRecord",
    "ThreatApprovalSummary",
    "write_approval_artifacts",
]
