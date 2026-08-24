from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from .providers import ProviderInterpretationResult
from .schema import DeterministicModel


class ProviderInterpretationSummary(DeterministicModel):
    provider: str
    model: str
    contract_id: str
    contract_version: str
    prompt_id: str
    prompt_version: str
    document_id: str
    document_hash: str
    generation_parameter_identity: str
    catalog_version: str
    catalog_vocabulary_hash: str
    raw_response_hash: str
    validation: str
    confidence: str
    severity: str
    activity_state: str
    technique_proposals: int
    attack_path_proposals: int
    blocking_findings: int
    review_findings: int


def summarize_provider_result(result: ProviderInterpretationResult) -> ProviderInterpretationSummary:
    findings = result.validation.findings
    return ProviderInterpretationSummary(
        provider=result.provider,
        model=result.model,
        contract_id=result.contract_id,
        contract_version=result.contract_version,
        prompt_id=result.prompt_id,
        prompt_version=result.prompt_version,
        document_id=result.document_id,
        document_hash=result.document_hash,
        generation_parameter_identity=result.generation_parameter_identity,
        catalog_version=result.catalog_version,
        catalog_vocabulary_hash=result.catalog_vocabulary_hash,
        raw_response_hash=result.raw_response_hash,
        validation="blocked" if result.validation.blocking else ("needs review" if findings else "valid"),
        confidence=result.validation.capped_confidence.value,
        severity=result.interpretation.proposed_severity.value,
        activity_state=result.interpretation.proposed_activity_state.value,
        technique_proposals=len(result.interpretation.proposed_technique_ids),
        attack_path_proposals=len(result.interpretation.proposed_attack_path_ids),
        blocking_findings=sum(item.blocking for item in findings),
        review_findings=sum(not item.blocking for item in findings),
    )


def write_provider_artifacts(result: ProviderInterpretationResult, output: Path) -> ProviderInterpretationSummary:
    summary = summarize_provider_result(result)
    _write_model(output, result)
    _write_model(output.with_name(f"{output.stem}-summary.json"), summary)
    return summary


def _write_model(path: Path, model: BaseModel) -> None:
    payload = model.model_dump(mode="json")
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "ProviderInterpretationSummary",
    "summarize_provider_result",
    "write_provider_artifacts",
]
