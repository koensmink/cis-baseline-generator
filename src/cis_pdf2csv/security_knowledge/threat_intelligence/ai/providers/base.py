from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import Field

from ....catalog.registry import SecurityKnowledgeCatalog
from ..contract import AIThreatInterpretationContract
from ..schema import (
    AIContractFinding,
    DeterministicModel,
    InterpretationValidationResult,
    ProposedThreatInterpretation,
    ThreatAdvisoryDocument,
)


class ProviderWarning(DeterministicModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)


class ProviderInterpretationResult(DeterministicModel):
    provider: str
    model: str
    model_version: str | None = None
    request_id: str | None = None
    contract_id: str
    contract_version: str
    prompt_id: str
    prompt_version: str
    document_id: str
    document_hash: str
    catalog_version: str
    catalog_vocabulary_hash: str
    generation_parameter_identity: str
    raw_response_hash: str
    interpretation: ProposedThreatInterpretation
    validation: InterpretationValidationResult
    provider_warnings: tuple[ProviderWarning, ...] = ()
    preflight_findings: tuple[AIContractFinding, ...] = ()


@runtime_checkable
class ThreatInterpretationProvider(Protocol):
    provider_name: str

    def interpret(
        self,
        document: ThreatAdvisoryDocument,
        contract: AIThreatInterpretationContract,
        catalog: SecurityKnowledgeCatalog,
    ) -> ProviderInterpretationResult: ...


__all__ = [
    "ProviderInterpretationResult",
    "ProviderWarning",
    "ThreatInterpretationProvider",
]
