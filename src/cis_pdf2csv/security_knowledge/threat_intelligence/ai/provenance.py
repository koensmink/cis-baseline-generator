from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AdvisoryDocumentProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    supplied_by: str = Field(min_length=1)
    collection_method: str = Field(min_length=1)
    source_revision: str | None = None


class AIInterpretationProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_id: str = Field(min_length=1)
    contract_version: str = Field(min_length=1)
    authority_policy_version: str = Field(min_length=1)
    generation_parameters_id: str | None = None
    input_document_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


__all__ = ["AIInterpretationProvenance", "AdvisoryDocumentProvenance"]
