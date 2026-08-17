from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .identifiers import TechniqueId
from .provenance import CatalogObjectProvenance, Confidence, LifecycleStatus


class ExternalTechniqueMapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    framework: str = Field(min_length=1)
    framework_version: str = Field(min_length=1)
    external_id: str = Field(min_length=1)
    confidence: Confidence


class AttackTechnique(BaseModel):
    model_config = ConfigDict(frozen=True)

    technique_id: TechniqueId
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    attack_stage: str = Field(min_length=1)
    external_mappings: list[ExternalTechniqueMapping] = Field(default_factory=list)
    affected_technologies: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    lifecycle_status: LifecycleStatus
    confidence: Confidence
    provenance: CatalogObjectProvenance

