from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class LifecycleStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class SourceExtractionProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_framework: str = Field(min_length=1)
    benchmark_identity: str = Field(min_length=1)
    benchmark_version: str = Field(min_length=1)
    source_hash: str = Field(min_length=1)
    block_hash: str = Field(min_length=1)
    page_range: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    extraction_method: str = Field(min_length=1)
    extracted_at: datetime
    confidence: Confidence


class CatalogObjectProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    catalog_authority: str = Field(min_length=1)
    catalog_version: str = Field(min_length=1)
    object_version: str = Field(min_length=1)
    creation_method: str = Field(min_length=1)
    rationale_sources: list[str] = Field(default_factory=list)
    supersedes_id: str | None = None
    created_at: datetime | None = None


class MappingEvidenceProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_fields_used: list[str] = Field(min_length=1)
    evidence_reference_ids: list[str] = Field(min_length=1)
    mapping_method: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    ontology_version: str = Field(min_length=1)
    mapped_at: datetime | None = None
    supersedes_mapping_id: str | None = None


class ReviewProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    reviewer: str = Field(min_length=1)
    review_authority: str = Field(min_length=1)
    reviewed_at: datetime
    disposition: str = Field(min_length=1)
    comments: str = ""
    reviewed_object_revision: str = Field(min_length=1)


class DecisionProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_revision: str = Field(min_length=1)
    mapping_revisions: list[str] = Field(min_length=1)
    boundary_evaluation_revisions: list[str] = Field(default_factory=list)
    rule_version: str = Field(min_length=1)
    catalog_version: str = Field(min_length=1)
    ontology_version: str = Field(min_length=1)
    decision_timestamp: datetime
    source_extraction_confidence: Confidence
    reviewer_approval: str | None = None
    supersedes_decision_id: str | None = None

