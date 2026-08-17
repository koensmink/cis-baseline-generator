from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import EvidenceItem
from .identifiers import BoundaryEvaluationId, BoundaryId, BoundarySetId, CapabilityId
from .provenance import CatalogObjectProvenance, Confidence, LifecycleStatus


class DecisionScope(str, Enum):
    BENCHMARK = "benchmark"
    ENVIRONMENT = "environment"


class ApplicabilityMode(str, Enum):
    UNIVERSAL = "universal"
    MANDATORY_WHEN_DEPLOYED = "mandatory_when_deployed"
    UNRESOLVED = "unresolved"


class DeploymentState(str, Enum):
    DEPLOYED = "deployed"
    NOT_DEPLOYED = "not_deployed"
    UNKNOWN = "unknown"
    NOT_EVALUATED = "not_evaluated"


class CompletenessStatus(str, Enum):
    COMPLETE_STANDALONE_PRIMARY = "complete_standalone_primary"
    COMPLETE_COMPLEMENTARY_CORE_SET = "complete_complementary_core_set"
    INCOMPLETE_BOUNDARY = "incomplete_boundary"
    SUPPORTING_ONLY = "supporting_only"
    DETECTION_ONLY = "detection_only"
    NO_EFFECTIVE_MITIGATION = "no_effective_mitigation"


class BoundaryDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    boundary_id: BoundaryId
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    technology_scope: list[str] = Field(min_length=1)
    related_capability_ids: list[CapabilityId] = Field(min_length=1)
    lifecycle_status: LifecycleStatus
    catalog_version: str = Field(min_length=1)
    provenance: CatalogObjectProvenance


class BoundarySetDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    boundary_set_id: BoundarySetId
    boundary_definition_id: BoundaryId
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    required_sub_boundaries: list[str] = Field(min_length=1)
    minimum_effective_roles: list[str] = Field(min_length=1)
    optional_supporting_roles: list[str] = Field(default_factory=list)
    completeness_rules: list[str] = Field(min_length=1)
    compensation_rules: list[str] = Field(default_factory=list)
    lifecycle_status: LifecycleStatus
    catalog_version: str = Field(min_length=1)
    provenance: CatalogObjectProvenance


class BoundaryEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    evaluation_id: BoundaryEvaluationId
    boundary_definition_id: BoundaryId
    boundary_set_definition_id: BoundarySetId | None = None
    decision_scope: DecisionScope
    benchmark_profile: str = Field(min_length=1)
    applicability_mode: ApplicabilityMode
    deployment_state: DeploymentState
    selected_control_ids: list[str] = Field(default_factory=list)
    selected_alternatives: list[str] = Field(default_factory=list)
    completeness_status: CompletenessStatus
    residual_path: str = Field(min_length=1)
    confidence: Confidence
    evidence: list[EvidenceItem] = Field(min_length=1)

