from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .boundaries import ApplicabilityMode
from .evidence import EvidenceItem
from .identifiers import (
    AttackPathId,
    BoundaryId,
    BoundarySetId,
    CapabilityId,
    MappingId,
    TechniqueId,
    ThreatScenarioId,
)
from .provenance import Confidence, LifecycleStatus, MappingEvidenceProvenance


class BoundaryRole(str, Enum):
    STANDALONE_PRIMARY_BOUNDARY = "standalone_primary_boundary"
    BOUNDARY_SET_CORE_MEMBER = "boundary_set_core_member"
    PREREQUISITE = "prerequisite"
    SUPPORTING_HARDENING = "supporting_hardening"
    FINE_TUNING = "fine_tuning"
    DETECTION_ONLY = "detection_only"
    INFORMATION_HIDING = "information_hiding"
    OPERATIONAL = "operational"


class MitigationRole(str, Enum):
    PREVENT = "prevent"
    RESTRICT = "restrict"
    ISOLATE = "isolate"
    PROTECT = "protect"
    DETECT = "detect"
    INVESTIGATE = "investigate"
    RECOVER = "recover"


class MitigationStrength(str, Enum):
    PRIMARY = "primary"
    COMPLEMENTARY = "complementary"
    SUPPORTING = "supporting"


class EquivalenceType(str, Enum):
    FULL = "full"
    CONDITIONAL = "conditional"
    PARTIAL = "partial"
    NONE = "none"


class MitigationMapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    mapping_id: MappingId
    source_recommendation_id: str = Field(min_length=1)
    capability_id: CapabilityId
    boundary_definition_id: BoundaryId
    boundary_set_definition_id: BoundarySetId | None = None
    threat_scenario_id: ThreatScenarioId | None = None
    attack_path_id: AttackPathId
    attack_stage: str = Field(min_length=1)
    boundary_role: BoundaryRole
    mitigation_role: MitigationRole
    mitigation_strength: MitigationStrength
    technique_ids: list[TechniqueId] = Field(default_factory=list)
    enforced_sub_boundary: str = Field(min_length=1)
    attack_path_if_omitted: str = Field(min_length=1)
    evidence: list[EvidenceItem] = Field(min_length=1)
    confidence: Confidence
    applicability_mode: ApplicabilityMode
    lifecycle_status: LifecycleStatus
    rule_version: str = Field(min_length=1)
    ontology_version: str = Field(min_length=1)
    provenance: MappingEvidenceProvenance | None = None

    @model_validator(mode="after")
    def role_dimensions_are_consistent(self) -> MitigationMapping:
        if (
            self.boundary_role
            in {
                BoundaryRole.SUPPORTING_HARDENING,
                BoundaryRole.FINE_TUNING,
                BoundaryRole.DETECTION_ONLY,
                BoundaryRole.INFORMATION_HIDING,
                BoundaryRole.OPERATIONAL,
            }
            and self.mitigation_strength != MitigationStrength.SUPPORTING
        ):
            raise ValueError("Non-core boundary roles require supporting strength")
        return self


class CompensatingControlEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    evaluation_id: str = Field(min_length=1)
    source_mapping_id: MappingId
    candidate_compensating_control_id: str = Field(min_length=1)
    replaced_security_effect: str = Field(min_length=1)
    protected_scope: str = Field(min_length=1)
    equivalence_type: EquivalenceType
    prerequisites: list[str] = Field(default_factory=list)
    applicability_mode: ApplicabilityMode
    evidence: list[EvidenceItem] = Field(min_length=1)
    confidence: Confidence
    residual_attack_path: str = Field(min_length=1)
    reviewer: str | None = None
    status: LifecycleStatus

    @model_validator(mode="after")
    def accepted_conditional_has_reviewer(self) -> CompensatingControlEvaluation:
        if (
            self.equivalence_type == EquivalenceType.CONDITIONAL
            and self.status == LifecycleStatus.ACTIVE
            and not self.reviewer
        ):
            raise ValueError("Active conditional compensation requires a reviewer")
        return self

