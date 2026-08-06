from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .attack_paths import AttackPath
from .boundaries import (
    ApplicabilityMode,
    BoundaryDefinition,
    BoundaryEvaluation,
    BoundarySetDefinition,
    DecisionScope,
    DeploymentState,
)
from .capabilities import SecurityCapability
from .evidence import EvidenceItem
from .identifiers import (
    AttackPathId,
    BoundaryEvaluationId,
    CapabilityId,
    MandatoryDecisionId,
    MappingId,
    OutcomeId,
    RiskId,
    ThreatScenarioId,
)
from .mitigation import (
    BoundaryRole,
    CompensatingControlEvaluation,
    EquivalenceType,
    MitigationMapping,
    MitigationRole,
    MitigationStrength,
)
from .provenance import (
    CatalogObjectProvenance,
    Confidence,
    DecisionProvenance,
    LifecycleStatus,
    ReviewProvenance,
)
from .techniques import AttackTechnique
from .threats import ThreatScenario

LegacyMitigationRole = Literal[
    "prevent", "restrict", "isolate", "protect", "detect", "investigate", "recover"
]
LegacyMitigationStrength = Literal["primary", "complementary", "supporting"]
MappingConfidence = Literal["Low", "Medium", "High"]


class ControlAttackPathMapping(BaseModel):
    """Deprecated Phase-1 mapping retained for CSV and Mandatory compatibility."""

    control_id: str
    attack_path_id: str
    capability_id: str
    mitigation_role: LegacyMitigationRole
    attack_stage: str
    mitigation_strength: LegacyMitigationStrength
    evidence: list[str] = Field(default_factory=list)
    rationale: str
    confidence: MappingConfidence


class SecurityOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome_id: OutcomeId
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    technical_impact: str = Field(min_length=1)
    lifecycle_status: LifecycleStatus
    provenance: CatalogObjectProvenance


class Risk(BaseModel):
    model_config = ConfigDict(frozen=True)

    risk_id: RiskId
    threat_scenario_id: ThreatScenarioId
    security_outcome_ids: list[OutcomeId] = Field(min_length=1)
    affected_asset_class: str = Field(min_length=1)
    technical_impact: str = Field(min_length=1)
    business_impact: str = Field(min_length=1)
    likelihood_factors: list[str] = Field(min_length=1)
    existing_mitigations: list[MappingId] = Field(default_factory=list)
    residual_risk_statement: str = Field(min_length=1)
    decision_scope: DecisionScope
    confidence: Confidence
    provenance: DecisionProvenance


class Proposal(str, Enum):
    REGULAR = "Regular Control"
    REVIEW = "Review Required"
    CANDIDATE = "Candidate Mandatory"
    DEFINITIVE = "Definitive Mandatory"


class MandatoryDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision_id: MandatoryDecisionId
    source_recommendation_id: str = Field(min_length=1)
    proposal: Proposal
    mitigation_mapping_ids: list[MappingId] = Field(default_factory=list)
    boundary_evaluation_ids: list[BoundaryEvaluationId] = Field(default_factory=list)
    decision_scope: DecisionScope
    applicability_mode: ApplicabilityMode
    deployment_state: DeploymentState
    confidence: Confidence
    rationale: str = Field(min_length=1)
    exclusions: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    review_provenance: list[ReviewProvenance] = Field(default_factory=list)
    decision_provenance: DecisionProvenance
    lifecycle_status: LifecycleStatus

    @model_validator(mode="after")
    def definitive_requires_human_approval(self) -> MandatoryDecision:
        if self.proposal == Proposal.DEFINITIVE and not any(
            item.disposition.lower() == "approved" for item in self.review_provenance
        ):
            raise ValueError("Definitive Mandatory requires approved human review provenance")
        return self


__all__ = [
    "ApplicabilityMode",
    "AttackPath",
    "AttackPathId",
    "AttackTechnique",
    "BoundaryDefinition",
    "BoundaryEvaluation",
    "BoundaryRole",
    "BoundarySetDefinition",
    "CapabilityId",
    "CompensatingControlEvaluation",
    "Confidence",
    "ControlAttackPathMapping",
    "DecisionScope",
    "DeploymentState",
    "EquivalenceType",
    "LifecycleStatus",
    "MandatoryDecision",
    "MitigationMapping",
    "MitigationRole",
    "MitigationStrength",
    "Proposal",
    "Risk",
    "SecurityCapability",
    "SecurityOutcome",
    "ThreatScenario",
]
