from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from cis_pdf2csv.security_knowledge.schema import ControlAttackPathMapping

Proposal = Literal["Regular Control", "Review Required", "Candidate Mandatory"]
Confidence = Literal["Low", "Medium", "High"]
ApplicabilityMode = Literal["universal", "mandatory_when_deployed", "unresolved"]
OverlapType = Literal["none", "duplicate", "complementary", "alternative"]
Relationship = Literal[
    "standalone primary boundary",
    "boundary-set core member",
    "prerequisite",
    "supporting hardening",
    "fine-tuning",
    "detection-only",
    "information-hiding",
    "operational",
]


class BenchmarkEvidence(BaseModel):
    field: str
    excerpt: str
    pages: str


class MandatoryAssessment(BaseModel):
    control_id: str
    proposal: Proposal
    control_family: str
    mandatory_criteria: list[str] = Field(default_factory=list)
    exclusion_reasons: list[str] = Field(default_factory=list)
    non_compensable_reason: str | None = None
    benchmark_evidence: list[BenchmarkEvidence] = Field(default_factory=list)
    related_control_ids: list[str] = Field(default_factory=list)
    relationship: Relationship = "operational"
    applicability_mode: ApplicabilityMode = "universal"
    overlap_type: OverlapType = "none"
    boundary_set_id: str | None = None
    boundary_set_name: str | None = None
    boundary_set_role: str | None = None
    related_core_member_ids: list[str] = Field(default_factory=list)
    enforced_sub_boundary: str | None = None
    attack_path_if_omitted: str | None = None
    remaining_members_cannot_compensate: str | None = None
    capability_ids: list[str] = Field(default_factory=list)
    attack_path_ids: list[str] = Field(default_factory=list)
    attack_path_names: list[str] = Field(default_factory=list)
    attack_stages: list[str] = Field(default_factory=list)
    mitigation_roles: list[str] = Field(default_factory=list)
    mitigation_strengths: list[str] = Field(default_factory=list)
    mapping_confidences: list[str] = Field(default_factory=list)
    attack_path_rationale: str | None = None
    attack_path_mappings: list[ControlAttackPathMapping] = Field(default_factory=list)
    rationale: str
    confidence: Confidence
    review_note: str | None = None
