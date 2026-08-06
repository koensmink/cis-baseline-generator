from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

MitigationRole = Literal[
    "prevent", "restrict", "isolate", "protect", "detect", "investigate", "recover"
]
MitigationStrength = Literal["primary", "complementary", "supporting"]
MappingConfidence = Literal["Low", "Medium", "High"]


class SecurityCapability(BaseModel):
    capability_id: str
    name: str
    description: str


class AttackPath(BaseModel):
    attack_path_id: str
    name: str
    description: str
    stages: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    security_outcomes: list[str] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)


class ControlAttackPathMapping(BaseModel):
    control_id: str
    attack_path_id: str
    capability_id: str
    mitigation_role: MitigationRole
    attack_stage: str
    mitigation_strength: MitigationStrength
    evidence: list[str] = Field(default_factory=list)
    rationale: str
    confidence: MappingConfidence

