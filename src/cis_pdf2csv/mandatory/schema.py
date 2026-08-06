from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Proposal = Literal["Regular Control", "Review Required", "Candidate Mandatory"]
Confidence = Literal["Low", "Medium", "High"]
Relationship = Literal[
    "primary boundary control",
    "supporting control",
    "fine-tuning control",
    "detection-only control",
    "duplicate or overlapping control",
    "independent control",
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
    relationship: Relationship = "independent control"
    rationale: str
    confidence: Confidence
    review_note: str | None = None
