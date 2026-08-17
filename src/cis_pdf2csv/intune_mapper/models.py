from __future__ import annotations

from pydantic import BaseModel, Field

from cis_pdf2csv.source_identity import SourceIdentity

from .value_parser import ParsedRecommendation


class MappingInputControl(BaseModel):
    source_framework: str = "cis"
    benchmark_family: str = "unknown"
    benchmark_name: str = ""
    benchmark_version: str = ""
    control_id: str
    title: str
    profile: str = "Unknown"
    assessment: str = "Unknown"
    applicability: str | None = None

    recommendation: str | None = None
    description: str | None = None
    rationale: str | None = None
    impact: str | None = None
    audit: str | None = None
    remediation: str | None = None
    default_value: str | None = None
    references: str | None = None


class NormalizedControl(MappingInputControl):
    source_identity: SourceIdentity
    target: str | None = None
    parsed_recommendation: ParsedRecommendation
    quality_flags: list[str] = Field(default_factory=list)


class IntuneMapping(BaseModel):
    source_framework: str = "cis"
    benchmark_family: str = "unknown"
    benchmark_name: str = ""
    benchmark_version: str = ""
    profile: str = "Unknown"
    cis_id: str
    title: str
    implementation_type: str
    intune_area: str
    setting_name: str
    value: str
    confidence: float

    rule_id: str
    reason_code: str | None = None
    notes: str | None = None
    parsed_value_type: str | None = None
    quality_flags: list[str] = Field(default_factory=list)


class MappingConflict(BaseModel):
    cis_id: str
    title: str
    selected_rule_id: str
    selected_implementation_type: str
    matched_rule_ids: list[str]
    matched_implementation_types: list[str]


class SuggestedMapping(BaseModel):
    cis_id: str
    title: str
    suggested_implementation_type: str
    suggested_intune_area: str
    suggested_setting_name: str
    suggested_value: str
    confidence: float
    reasoning: str


class ResolverResult(BaseModel):
    mappings: list[IntuneMapping]
    conflicts: list[MappingConflict]
    suggestions: list[SuggestedMapping] = Field(default_factory=list)
