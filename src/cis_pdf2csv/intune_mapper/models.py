from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cis_pdf2csv.source_identity import SourceIdentity

from .value_parser import ParsedRecommendation


class CandidateSource(str, Enum):
    DETERMINISTIC_RULE = "deterministic_rule"
    LLM = "llm"
    HEURISTIC = "heuristic"


class MappingStatus(str, Enum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    MANUAL_REVIEW = "manual_review"


class ImplementationMethod(str, Enum):
    SETTINGS_CATALOG = "settings_catalog"
    ENDPOINT_SECURITY = "endpoint_security"
    ADMINISTRATIVE_TEMPLATE = "administrative_template"
    POLICY_CSP = "policy_csp"
    CUSTOM_OMA_URI = "custom_oma_uri"
    REGISTRY = "registry"
    POWERSHELL = "powershell"
    NOT_MANAGEABLE = "not_manageable"
    UNKNOWN = "unknown"


IMPLEMENTATION_METHOD_ALIASES = {
    "settings catalog": ImplementationMethod.SETTINGS_CATALOG,
    "settings_catalog": ImplementationMethod.SETTINGS_CATALOG,
    "endpoint security": ImplementationMethod.ENDPOINT_SECURITY,
    "endpoint_security": ImplementationMethod.ENDPOINT_SECURITY,
    "administrative template": ImplementationMethod.ADMINISTRATIVE_TEMPLATE,
    "administrative templates": ImplementationMethod.ADMINISTRATIVE_TEMPLATE,
    "administrative_template": ImplementationMethod.ADMINISTRATIVE_TEMPLATE,
    "policy csp": ImplementationMethod.POLICY_CSP,
    "policy_csp": ImplementationMethod.POLICY_CSP,
    "custom oma-uri": ImplementationMethod.CUSTOM_OMA_URI,
    "custom oma uri": ImplementationMethod.CUSTOM_OMA_URI,
    "custom_oma_uri": ImplementationMethod.CUSTOM_OMA_URI,
    "registry": ImplementationMethod.REGISTRY,
    "powershell": ImplementationMethod.POWERSHELL,
    "powershell script": ImplementationMethod.POWERSHELL,
    "script": ImplementationMethod.POWERSHELL,
    "not manageable": ImplementationMethod.NOT_MANAGEABLE,
    "not_manageable": ImplementationMethod.NOT_MANAGEABLE,
    "unknown": ImplementationMethod.UNKNOWN,
    "manual review": ImplementationMethod.UNKNOWN,
    "manual_review": ImplementationMethod.UNKNOWN,
}


def normalize_implementation_method(value: object) -> ImplementationMethod:
    if isinstance(value, ImplementationMethod):
        return value
    return IMPLEMENTATION_METHOD_ALIASES.get(
        str(value or "unknown").strip().casefold(), ImplementationMethod.UNKNOWN
    )


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


class MappingCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_identity: SourceIdentity
    recommendation_id: str
    title: str
    platform: str = "microsoft_intune"
    target_platform: str | None = None
    implementation_method: ImplementationMethod
    proposed_intune_area: str
    proposed_setting_name: str
    proposed_value: str | bool | int
    candidate_source: CandidateSource
    candidate_confidence: float = Field(ge=0.0, le=1.0)
    catalog_identifier: str | None = None
    rule_id: str | None = None
    reasoning: str
    match_evidence: tuple[str, ...] = ()
    parsed_recommendation: ParsedRecommendation
    quality_flags: tuple[str, ...] = ()


class VerificationDetails(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str | None = None
    catalog_version: str | None = None
    match_method: str | None = None
    canonical_identifier: str | None = None
    reason_codes: tuple[str, ...] = ()


class IntuneMapping(BaseModel):
    platform: str = "microsoft_intune"
    source_framework: str = "cis"
    benchmark_family: str = "unknown"
    benchmark_name: str = ""
    benchmark_version: str = ""
    profile: str = "Unknown"
    cis_id: str
    title: str
    implementation_type: str = "unknown"
    implementation_method: ImplementationMethod = ImplementationMethod.UNKNOWN
    intune_area: str
    setting_name: str
    value: Any
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    candidate_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    candidate_source: CandidateSource = CandidateSource.DETERMINISTIC_RULE
    mapping_status: MappingStatus = MappingStatus.CANDIDATE
    canonical_identifier: str | None = None
    verification: VerificationDetails = Field(default_factory=VerificationDetails)
    rule_id: str
    reason_code: str | None = None
    notes: str | None = None
    parsed_value_type: str | None = None
    quality_flags: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        values = dict(data)
        legacy_type = values.get("implementation_type")
        values["implementation_method"] = normalize_implementation_method(
            values.get("implementation_method", legacy_type)
        )
        if legacy_type == "manual_review" and "mapping_status" not in values:
            values["mapping_status"] = MappingStatus.MANUAL_REVIEW
        if "candidate_confidence" not in values:
            values["candidate_confidence"] = values.get("confidence", 0.0)
        return values

    @model_validator(mode="after")
    def retain_legacy_projection(self) -> IntuneMapping:
        self.confidence = self.candidate_confidence or 0.0
        self.implementation_type = (
            "manual_review"
            if self.mapping_status == MappingStatus.MANUAL_REVIEW
            else self.implementation_method.value
        )
        return self


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
    suggested_catalog_identifier: str | None = None
    candidate_source: CandidateSource = CandidateSource.LLM
    mapping_status: MappingStatus = MappingStatus.CANDIDATE
    verification: VerificationDetails = Field(default_factory=VerificationDetails)


class ResolverResult(BaseModel):
    mappings: list[IntuneMapping]
    conflicts: list[MappingConflict]
    suggestions: list[SuggestedMapping] = Field(default_factory=list)
