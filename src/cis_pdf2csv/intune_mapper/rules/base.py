from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import (
    CandidateSource,
    ImplementationMethod,
    MappingCandidate,
    NormalizedControl,
)


def build_rule_candidate(
    control: NormalizedControl,
    *,
    rule_id: str,
    implementation_method: ImplementationMethod,
    intune_area: str,
    setting_name: str,
    confidence: float,
    default_value: str = "Use CIS recommended value",
    catalog_identifier: str | None = None,
) -> MappingCandidate:
    value = control.parsed_recommendation.normalized_text or default_value
    return MappingCandidate(
        source_identity=control.source_identity,
        recommendation_id=control.control_id,
        title=control.title,
        target_platform=control.target,
        implementation_method=implementation_method,
        proposed_intune_area=intune_area,
        proposed_setting_name=setting_name,
        proposed_value=value,
        candidate_source=CandidateSource.DETERMINISTIC_RULE,
        candidate_confidence=confidence,
        catalog_identifier=catalog_identifier,
        rule_id=rule_id,
        reasoning=f"Deterministic rule {rule_id} matched structured control evidence.",
        match_evidence=(control.title,),
        parsed_recommendation=control.parsed_recommendation,
        quality_flags=tuple(control.quality_flags),
    )


class MappingRule(ABC):
    rule_id: str

    @abstractmethod
    def matches(self, control: NormalizedControl) -> bool:
        raise NotImplementedError

    @abstractmethod
    def apply(self, control: NormalizedControl) -> MappingCandidate:
        raise NotImplementedError
