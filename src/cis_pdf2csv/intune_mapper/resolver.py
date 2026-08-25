from __future__ import annotations

from collections.abc import Iterable

from cis_pdf2csv.source_identity import SourceIdentity

from .catalog import DEFAULT_LOCAL_CATALOG, AuthoritativeCatalog
from .llm_fallback import LLMClient, suggest_manual_review_mappings
from .models import (
    CandidateSource,
    ImplementationMethod,
    IntuneMapping,
    MappingCandidate,
    MappingConflict,
    MappingInputControl,
    MappingStatus,
    NormalizedControl,
    ResolverResult,
    SuggestedMapping,
    VerificationDetails,
    normalize_implementation_method,
)
from .normalizer import normalize_control
from .rules import STARTER_RULES, MappingRule
from .suggestion_normalizer import normalize_suggestion_dict
from .value_parser import parse_recommendation
from .verifier import AuthoritativeCatalogResolver

IMPLEMENTATION_PRIORITY = {
    ImplementationMethod.ENDPOINT_SECURITY: 0,
    ImplementationMethod.SETTINGS_CATALOG: 1,
    ImplementationMethod.ADMINISTRATIVE_TEMPLATE: 2,
    ImplementationMethod.POLICY_CSP: 3,
    ImplementationMethod.CUSTOM_OMA_URI: 4,
    ImplementationMethod.REGISTRY: 5,
    ImplementationMethod.POWERSHELL: 6,
    ImplementationMethod.NOT_MANAGEABLE: 7,
    ImplementationMethod.UNKNOWN: 8,
}
SUPPORTED_WINDOWS_FAMILY = "microsoft-windows-server"
UNSUPPORTED_FAMILY_REASON = "UNSUPPORTED_BENCHMARK_FAMILY"


def _manual_mapping(
    control: NormalizedControl,
    *,
    reason_code: str | None = None,
    notes: str = "No deterministic rule matched; requires analyst validation.",
) -> IntuneMapping:
    identity = control.source_identity
    return IntuneMapping(
        source_framework=identity.source_framework,
        benchmark_family=identity.benchmark_family,
        benchmark_name=identity.benchmark_name,
        benchmark_version=identity.benchmark_version,
        profile=identity.benchmark_profile,
        cis_id=control.control_id,
        title=control.title,
        implementation_method=ImplementationMethod.UNKNOWN,
        intune_area="Manual Review",
        setting_name="Unmapped control",
        value=control.parsed_recommendation.normalized_text or "N/A",
        candidate_confidence=0.0,
        candidate_source=CandidateSource.DETERMINISTIC_RULE,
        mapping_status=MappingStatus.MANUAL_REVIEW,
        verification=VerificationDetails(
            reason_codes=((reason_code,) if reason_code else ())
        ),
        rule_id="fallback.manual_review",
        reason_code=reason_code,
        notes=notes,
        parsed_value_type=control.parsed_recommendation.value_type,
        quality_flags=control.quality_flags,
    )


def resolve_normalized_control(
    control: NormalizedControl,
    rules: Iterable[MappingRule] = STARTER_RULES,
    *,
    catalog: AuthoritativeCatalog = DEFAULT_LOCAL_CATALOG,
) -> tuple[IntuneMapping, MappingConflict | None]:
    if control.benchmark_family != SUPPORTED_WINDOWS_FAMILY:
        return (
            _manual_mapping(
                control,
                reason_code=UNSUPPORTED_FAMILY_REASON,
                notes=(
                    "No Intune rule pack supports benchmark family "
                    f"'{control.benchmark_family}'. Windows Server rules were not evaluated."
                ),
            ),
            None,
        )

    matches = [rule.apply(control) for rule in rules if rule.matches(control)]
    if not matches:
        return _manual_mapping(control), None

    selected = min(
        matches,
        key=lambda item: (
            IMPLEMENTATION_PRIORITY.get(item.implementation_method, 99),
            -item.candidate_confidence,
            item.rule_id or "",
        ),
    )
    conflict = None
    if len(matches) > 1:
        conflict = MappingConflict(
            cis_id=control.control_id,
            title=control.title,
            selected_rule_id=selected.rule_id or "candidate.unattributed",
            selected_implementation_type=selected.implementation_method.value,
            matched_rule_ids=[
                item.rule_id or "candidate.unattributed" for item in matches
            ],
            matched_implementation_types=[
                item.implementation_method.value for item in matches
            ],
        )

    return AuthoritativeCatalogResolver(catalog).verify(selected), conflict


def resolve_control(
    control: MappingInputControl,
    rules: Iterable[MappingRule] = STARTER_RULES,
    *,
    catalog: AuthoritativeCatalog = DEFAULT_LOCAL_CATALOG,
) -> tuple[IntuneMapping, MappingConflict | None]:
    normalized = normalize_control(control)
    return resolve_normalized_control(normalized, rules=rules, catalog=catalog)


def _suggestion_candidate(
    suggestion: SuggestedMapping,
    original: IntuneMapping,
) -> MappingCandidate:
    normalized = normalize_suggestion_dict(suggestion.model_dump(mode="python"))
    identity = SourceIdentity(
        source_framework=original.source_framework,
        benchmark_family=original.benchmark_family,
        benchmark_name=original.benchmark_name,
        benchmark_version=original.benchmark_version,
        benchmark_profile=original.profile,
        control_id=original.cis_id,
    )
    return MappingCandidate(
        source_identity=identity,
        recommendation_id=original.cis_id,
        title=original.title,
        target_platform=(
            "windows_server_2025"
            if original.benchmark_family == SUPPORTED_WINDOWS_FAMILY
            else None
        ),
        implementation_method=normalize_implementation_method(
            normalized.suggested_implementation_type
        ),
        proposed_intune_area=normalized.suggested_intune_area,
        proposed_setting_name=normalized.suggested_setting_name,
        proposed_value=normalized.suggested_value,
        candidate_source=suggestion.candidate_source,
        candidate_confidence=normalized.confidence,
        catalog_identifier=suggestion.suggested_catalog_identifier,
        rule_id="fallback.suggestion",
        reasoning=normalized.reasoning,
        parsed_recommendation=parse_recommendation(normalized.suggested_value),
        quality_flags=tuple(normalized.normalization_notes),
    )


def _verify_suggestions(
    suggestions: list[SuggestedMapping],
    mappings: list[IntuneMapping],
    catalog: AuthoritativeCatalog,
) -> list[SuggestedMapping]:
    by_id = {item.cis_id: item for item in mappings}
    resolver = AuthoritativeCatalogResolver(catalog)
    verified: list[SuggestedMapping] = []
    for suggestion in suggestions:
        original = by_id[suggestion.cis_id]
        candidate = _suggestion_candidate(suggestion, original)
        result = resolver.verify(candidate)
        verified.append(
            suggestion.model_copy(
                update={
                    "suggested_implementation_type": candidate.implementation_method.value,
                    "suggested_intune_area": candidate.proposed_intune_area,
                    "suggested_setting_name": candidate.proposed_setting_name,
                    "suggested_value": str(candidate.proposed_value),
                    "confidence": candidate.candidate_confidence,
                    "mapping_status": result.mapping_status,
                    "verification": result.verification,
                }
            )
        )
    return verified


def resolve_controls(
    controls: Iterable[MappingInputControl],
    rules: Iterable[MappingRule] = STARTER_RULES,
    llm_client: LLMClient | None = None,
    *,
    catalog: AuthoritativeCatalog = DEFAULT_LOCAL_CATALOG,
) -> ResolverResult:
    mappings: list[IntuneMapping] = []
    conflicts: list[MappingConflict] = []
    ordered_controls = sorted(
        controls,
        key=lambda item: normalize_control(item).source_identity.as_tuple(),
    )
    for control in ordered_controls:
        mapping, conflict = resolve_control(control, rules=rules, catalog=catalog)
        mappings.append(mapping)
        if conflict:
            conflicts.append(conflict)

    manual_review_mappings = [
        item for item in mappings if item.mapping_status == MappingStatus.MANUAL_REVIEW
    ]
    suggestions = suggest_manual_review_mappings(
        manual_review_mappings,
        client=llm_client,
    )
    return ResolverResult(
        mappings=mappings,
        conflicts=conflicts,
        suggestions=_verify_suggestions(suggestions, mappings, catalog),
    )
