from __future__ import annotations

from collections.abc import Iterable

from .llm_fallback import LLMClient, suggest_manual_review_mappings
from .models import (
    IntuneMapping,
    MappingConflict,
    MappingInputControl,
    NormalizedControl,
    ResolverResult,
)
from .normalizer import normalize_control
from .rules import STARTER_RULES, MappingRule

IMPLEMENTATION_PRIORITY = {
    "endpoint_security": 0,
    "settings_catalog": 1,
    "administrative_template": 2,
    "custom_oma_uri": 3,
    "manual_review": 4,
}
SUPPORTED_WINDOWS_FAMILY = "microsoft-windows-server"
UNSUPPORTED_FAMILY_REASON = "UNSUPPORTED_BENCHMARK_FAMILY"


def _identity_update(control: NormalizedControl) -> dict[str, str]:
    identity = control.source_identity
    return {
        "source_framework": identity.source_framework,
        "benchmark_family": identity.benchmark_family,
        "benchmark_name": identity.benchmark_name,
        "benchmark_version": identity.benchmark_version,
        "profile": identity.benchmark_profile,
    }


def _manual_mapping(
    control: NormalizedControl,
    *,
    reason_code: str | None = None,
    notes: str = "No deterministic rule matched; requires analyst validation.",
) -> IntuneMapping:
    return IntuneMapping(
        **_identity_update(control),
        cis_id=control.control_id,
        title=control.title,
        implementation_type="manual_review",
        intune_area="Manual Review",
        setting_name="Unmapped control",
        value=control.parsed_recommendation.normalized_text or "N/A",
        confidence=0.0,
        rule_id="fallback.manual_review",
        reason_code=reason_code,
        notes=notes,
        parsed_value_type=control.parsed_recommendation.value_type,
        quality_flags=control.quality_flags,
    )


def resolve_normalized_control(
    control: NormalizedControl,
    rules: Iterable[MappingRule] = STARTER_RULES,
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

    matches: list[IntuneMapping] = []

    for rule in rules:
        if rule.matches(control):
            matches.append(rule.apply(control))

    if not matches:
        return _manual_mapping(control), None

    selected = min(
        matches,
        key=lambda m: (
            IMPLEMENTATION_PRIORITY.get(m.implementation_type, 99),
            -m.confidence,
            m.rule_id,
        ),
    )

    conflict = None
    if len(matches) > 1:
        conflict = MappingConflict(
            cis_id=control.control_id,
            title=control.title,
            selected_rule_id=selected.rule_id,
            selected_implementation_type=selected.implementation_type,
            matched_rule_ids=[m.rule_id for m in matches],
            matched_implementation_types=[m.implementation_type for m in matches],
        )

    return selected.model_copy(update=_identity_update(control)), conflict


def resolve_control(
    control: MappingInputControl,
    rules: Iterable[MappingRule] = STARTER_RULES,
) -> tuple[IntuneMapping, MappingConflict | None]:
    normalized = normalize_control(control)
    return resolve_normalized_control(normalized, rules=rules)


def resolve_controls(
    controls: Iterable[MappingInputControl],
    rules: Iterable[MappingRule] = STARTER_RULES,
    llm_client: LLMClient | None = None,
) -> ResolverResult:
    """
    Resolve all controls into:
    - deterministic mappings where possible
    - manual_review mappings where no rule matched
    - LLM-backed suggestions for manual_review items if llm_client is provided
    - heuristic suggestions only when no llm_client is provided
    """
    mappings: list[IntuneMapping] = []
    conflicts: list[MappingConflict] = []

    ordered_controls = sorted(
        controls,
        key=lambda item: normalize_control(item).source_identity.as_tuple(),
    )
    for control in ordered_controls:
        mapping, conflict = resolve_control(control, rules=rules)
        mappings.append(mapping)

        if conflict:
            conflicts.append(conflict)

    # Only manual review items go through suggestion generation.
    # If llm_client is provided, llm_fallback.py should use the real LLM.
    # If not, it should fall back to HeuristicLLMClient().
    manual_review_mappings = [
        m for m in mappings if m.implementation_type == "manual_review"
    ]

    suggestions = suggest_manual_review_mappings(
        manual_review_mappings,
        client=llm_client,
    )

    return ResolverResult(
        mappings=mappings,
        conflicts=conflicts,
        suggestions=suggestions,
    )
