from __future__ import annotations

from enum import Enum

from .catalog import (
    AuthoritativeCatalog,
    AuthoritativeCatalogEntry,
    CatalogValueType,
)
from .models import (
    CandidateSource,
    IntuneMapping,
    MappingCandidate,
    MappingStatus,
    VerificationDetails,
)
from .value_parser import parse_recommendation


class VerificationReasonCode(str, Enum):
    CATALOG_ENTRY_NOT_FOUND = "CATALOG_ENTRY_NOT_FOUND"
    AMBIGUOUS_CATALOG_MATCH = "AMBIGUOUS_CATALOG_MATCH"
    IMPLEMENTATION_METHOD_MISMATCH = "IMPLEMENTATION_METHOD_MISMATCH"
    PLATFORM_NOT_SUPPORTED = "PLATFORM_NOT_SUPPORTED"
    VALUE_TYPE_MISMATCH = "VALUE_TYPE_MISMATCH"
    VALUE_OUT_OF_RANGE = "VALUE_OUT_OF_RANGE"
    ENUM_VALUE_NOT_ALLOWED = "ENUM_VALUE_NOT_ALLOWED"
    INSUFFICIENT_PROVENANCE = "INSUFFICIENT_PROVENANCE"
    LLM_CANDIDATE_UNVERIFIED = "LLM_CANDIDATE_UNVERIFIED"


def _validated_value(
    candidate: MappingCandidate,
    entry: AuthoritativeCatalogEntry,
) -> tuple[object, tuple[VerificationReasonCode, ...]]:
    parsed = parse_recommendation(str(candidate.proposed_value))
    if entry.value_type == CatalogValueType.BOOLEAN:
        if parsed.value_type != "boolean":
            return candidate.proposed_value, (
                VerificationReasonCode.VALUE_TYPE_MISMATCH,
            )
        return parsed.bool_value, ()
    if entry.value_type == CatalogValueType.INTEGER:
        if parsed.value_type != "integer" or parsed.int_value is None:
            return candidate.proposed_value, (
                VerificationReasonCode.VALUE_TYPE_MISMATCH,
            )
        if entry.minimum is not None and parsed.int_value < entry.minimum:
            return parsed.int_value, (VerificationReasonCode.VALUE_OUT_OF_RANGE,)
        if entry.maximum is not None and parsed.int_value > entry.maximum:
            return parsed.int_value, (VerificationReasonCode.VALUE_OUT_OF_RANGE,)
        return parsed.int_value, ()
    if entry.value_type == CatalogValueType.RANGE:
        if (
            parsed.value_type != "range"
            or parsed.min_value is None
            or parsed.max_value is None
        ):
            return candidate.proposed_value, (
                VerificationReasonCode.VALUE_TYPE_MISMATCH,
            )
        if entry.minimum is not None and parsed.min_value < entry.minimum:
            return candidate.proposed_value, (
                VerificationReasonCode.VALUE_OUT_OF_RANGE,
            )
        if entry.maximum is not None and parsed.max_value > entry.maximum:
            return candidate.proposed_value, (
                VerificationReasonCode.VALUE_OUT_OF_RANGE,
            )
        return candidate.proposed_value, ()
    if entry.value_type == CatalogValueType.ENUM:
        value = str(candidate.proposed_value).strip()
        allowed = {item.casefold(): item for item in entry.allowed_enum_values}
        if value.casefold() not in allowed:
            return value, (VerificationReasonCode.ENUM_VALUE_NOT_ALLOWED,)
        return allowed[value.casefold()], ()
    value = str(candidate.proposed_value)
    if not value:
        return value, (VerificationReasonCode.VALUE_TYPE_MISMATCH,)
    return value, ()


class AuthoritativeCatalogResolver:
    def __init__(self, catalog: AuthoritativeCatalog) -> None:
        self.catalog = catalog

    def verify(self, candidate: MappingCandidate) -> IntuneMapping:
        reasons: list[VerificationReasonCode] = []
        matches = (
            self.catalog.find_by_identifier(candidate.catalog_identifier)
            if candidate.catalog_identifier
            else ()
        )
        entry: AuthoritativeCatalogEntry | None = None
        if not matches:
            reasons.append(VerificationReasonCode.CATALOG_ENTRY_NOT_FOUND)
        elif len(matches) > 1:
            reasons.append(VerificationReasonCode.AMBIGUOUS_CATALOG_MATCH)
        else:
            entry = matches[0]

        value: object = candidate.proposed_value
        if entry is not None:
            if candidate.implementation_method != entry.implementation_method:
                reasons.append(VerificationReasonCode.IMPLEMENTATION_METHOD_MISMATCH)
            if (
                candidate.target_platform is None
                or candidate.target_platform not in entry.supported_platforms
            ):
                reasons.append(VerificationReasonCode.PLATFORM_NOT_SUPPORTED)
            value, value_reasons = _validated_value(candidate, entry)
            reasons.extend(value_reasons)
            provenance = entry.provenance
            if not (
                provenance.authoritative_for_scope
                and provenance.source
                and provenance.catalog_version
            ):
                reasons.append(VerificationReasonCode.INSUFFICIENT_PROVENANCE)

        if candidate.candidate_source == CandidateSource.LLM:
            reasons.append(VerificationReasonCode.LLM_CANDIDATE_UNVERIFIED)

        ordered_reasons = tuple(sorted(set(reasons), key=lambda item: item.value))
        status = MappingStatus.UNVERIFIED
        if not ordered_reasons:
            status = MappingStatus.VERIFIED

        identity = candidate.source_identity
        verification = VerificationDetails(
            source=self.catalog.source,
            catalog_version=self.catalog.version,
            match_method="exact_identifier" if entry is not None else None,
            canonical_identifier=(entry.canonical_identifier if entry else None),
            reason_codes=tuple(item.value for item in ordered_reasons),
        )
        return IntuneMapping(
            source_framework=identity.source_framework,
            benchmark_family=identity.benchmark_family,
            benchmark_name=identity.benchmark_name,
            benchmark_version=identity.benchmark_version,
            profile=identity.benchmark_profile,
            cis_id=candidate.recommendation_id,
            title=candidate.title,
            implementation_method=candidate.implementation_method,
            intune_area=(
                entry.category
                if entry and entry.category
                else candidate.proposed_intune_area
            ),
            setting_name=(
                entry.setting_name if entry else candidate.proposed_setting_name
            ),
            value=value,
            candidate_confidence=candidate.candidate_confidence,
            candidate_source=candidate.candidate_source,
            mapping_status=status,
            canonical_identifier=(
                entry.canonical_identifier if entry else candidate.catalog_identifier
            ),
            verification=verification,
            rule_id=candidate.rule_id or "candidate.unattributed",
            reason_code=(ordered_reasons[0].value if ordered_reasons else None),
            notes=candidate.reasoning,
            parsed_value_type=candidate.parsed_recommendation.value_type,
            quality_flags=list(candidate.quality_flags),
        )


__all__ = ["AuthoritativeCatalogResolver", "VerificationReasonCode"]
