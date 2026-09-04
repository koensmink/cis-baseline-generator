from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone

from cis_pdf2csv.environment_scan.models import (
    CurrentStateSnapshot,
    ObservationScope,
    ObservedSetting,
)
from cis_pdf2csv.intune_mapper.catalog import DEFAULT_LOCAL_CATALOG
from cis_pdf2csv.intune_mapper.models import MappingInputControl, MappingStatus
from cis_pdf2csv.intune_mapper.resolver import resolve_control
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.source_identity import source_identity_for_control

from .models import (
    AssessmentStatus,
    BaselineAssessment,
    ControlAssessment,
    ExceptionDecision,
    ExceptionRecord,
    ValueComparison,
)
from .values import ComparisonResult, compare_value


def _mapping_aliases(canonical_identifier: str) -> tuple[str, ...]:
    aliases = {canonical_identifier}
    for entry in DEFAULT_LOCAL_CATALOG.find_by_identifier(canonical_identifier):
        aliases.update(
            value
            for value in (
                entry.setting_definition_id,
                entry.endpoint_security_setting_id,
                entry.csp_uri,
            )
            if value
        )
    return tuple(sorted(aliases))


def _recommendation_from_title(title: str) -> str | None:
    """Extract only an explicit CIS desired state; never use the default value."""
    normalized = " ".join(title.split()).strip()
    match = re.search(
        r"\b(?:is set to|is)\s+['\"]?"
        r"(enabled|disabled|not configured|true|false|\d+)['\"]?\s*$",
        normalized,
        flags=re.IGNORECASE,
    )
    return match.group(1) if match else None


def _mapping_input(control: ControlRecord) -> MappingInputControl:
    payload = control.model_dump()
    payload["recommendation"] = _recommendation_from_title(control.title)
    # A CIS default describes the unhardened/default state, not the desired state.
    payload["default_value"] = None
    return MappingInputControl.model_validate(payload)


def _matching_exception(
    control: ControlRecord,
    exceptions: tuple[ExceptionRecord, ...],
    at_time: datetime,
) -> tuple[ExceptionRecord | None, bool]:
    matches = [
        item
        for item in exceptions
        if item.control_id == control.control_id
        and (
            item.benchmark_name is None or item.benchmark_name == control.benchmark_name
        )
        and (
            item.benchmark_version is None
            or item.benchmark_version == control.benchmark_version
        )
    ]
    active = [item for item in matches if item.expires_at > at_time]
    if len(active) > 1:
        raise ValueError(
            f"Multiple active exceptions match {control.benchmark_name} "
            f"{control.benchmark_version} {control.control_id}"
        )
    return (active[0] if active else None), bool(matches and not active)


def _base_assessment(
    control: ControlRecord,
    *,
    status: AssessmentStatus,
    mapping_status: str,
    reason_codes: tuple[str, ...],
    exception: ExceptionRecord | None = None,
) -> ControlAssessment:
    return ControlAssessment(
        source_identity=source_identity_for_control(control),
        control_id=control.control_id,
        title=control.title,
        profile=control.profile,
        assessment=control.assessment,
        status=status,
        comparison=ValueComparison.NOT_PERFORMED,
        mapping_status=mapping_status,
        reason_codes=reason_codes,
        exception=exception,
    )


def _observations_by_identity(
    snapshot: CurrentStateSnapshot,
) -> dict[str, tuple[ObservedSetting, ...]]:
    grouped: dict[str, list[ObservedSetting]] = {}
    for policy in snapshot.policies:
        for setting in policy.settings:
            grouped.setdefault(setting.identity.casefold(), []).append(setting)
    return {
        identity: tuple(
            sorted(items, key=lambda item: (item.policy_name, item.policy_id))
        )
        for identity, items in grouped.items()
    }


def _assess_control(
    control: ControlRecord,
    *,
    observations: dict[str, tuple[ObservedSetting, ...]],
    exceptions: tuple[ExceptionRecord, ...],
    at_time: datetime,
) -> ControlAssessment:
    mapping, _ = resolve_control(_mapping_input(control))
    exception, expired = _matching_exception(control, exceptions, at_time)
    if exception is not None:
        status = (
            AssessmentStatus.NOT_APPLICABLE
            if exception.decision == ExceptionDecision.NOT_APPLICABLE
            else AssessmentStatus.EXCEPTION_ACTIVE
        )
        return _base_assessment(
            control,
            status=status,
            mapping_status=mapping.mapping_status.value,
            reason_codes=("APPROVED_EXCEPTION",),
            exception=exception,
        )
    expired_reason = ("EXCEPTION_EXPIRED",) if expired else ()
    if control.assessment == "Manual":
        return _base_assessment(
            control,
            status=AssessmentStatus.MANUAL_EVIDENCE_REQUIRED,
            mapping_status=mapping.mapping_status.value,
            reason_codes=expired_reason + ("CIS_MANUAL_ASSESSMENT",),
        )
    if (
        mapping.mapping_status != MappingStatus.VERIFIED
        or not mapping.canonical_identifier
    ):
        return _base_assessment(
            control,
            status=AssessmentStatus.NOT_MEASURABLE,
            mapping_status=mapping.mapping_status.value,
            reason_codes=expired_reason + ("MAPPING_NOT_VERIFIED",),
        )

    aliases = _mapping_aliases(mapping.canonical_identifier)
    matched = tuple(
        observation
        for alias in aliases
        for observation in observations.get(alias.casefold(), ())
    )
    if not matched:
        return _base_assessment(
            control,
            status=AssessmentStatus.NOT_MEASURABLE,
            mapping_status=mapping.mapping_status.value,
            reason_codes=expired_reason + ("SETTING_NOT_OBSERVED",),
        ).model_copy(
            update={
                "desired_value": str(mapping.value),
                "mapping_identifier": mapping.canonical_identifier,
            }
        )

    comparisons = tuple(compare_value(mapping.value, item.value) for item in matched)
    values = tuple(sorted({item.value for item in matched}))
    reasons: tuple[str, ...]
    if len(values) > 1 or (
        ComparisonResult.MATCH in comparisons
        and ComparisonResult.MISMATCH in comparisons
    ):
        status = AssessmentStatus.POTENTIAL_CONFLICT
        comparison = ValueComparison.UNKNOWN
        reasons = ("MULTIPLE_DECLARED_VALUES", "ASSIGNMENT_OVERLAP_NOT_PROVEN")
    elif all(item == ComparisonResult.MATCH for item in comparisons):
        status = AssessmentStatus.DECLARED_COMPLIANT
        comparison = ValueComparison.MATCH
        reasons = ("VERIFIED_MAPPING_VALUE_MATCH", "EFFECTIVE_STATE_NOT_OBSERVED")
    elif all(item == ComparisonResult.MISMATCH for item in comparisons):
        status = AssessmentStatus.DECLARED_NON_COMPLIANT
        comparison = ValueComparison.MISMATCH
        reasons = ("VERIFIED_MAPPING_VALUE_MISMATCH", "EFFECTIVE_STATE_NOT_OBSERVED")
    else:
        status = AssessmentStatus.NOT_MEASURABLE
        comparison = ValueComparison.UNKNOWN
        reasons = ("OBSERVED_VALUE_NOT_COMPARABLE",)

    return ControlAssessment(
        source_identity=source_identity_for_control(control),
        control_id=control.control_id,
        title=control.title,
        profile=control.profile,
        assessment=control.assessment,
        status=status,
        comparison=comparison,
        desired_value=str(mapping.value),
        observed_values=values,
        observed_setting_identities=tuple(sorted({item.identity for item in matched})),
        policy_ids=tuple(sorted({item.policy_id for item in matched})),
        policy_names=tuple(sorted({item.policy_name for item in matched})),
        mapping_status=mapping.mapping_status.value,
        mapping_identifier=mapping.canonical_identifier,
        reason_codes=expired_reason + reasons,
        evidence=tuple(
            sorted(
                f"{item.policy_name}: {item.display_name}={item.value}"
                for item in matched
            )
        ),
    )


def assess_baseline(
    controls: list[ControlRecord],
    snapshot: CurrentStateSnapshot,
    *,
    current_state_sha256: str,
    exceptions: tuple[ExceptionRecord, ...] = (),
    at_time: datetime | None = None,
) -> BaselineAssessment:
    assessed_at = (at_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
    observations = _observations_by_identity(snapshot)
    assessed = tuple(
        sorted(
            (
                _assess_control(
                    control,
                    observations=observations,
                    exceptions=exceptions,
                    at_time=assessed_at,
                )
                for control in controls
            ),
            key=lambda item: item.source_identity.as_tuple(),
        )
    )
    counts = Counter(item.status.value for item in assessed)
    warnings = ["Declared policy matches do not prove effective per-device compliance."]
    if snapshot.status.value == "partial":
        warnings.append(
            "The current-state snapshot is partial; review collection_errors."
        )
    effective = ObservationScope.EFFECTIVE_STATE in snapshot.scopes
    return BaselineAssessment(
        assessed_at_utc=assessed_at.isoformat().replace("+00:00", "Z"),
        current_state_sha256=current_state_sha256,
        current_state_status=snapshot.status.value,
        current_state_source=snapshot.provenance.source.value,
        effective_state_observed=effective,
        controls=assessed,
        status_counts=dict(sorted(counts.items())),
        warnings=tuple(warnings),
    )
