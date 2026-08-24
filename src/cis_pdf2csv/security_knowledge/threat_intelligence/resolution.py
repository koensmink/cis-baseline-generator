from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict

from ..catalog.registry import AttackPath, SecurityKnowledgeCatalog
from ..provenance import Confidence, LifecycleStatus
from .schema import ThreatApplicabilityScope, ThreatContext


class ResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    PARTIALLY_RESOLVED = "partially_resolved"
    REVIEW_REQUIRED = "review_required"
    UNRESOLVED = "unresolved"
    INACTIVE = "inactive"


class KnowledgeObjectType(str, Enum):
    THREAT_SCENARIO = "threat_scenario"
    ATTACK_TECHNIQUE = "attack_technique"
    ATTACK_PATH = "attack_path"
    SECURITY_BOUNDARY = "security_boundary"
    SECURITY_OUTCOME = "security_outcome"


class RelationshipSource(str, Enum):
    EXPLICIT_THREAT_CONTEXT_REFERENCE = "explicit_threat_context_reference"
    CATALOG_ATTACK_PATH_RELATIONSHIP = "catalog_attack_path_relationship"
    CATALOG_TECHNIQUE_RELATIONSHIP = "catalog_technique_relationship"
    CATALOG_SCENARIO_RELATIONSHIP = "catalog_scenario_relationship"


class FindingSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ResolvedKnowledgeReference(BaseModel):
    model_config = ConfigDict(frozen=True)

    object_id: str
    object_type: KnowledgeObjectType
    relationship_source: RelationshipSource
    originating_threat_context_id: str
    confidence: Confidence
    evidence_reference_ids: tuple[str, ...] = ()


class ResolutionFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    severity: FindingSeverity
    object_type: str
    object_id: str
    message: str
    successor_candidate_ids: tuple[str, ...] = ()
    lifecycle_reason: str | None = None


class ResolutionPath(BaseModel):
    model_config = ConfigDict(frozen=True)

    attack_path: ResolvedKnowledgeReference
    threat_scenarios: tuple[ResolvedKnowledgeReference, ...] = ()
    techniques: tuple[ResolvedKnowledgeReference, ...] = ()
    boundaries: tuple[ResolvedKnowledgeReference, ...] = ()
    outcomes: tuple[ResolvedKnowledgeReference, ...] = ()


class ThreatResolution(BaseModel):
    model_config = ConfigDict(frozen=True)

    threat_context_id: str
    threat_context_revision: str
    status: ResolutionStatus
    confidence: Confidence
    historical_mode: bool
    affected_technology_families: tuple[str, ...] = ()
    applicability_scope: ThreatApplicabilityScope
    targeted_asset_classes: tuple[str, ...] = ()
    threat_scenarios: tuple[ResolvedKnowledgeReference, ...] = ()
    techniques: tuple[ResolvedKnowledgeReference, ...] = ()
    attack_paths: tuple[ResolvedKnowledgeReference, ...] = ()
    boundaries: tuple[ResolvedKnowledgeReference, ...] = ()
    outcomes: tuple[ResolvedKnowledgeReference, ...] = ()
    findings: tuple[ResolutionFinding, ...] = ()
    resolution_paths: tuple[ResolutionPath, ...] = ()

    def to_deterministic_json(self) -> str:
        return (
            json.dumps(
                self.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        )


class ResolutionCoverageReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    resolved: int = 0
    partially_resolved: int = 0
    review_required: int = 0
    unresolved: int = 0
    inactive: int = 0
    referenced_techniques: int = 0
    resolved_attack_paths: int = 0
    resolved_boundaries: int = 0
    resolved_outcomes: int = 0
    unresolved_external_catalog_references: int = 0

    def to_deterministic_json(self) -> str:
        return (
            json.dumps(
                self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            )
            + "\n"
        )


_CONFIDENCE_ORDER = {
    Confidence.LOW.value: 0,
    Confidence.MEDIUM.value: 1,
    Confidence.HIGH.value: 2,
}
_UNKNOWN_REFERENCE_CODES = {
    "THREAT_RESOLUTION_UNKNOWN_ATTACK_PATH",
    "THREAT_RESOLUTION_UNKNOWN_TECHNIQUE",
    "THREAT_RESOLUTION_UNKNOWN_THREAT_SCENARIO",
}


def _lower_confidence(*values: str | Confidence) -> Confidence:
    """Return the least confident input; catalog relations can only lower confidence."""
    normalized = [
        value.value if isinstance(value, Confidence) else value for value in values
    ]
    return Confidence(min(normalized, key=_CONFIDENCE_ORDER.__getitem__))


def _evidence_ids(context: ThreatContext) -> tuple[str, ...]:
    return tuple(
        sorted(
            {context.source_reference}
            | {item.external_reference for item in context.evidence}
        )
    )


def _reference(
    context: ThreatContext,
    object_id: str,
    object_type: KnowledgeObjectType,
    source: RelationshipSource,
    *confidences: str | Confidence,
) -> ResolvedKnowledgeReference:
    return ResolvedKnowledgeReference(
        object_id=object_id,
        object_type=object_type,
        relationship_source=source,
        originating_threat_context_id=context.threat_context_id,
        confidence=_lower_confidence(context.confidence, *confidences),
        evidence_reference_ids=_evidence_ids(context),
    )


def _finding(
    code: str,
    severity: FindingSeverity,
    object_type: str,
    object_id: str,
    message: str,
    *,
    successors: Sequence[str] = (),
    lifecycle_reason: str | None = None,
) -> ResolutionFinding:
    return ResolutionFinding(
        code=code,
        severity=severity,
        object_type=object_type,
        object_id=object_id,
        message=message,
        successor_candidate_ids=tuple(sorted(set(successors))),
        lifecycle_reason=lifecycle_reason,
    )


def _successors(item: object, active_ids: set[str]) -> tuple[str, ...]:
    candidates = set(getattr(item, "successor_ids", ()))
    return tuple(sorted(candidates & active_ids))


def _active_or_historical(
    item: Any,
    *,
    historical_mode: bool,
) -> bool:
    return historical_mode or item.lifecycle_status == LifecycleStatus.ACTIVE.value


_SOURCE_PRECEDENCE = {
    RelationshipSource.EXPLICIT_THREAT_CONTEXT_REFERENCE: 0,
    RelationshipSource.CATALOG_ATTACK_PATH_RELATIONSHIP: 1,
    RelationshipSource.CATALOG_TECHNIQUE_RELATIONSHIP: 2,
    RelationshipSource.CATALOG_SCENARIO_RELATIONSHIP: 3,
}


def _unique_references(
    items: Iterable[ResolvedKnowledgeReference],
) -> tuple[ResolvedKnowledgeReference, ...]:
    unique: dict[tuple[str, str], ResolvedKnowledgeReference] = {}
    for item in items:
        key = (item.object_type.value, item.object_id)
        current = unique.get(key)
        if (
            current is None
            or _SOURCE_PRECEDENCE[item.relationship_source]
            < _SOURCE_PRECEDENCE[current.relationship_source]
        ):
            unique[key] = item
    return tuple(unique[key] for key in sorted(unique))


def _sorted_findings(
    items: Iterable[ResolutionFinding],
) -> tuple[ResolutionFinding, ...]:
    return tuple(
        sorted(
            items,
            key=lambda item: (
                item.code,
                item.object_type,
                item.object_id,
                item.successor_candidate_ids,
                item.message,
            ),
        )
    )


def _resolution(
    context: ThreatContext,
    historical_mode: bool,
    status: ResolutionStatus,
    *,
    confidence: Confidence | None = None,
    **updates: Any,
) -> ThreatResolution:
    return ThreatResolution(
        threat_context_id=context.threat_context_id,
        threat_context_revision=context.provenance.object_version,
        status=status,
        confidence=context.confidence if confidence is None else confidence,
        historical_mode=historical_mode,
        affected_technology_families=tuple(
            sorted(set(context.affected_technology_families))
        ),
        applicability_scope=context.applicability_scope,
        targeted_asset_classes=tuple(sorted(set(context.targeted_asset_classes))),
        **updates,
    )


def resolve_threat_context(
    context: ThreatContext,
    catalog: SecurityKnowledgeCatalog,
    *,
    at_time: datetime,
    historical_mode: bool = False,
) -> ThreatResolution:
    """Resolve only asserted catalog IDs and authoritative catalog relationships."""
    if at_time.tzinfo is None or at_time.utcoffset() is None:
        raise ValueError("at_time must be timezone-aware")

    window_is_valid = not (
        context.valid_from is not None
        and context.valid_until is not None
        and context.valid_from >= context.valid_until
    )
    aware_times = all(
        value is None or (value.tzinfo is not None and value.utcoffset() is not None)
        for value in (context.valid_from, context.valid_until)
    )
    if not aware_times or not window_is_valid:
        finding = _finding(
            "THREAT_RESOLUTION_INVALID_TEMPORAL_WINDOW",
            FindingSeverity.ERROR,
            "threat_context",
            context.threat_context_id,
            "The threat validity window is invalid or lacks timezone information.",
        )
        return _resolution(
            context,
            historical_mode,
            ResolutionStatus.UNRESOLVED,
            findings=(finding,),
        )

    if not historical_mode and not context.is_active(at_time):
        return _resolution(context, historical_mode, ResolutionStatus.INACTIVE)

    if context.applicability_scope == ThreatApplicabilityScope.UNRESOLVED:
        finding = _finding(
            "THREAT_RESOLUTION_APPLICABILITY_BLOCKER",
            FindingSeverity.ERROR,
            "threat_context",
            context.threat_context_id,
            "Unresolved applicability materially prevents active knowledge resolution.",
        )
        return _resolution(
            context,
            historical_mode,
            ResolutionStatus.UNRESOLVED,
            findings=(finding,),
        )

    technique_by_id = {item.technique_id: item for item in catalog.attack_techniques}
    scenario_by_id = {
        item.threat_scenario_id: item for item in catalog.threat_scenarios
    }
    path_by_id = {item.attack_path_id: item for item in catalog.attack_paths}
    boundary_by_id = {item.boundary_id: item for item in catalog.boundary_definitions}
    outcome_by_id = {item.outcome_id: item for item in catalog.security_outcomes}
    paths_by_technique: dict[str, list[AttackPath]] = defaultdict(list)
    paths_by_scenario: dict[str, list[AttackPath]] = defaultdict(list)
    for path in sorted(catalog.attack_paths, key=lambda item: item.attack_path_id):
        if not _active_or_historical(path, historical_mode=historical_mode):
            continue
        for identifier in path.technique_ids:
            paths_by_technique[identifier].append(path)
        for identifier in path.threat_scenario_ids:
            paths_by_scenario[identifier].append(path)

    findings: list[ResolutionFinding] = []
    direct_techniques: list[ResolvedKnowledgeReference] = []
    direct_scenarios: list[ResolvedKnowledgeReference] = []
    selected_paths: dict[str, tuple[AttackPath, RelationshipSource]] = {}
    review_required = False
    blocking_unknown = False

    def inspect_explicit(
        identifier: str,
        item: Any | None,
        object_type: KnowledgeObjectType,
        active_ids: set[str],
    ) -> bool:
        nonlocal review_required, blocking_unknown
        if item is None:
            code = {
                KnowledgeObjectType.ATTACK_PATH: "THREAT_RESOLUTION_UNKNOWN_ATTACK_PATH",
                KnowledgeObjectType.ATTACK_TECHNIQUE: "THREAT_RESOLUTION_UNKNOWN_TECHNIQUE",
                KnowledgeObjectType.THREAT_SCENARIO: "THREAT_RESOLUTION_UNKNOWN_THREAT_SCENARIO",
            }[object_type]
            findings.append(
                _finding(
                    code,
                    FindingSeverity.ERROR,
                    object_type.value,
                    identifier,
                    "The explicit catalog reference is unknown.",
                )
            )
            if object_type in {
                KnowledgeObjectType.ATTACK_PATH,
                KnowledgeObjectType.ATTACK_TECHNIQUE,
            }:
                blocking_unknown = True
            return False
        lifecycle = str(item.lifecycle_status)
        if lifecycle == LifecycleStatus.ACTIVE.value or historical_mode:
            if historical_mode and lifecycle != LifecycleStatus.ACTIVE.value:
                findings.append(
                    _finding(
                        "THREAT_RESOLUTION_HISTORICAL_REFERENCE",
                        FindingSeverity.INFO,
                        object_type.value,
                        identifier,
                        "Historical mode explicitly retained an inactive catalog object.",
                        lifecycle_reason=lifecycle,
                    )
                )
            return True
        review_required = True
        successors = _successors(item, active_ids)
        if lifecycle == LifecycleStatus.SUPERSEDED.value:
            if len(successors) == 1:
                code = "THREAT_RESOLUTION_SUCCESSOR_REVIEW_REQUIRED"
            elif successors:
                code = "THREAT_RESOLUTION_MULTIPLE_SUCCESSORS_REVIEW_REQUIRED"
            else:
                code = "THREAT_RESOLUTION_NO_SUCCESSOR_REVIEW_REQUIRED"
        else:
            code = "THREAT_RESOLUTION_DEPRECATED_REFERENCE_REVIEW_REQUIRED"
        findings.append(
            _finding(
                code,
                FindingSeverity.WARNING,
                object_type.value,
                identifier,
                "An inactive explicit catalog reference was preserved and was not remapped.",
                successors=successors,
                lifecycle_reason=lifecycle,
            )
        )
        return False

    active_path_ids = {
        key
        for key, value in path_by_id.items()
        if value.lifecycle_status == LifecycleStatus.ACTIVE.value
    }
    active_technique_ids = {
        key
        for key, value in technique_by_id.items()
        if value.lifecycle_status == LifecycleStatus.ACTIVE.value
    }
    active_scenario_ids = {
        key
        for key, value in scenario_by_id.items()
        if value.lifecycle_status == LifecycleStatus.ACTIVE.value
    }

    for identifier in sorted(set(context.attack_path_ids)):
        path_item = path_by_id.get(identifier)
        if inspect_explicit(
            identifier, path_item, KnowledgeObjectType.ATTACK_PATH, active_path_ids
        ):
            assert path_item is not None
            selected_paths[identifier] = (
                path_item,
                RelationshipSource.EXPLICIT_THREAT_CONTEXT_REFERENCE,
            )
    for identifier in sorted(set(context.technique_ids)):
        technique_item = technique_by_id.get(identifier)
        if inspect_explicit(
            identifier,
            technique_item,
            KnowledgeObjectType.ATTACK_TECHNIQUE,
            active_technique_ids,
        ):
            assert technique_item is not None
            direct_techniques.append(
                _reference(
                    context,
                    identifier,
                    KnowledgeObjectType.ATTACK_TECHNIQUE,
                    RelationshipSource.EXPLICIT_THREAT_CONTEXT_REFERENCE,
                    technique_item.confidence,
                )
            )
            for path in paths_by_technique.get(identifier, ()):
                selected_paths.setdefault(
                    path.attack_path_id,
                    (path, RelationshipSource.CATALOG_TECHNIQUE_RELATIONSHIP),
                )
    for identifier in sorted(set(context.threat_scenario_ids)):
        scenario_item = scenario_by_id.get(identifier)
        if inspect_explicit(
            identifier,
            scenario_item,
            KnowledgeObjectType.THREAT_SCENARIO,
            active_scenario_ids,
        ):
            assert scenario_item is not None
            direct_scenarios.append(
                _reference(
                    context,
                    identifier,
                    KnowledgeObjectType.THREAT_SCENARIO,
                    RelationshipSource.EXPLICIT_THREAT_CONTEXT_REFERENCE,
                    scenario_item.confidence,
                )
            )
            for path in paths_by_scenario.get(identifier, ()):
                selected_paths.setdefault(
                    path.attack_path_id,
                    (path, RelationshipSource.CATALOG_SCENARIO_RELATIONSHIP),
                )

    if blocking_unknown:
        return _resolution(
            context,
            historical_mode,
            ResolutionStatus.UNRESOLVED,
            techniques=_unique_references(direct_techniques),
            threat_scenarios=_unique_references(direct_scenarios),
            findings=_sorted_findings(findings),
        )

    path_references: list[ResolvedKnowledgeReference] = []
    scenario_references = list(direct_scenarios)
    technique_references = list(direct_techniques)
    boundary_references: list[ResolvedKnowledgeReference] = []
    outcome_references: list[ResolvedKnowledgeReference] = []
    resolution_paths: list[ResolutionPath] = []
    incomplete = any(
        finding.code == "THREAT_RESOLUTION_UNKNOWN_THREAT_SCENARIO"
        for finding in findings
    )

    for path_id in sorted(selected_paths):
        path, path_source = selected_paths[path_id]
        path_ref = _reference(
            context,
            path_id,
            KnowledgeObjectType.ATTACK_PATH,
            path_source,
            path.confidence,
        )
        path_references.append(path_ref)
        path_scenarios: list[ResolvedKnowledgeReference] = []
        path_techniques: list[ResolvedKnowledgeReference] = []
        path_boundaries: list[ResolvedKnowledgeReference] = []
        path_outcomes: list[ResolvedKnowledgeReference] = []
        for identifier in sorted(set(path.threat_scenario_ids)):
            related_scenario = scenario_by_id.get(identifier)
            if related_scenario is not None and _active_or_historical(
                related_scenario, historical_mode=historical_mode
            ):
                ref = _reference(
                    context,
                    identifier,
                    KnowledgeObjectType.THREAT_SCENARIO,
                    RelationshipSource.CATALOG_ATTACK_PATH_RELATIONSHIP,
                    path.confidence,
                    related_scenario.confidence,
                )
                path_scenarios.append(ref)
                scenario_references.append(ref)
        for identifier in sorted(set(path.technique_ids)):
            related_technique = technique_by_id.get(identifier)
            if related_technique is not None and _active_or_historical(
                related_technique, historical_mode=historical_mode
            ):
                ref = _reference(
                    context,
                    identifier,
                    KnowledgeObjectType.ATTACK_TECHNIQUE,
                    RelationshipSource.CATALOG_ATTACK_PATH_RELATIONSHIP,
                    path.confidence,
                    related_technique.confidence,
                )
                path_techniques.append(ref)
                technique_references.append(ref)
        for identifier in sorted(set(path.boundary_ids)):
            related_boundary = boundary_by_id.get(identifier)
            if related_boundary is not None and _active_or_historical(
                related_boundary, historical_mode=historical_mode
            ):
                ref = _reference(
                    context,
                    identifier,
                    KnowledgeObjectType.SECURITY_BOUNDARY,
                    RelationshipSource.CATALOG_ATTACK_PATH_RELATIONSHIP,
                    path.confidence,
                )
                path_boundaries.append(ref)
                boundary_references.append(ref)
        for identifier in sorted(set(path.security_outcome_ids)):
            related_outcome = outcome_by_id.get(identifier)
            if related_outcome is not None and _active_or_historical(
                related_outcome, historical_mode=historical_mode
            ):
                ref = _reference(
                    context,
                    identifier,
                    KnowledgeObjectType.SECURITY_OUTCOME,
                    RelationshipSource.CATALOG_ATTACK_PATH_RELATIONSHIP,
                    path.confidence,
                )
                path_outcomes.append(ref)
                outcome_references.append(ref)
        for missing, values in (
            ("THREAT_SCENARIO", path_scenarios),
            ("TECHNIQUE", path_techniques),
            ("BOUNDARY", path_boundaries),
            ("OUTCOME", path_outcomes),
        ):
            if not values:
                incomplete = True
                findings.append(
                    _finding(
                        f"THREAT_RESOLUTION_PATH_WITHOUT_{missing}",
                        FindingSeverity.WARNING,
                        "attack_path",
                        path_id,
                        f"The resolved attack path has no active {missing.lower()} relationship.",
                    )
                )
        resolution_paths.append(
            ResolutionPath(
                attack_path=path_ref,
                threat_scenarios=_unique_references(path_scenarios),
                techniques=_unique_references(path_techniques),
                boundaries=_unique_references(path_boundaries),
                outcomes=_unique_references(path_outcomes),
            )
        )

    any_references = bool(direct_techniques or direct_scenarios or path_references)
    if review_required:
        status = ResolutionStatus.REVIEW_REQUIRED
    elif not any_references:
        status = ResolutionStatus.UNRESOLVED
        if not findings:
            findings.append(
                _finding(
                    "THREAT_RESOLUTION_NO_EXPLICIT_KNOWLEDGE_REFERENCE",
                    FindingSeverity.WARNING,
                    "threat_context",
                    context.threat_context_id,
                    "No catalog IDs were asserted; free-text inference is outside Phase 2.",
                )
            )
    elif not path_references or incomplete:
        status = ResolutionStatus.PARTIALLY_RESOLVED
    else:
        status = ResolutionStatus.RESOLVED

    all_refs = [
        *scenario_references,
        *technique_references,
        *path_references,
        *boundary_references,
        *outcome_references,
    ]
    resolution_confidence = (
        _lower_confidence(*(ref.confidence for ref in all_refs))
        if all_refs
        else context.confidence
    )
    return _resolution(
        context,
        historical_mode,
        status,
        confidence=resolution_confidence,
        threat_scenarios=_unique_references(scenario_references),
        techniques=_unique_references(technique_references),
        attack_paths=_unique_references(path_references),
        boundaries=_unique_references(boundary_references),
        outcomes=_unique_references(outcome_references),
        findings=_sorted_findings(findings),
        resolution_paths=tuple(resolution_paths),
    )


def build_resolution_coverage_report(
    resolutions: Iterable[ThreatResolution],
) -> ResolutionCoverageReport:
    items = tuple(resolutions)
    statuses = Counter(item.status.value for item in items)
    return ResolutionCoverageReport(
        resolved=statuses[ResolutionStatus.RESOLVED.value],
        partially_resolved=statuses[ResolutionStatus.PARTIALLY_RESOLVED.value],
        review_required=statuses[ResolutionStatus.REVIEW_REQUIRED.value],
        unresolved=statuses[ResolutionStatus.UNRESOLVED.value],
        inactive=statuses[ResolutionStatus.INACTIVE.value],
        referenced_techniques=sum(len(item.techniques) for item in items),
        resolved_attack_paths=sum(len(item.attack_paths) for item in items),
        resolved_boundaries=sum(len(item.boundaries) for item in items),
        resolved_outcomes=sum(len(item.outcomes) for item in items),
        unresolved_external_catalog_references=sum(
            finding.code in _UNKNOWN_REFERENCE_CODES
            for item in items
            for finding in item.findings
        ),
    )


__all__ = [
    "FindingSeverity",
    "KnowledgeObjectType",
    "RelationshipSource",
    "ResolutionCoverageReport",
    "ResolutionFinding",
    "ResolutionPath",
    "ResolutionStatus",
    "ResolvedKnowledgeReference",
    "ThreatResolution",
    "build_resolution_coverage_report",
    "resolve_threat_context",
]
