from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict

from cis_pdf2csv.source_identity import SourceIdentity

from ..boundaries import ApplicabilityMode
from ..mitigation import BoundaryRole, MitigationRole, MitigationStrength
from ..provenance import Confidence
from ..schema import Proposal
from .projection import (
    ProjectionCausalBasis,
    ProjectionEligibility,
    ThreatControlProjection,
)
from .resolution import ResolutionStatus


class ThreatRelevance(str, Enum):
    NORMAL = "Normal"
    ELEVATED = "Elevated"
    HIGH = "High"
    CRITICAL = "Critical"


class AdvisoryAction(str, Enum):
    NONE = "none"
    MONITOR = "monitor"
    REVIEW = "review"
    PRIORITIZE = "prioritize"
    URGENT_PRIORITIZE = "urgent_prioritize"


class PriorityFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str


class ThreatPriorityDriver(BaseModel):
    model_config = ConfigDict(frozen=True)

    driver_id: str
    threat_context_id: str
    threat_resolution_id: str
    mapping_id: str
    relevance: ThreatRelevance
    confidence: Confidence
    advisory_action: AdvisoryAction
    attack_path_ids: tuple[str, ...]
    boundary_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    context_technique_ids: tuple[str, ...]
    derived_technique_ids: tuple[str, ...]
    context_scenario_ids: tuple[str, ...]
    derived_scenario_ids: tuple[str, ...]
    causal_bases: tuple[ProjectionCausalBasis, ...]
    security_effect: str
    mitigation_role: MitigationRole
    mitigation_strength: MitigationStrength
    boundary_role: BoundaryRole
    applicability_mode: ApplicabilityMode
    rationale: str
    findings: tuple[PriorityFinding, ...] = ()


class ThreatInformedControlOverlay(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_identity: SourceIdentity
    control_id: str
    title: str | None = None
    base_proposal: Proposal
    threat_relevance: ThreatRelevance
    priority_confidence: Confidence
    advisory_action: AdvisoryAction
    driver_ids: tuple[str, ...]
    attack_path_ids: tuple[str, ...]
    boundary_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    context_technique_ids: tuple[str, ...]
    derived_technique_ids: tuple[str, ...]
    context_scenario_ids: tuple[str, ...]
    derived_scenario_ids: tuple[str, ...]
    threat_context_ids: tuple[str, ...]
    mitigation_roles: tuple[MitigationRole, ...]
    boundary_roles: tuple[BoundaryRole, ...]
    security_effects: tuple[str, ...]
    rationale: str
    drivers: tuple[ThreatPriorityDriver, ...]
    findings: tuple[PriorityFinding, ...] = ()

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


class ThreatPrioritySummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_projected_controls: int = 0
    normal: int = 0
    elevated: int = 0
    high: int = 0
    critical: int = 0
    review_capped_controls: int = 0
    unique_threat_contexts: int = 0
    unique_attack_paths: int = 0
    unique_boundaries: int = 0
    controls_by_base_proposal: tuple[tuple[str, int], ...] = ()
    controls_by_mitigation_role: tuple[tuple[str, int], ...] = ()

    def to_deterministic_json(self) -> str:
        return (
            json.dumps(
                self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            )
            + "\n"
        )


_CONFIDENCE_ORDER = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_RELEVANCE_ORDER = {
    ThreatRelevance.NORMAL: 0,
    ThreatRelevance.ELEVATED: 1,
    ThreatRelevance.HIGH: 2,
    ThreatRelevance.CRITICAL: 3,
}
_CORE_ROLES = {
    BoundaryRole.STANDALONE_PRIMARY_BOUNDARY,
    BoundaryRole.BOUNDARY_SET_CORE_MEMBER,
    BoundaryRole.PREREQUISITE,
}
_DIRECT_MITIGATIONS = {
    MitigationRole.PREVENT,
    MitigationRole.RESTRICT,
    MitigationRole.ISOLATE,
    MitigationRole.PROTECT,
}
_NORMAL_ROLES = {
    BoundaryRole.FINE_TUNING,
    BoundaryRole.INFORMATION_HIDING,
    BoundaryRole.OPERATIONAL,
}
_REVIEW_CAP_CODES = {
    "THREAT_PRIORITY_AMBIGUOUS_EQUIVALENCE",
    "THREAT_PRIORITY_APPLICABILITY_CAP",
    "THREAT_PRIORITY_CONFIDENCE_CAP",
    "THREAT_PRIORITY_PARTIAL_RESOLUTION_CAP",
    "THREAT_PRIORITY_PROJECTION_REVIEW_CAP",
}


def _minimum_confidence(projection: ThreatControlProjection) -> Confidence:
    return min(
        (projection.resolution_confidence, projection.mapping_confidence),
        key=_CONFIDENCE_ORDER.__getitem__,
    )


def _ambiguous_projection_ids(
    projections: tuple[ThreatControlProjection, ...],
) -> set[tuple[str, str, str]]:
    grouped: dict[
        tuple[str, tuple[str, ...], str, str, str], list[ThreatControlProjection]
    ] = defaultdict(list)
    for item in projections:
        grouped[
            (
                item.threat_resolution_id,
                item.attack_path_ids,
                item.boundary_ids[0] if item.boundary_ids else "",
                item.security_effect,
                item.applicability_mode.value,
            )
        ].append(item)
    ambiguous: set[tuple[str, str, str]] = set()
    for values in grouped.values():
        primary_sources = {
            item.source_identity.serialize()
            for item in values
            if item.mitigation_strength == MitigationStrength.PRIMARY
        }
        if len(primary_sources) > 1:
            ambiguous.update(
                (
                    item.source_identity.serialize(),
                    item.mapping_id,
                    item.threat_context_id,
                )
                for item in values
                if item.mitigation_strength == MitigationStrength.PRIMARY
            )
    return ambiguous


def _driver(
    projection: ThreatControlProjection,
    *,
    ambiguous_equivalence: bool,
) -> ThreatPriorityDriver:
    confidence = _minimum_confidence(projection)
    findings: list[PriorityFinding] = []

    def cap(code: str, message: str) -> None:
        findings.append(PriorityFinding(code=code, message=message))

    relevance = ThreatRelevance.NORMAL
    has_causal_basis = bool(projection.causal_bases)
    if projection.eligibility == ProjectionEligibility.INELIGIBLE:
        cap(
            "THREAT_PRIORITY_ROLE_NORMAL_CEILING",
            "An ineligible projection has a Normal ceiling.",
        )
    elif projection.boundary_role in _NORMAL_ROLES:
        cap(
            "THREAT_PRIORITY_ROLE_NORMAL_CEILING",
            f"Boundary role {projection.boundary_role.value} has a Normal ceiling.",
        )
    elif not has_causal_basis:
        cap(
            "THREAT_PRIORITY_CAUSAL_BASIS_REQUIRED",
            "Attack-path proximity without a resolved boundary or exact explicit-technique mapping does not establish Elevated relevance.",
        )
    elif projection.boundary_role in {
        BoundaryRole.SUPPORTING_HARDENING,
        BoundaryRole.DETECTION_ONLY,
    } or projection.mitigation_role in {
        MitigationRole.DETECT,
        MitigationRole.INVESTIGATE,
        MitigationRole.RECOVER,
    }:
        relevance = ThreatRelevance.ELEVATED
        cap(
            "THREAT_PRIORITY_SUPPORTING_CEILING",
            "Supporting, detection, investigation, and recovery effects are capped at Elevated.",
        )
    elif (
        ProjectionCausalBasis.RESOLVED_BOUNDARY in projection.causal_bases
        and projection.boundary_role in _CORE_ROLES
        and projection.mitigation_strength
        in {MitigationStrength.PRIMARY, MitigationStrength.COMPLEMENTARY}
        and projection.mitigation_role in _DIRECT_MITIGATIONS
    ):
        relevance = ThreatRelevance.HIGH
    else:
        relevance = ThreatRelevance.ELEVATED

    if projection.resolution_status != ResolutionStatus.RESOLVED:
        relevance = min(
            relevance, ThreatRelevance.ELEVATED, key=_RELEVANCE_ORDER.__getitem__
        )
        cap(
            "THREAT_PRIORITY_PARTIAL_RESOLUTION_CAP",
            f"Resolution status {projection.resolution_status.value} prevents High relevance.",
        )
    if confidence != Confidence.HIGH:
        relevance = min(
            relevance, ThreatRelevance.ELEVATED, key=_RELEVANCE_ORDER.__getitem__
        )
        cap(
            "THREAT_PRIORITY_CONFIDENCE_CAP",
            f"Conservative priority confidence is {confidence.value}.",
        )
    if projection.applicability_mode != ApplicabilityMode.UNIVERSAL:
        relevance = min(
            relevance, ThreatRelevance.ELEVATED, key=_RELEVANCE_ORDER.__getitem__
        )
        cap(
            "THREAT_PRIORITY_APPLICABILITY_CAP",
            f"Control applicability is {projection.applicability_mode.value}; deployment is not inferred.",
        )
    if projection.eligibility == ProjectionEligibility.REVIEW_REQUIRED:
        relevance = min(
            relevance, ThreatRelevance.ELEVATED, key=_RELEVANCE_ORDER.__getitem__
        )
        cap(
            "THREAT_PRIORITY_PROJECTION_REVIEW_CAP",
            "Projection findings require review before escalation.",
        )
    if ambiguous_equivalence or projection.overlap_type in {"duplicate", "alternative"}:
        relevance = min(
            relevance, ThreatRelevance.ELEVATED, key=_RELEVANCE_ORDER.__getitem__
        )
        cap(
            "THREAT_PRIORITY_AMBIGUOUS_EQUIVALENCE",
            "Existing overlap evidence does not select a unique primary implementation.",
        )

    findings.extend(
        PriorityFinding(code=item.code, message=item.message)
        for item in projection.findings
    )
    unique_findings = {(item.code, item.message): item for item in findings}
    ordered_findings = tuple(unique_findings[key] for key in sorted(unique_findings))
    review_capped = any(item.code in _REVIEW_CAP_CODES for item in ordered_findings)
    action = {
        ThreatRelevance.NORMAL: AdvisoryAction.NONE,
        ThreatRelevance.ELEVATED: AdvisoryAction.REVIEW
        if review_capped
        else AdvisoryAction.MONITOR,
        ThreatRelevance.HIGH: AdvisoryAction.PRIORITIZE,
        ThreatRelevance.CRITICAL: AdvisoryAction.URGENT_PRIORITIZE,
    }[relevance]
    cap_text = (
        "; ".join(item.message for item in ordered_findings)
        or "No priority cap applies."
    )
    basis_text = ", ".join(item.value for item in projection.causal_bases) or "none"
    rationale = (
        f"Threat {projection.threat_context_id} resolves attack path {', '.join(projection.attack_path_ids)} "
        f"and boundary {', '.join(projection.boundary_ids) or 'unresolved'}; mapping {projection.mapping_id} "
        f"enforces {projection.security_effect} as {projection.mitigation_role.value}/"
        f"{projection.boundary_role.value} ({projection.mitigation_strength.value}). "
        f"Causal basis: {basis_text}. Explicit context techniques: "
        f"{', '.join(projection.context_technique_ids) or 'none'}; derived path techniques: "
        f"{', '.join(projection.derived_technique_ids) or 'none'}. "
        f"This produces {relevance.value} relevance at {confidence.value} confidence. "
        f"Base proposal remains {projection.base_proposal.value}. Cap rationale: {cap_text}"
    )
    return ThreatPriorityDriver(
        driver_id=f"{projection.threat_resolution_id}|{projection.mapping_id}",
        threat_context_id=projection.threat_context_id,
        threat_resolution_id=projection.threat_resolution_id,
        mapping_id=projection.mapping_id,
        relevance=relevance,
        confidence=confidence,
        advisory_action=action,
        attack_path_ids=projection.attack_path_ids,
        boundary_ids=projection.boundary_ids,
        technique_ids=projection.technique_ids,
        context_technique_ids=projection.context_technique_ids,
        derived_technique_ids=projection.derived_technique_ids,
        context_scenario_ids=projection.context_scenario_ids,
        derived_scenario_ids=projection.derived_scenario_ids,
        causal_bases=projection.causal_bases,
        security_effect=projection.security_effect,
        mitigation_role=projection.mitigation_role,
        mitigation_strength=projection.mitigation_strength,
        boundary_role=projection.boundary_role,
        applicability_mode=projection.applicability_mode,
        rationale=rationale,
        findings=ordered_findings,
    )


def prioritize_threat_projections(
    projections: Iterable[ThreatControlProjection],
) -> tuple[ThreatInformedControlOverlay, ...]:
    """Create an advisory overlay without changing any base proposal."""
    items = tuple(
        sorted(
            projections,
            key=lambda item: (
                item.source_identity.as_tuple(),
                item.threat_context_id,
                item.mapping_id,
            ),
        )
    )
    ambiguous = _ambiguous_projection_ids(items)
    grouped: dict[
        SourceIdentity, list[tuple[ThreatControlProjection, ThreatPriorityDriver]]
    ] = defaultdict(list)
    for item in items:
        key = (
            item.source_identity.serialize(),
            item.mapping_id,
            item.threat_context_id,
        )
        grouped[item.source_identity].append(
            (item, _driver(item, ambiguous_equivalence=key in ambiguous))
        )

    overlays: list[ThreatInformedControlOverlay] = []
    for identity in sorted(grouped, key=lambda item: item.as_tuple()):
        values = grouped[identity]
        first = values[0][0]
        if any(item.base_proposal != first.base_proposal for item, _ in values):
            raise ValueError(
                "A SourceIdentity has conflicting immutable base proposals"
            )
        drivers = tuple(
            sorted((driver for _, driver in values), key=lambda item: item.driver_id)
        )
        relevance = max(
            (item.relevance for item in drivers), key=_RELEVANCE_ORDER.__getitem__
        )
        winning = tuple(item for item in drivers if item.relevance == relevance)
        confidence = min(
            (item.confidence for item in winning), key=_CONFIDENCE_ORDER.__getitem__
        )
        review_capped = any(
            item.code in _REVIEW_CAP_CODES
            for driver in winning
            for item in driver.findings
        )
        action = {
            ThreatRelevance.NORMAL: AdvisoryAction.NONE,
            ThreatRelevance.ELEVATED: AdvisoryAction.REVIEW
            if review_capped
            else AdvisoryAction.MONITOR,
            ThreatRelevance.HIGH: AdvisoryAction.PRIORITIZE,
            ThreatRelevance.CRITICAL: AdvisoryAction.URGENT_PRIORITIZE,
        }[relevance]
        finding_map = {
            (item.code, item.message): item
            for driver in drivers
            for item in driver.findings
        }
        overlays.append(
            ThreatInformedControlOverlay(
                source_identity=identity,
                control_id=identity.control_id,
                title=first.title,
                base_proposal=first.base_proposal,
                threat_relevance=relevance,
                priority_confidence=confidence,
                advisory_action=action,
                driver_ids=tuple(item.driver_id for item in drivers),
                attack_path_ids=tuple(
                    sorted(
                        {value for item in drivers for value in item.attack_path_ids}
                    )
                ),
                boundary_ids=tuple(
                    sorted({value for item in drivers for value in item.boundary_ids})
                ),
                technique_ids=tuple(
                    sorted({value for item in drivers for value in item.technique_ids})
                ),
                context_technique_ids=tuple(
                    sorted(
                        {
                            value
                            for item in drivers
                            for value in item.context_technique_ids
                        }
                    )
                ),
                derived_technique_ids=tuple(
                    sorted(
                        {
                            value
                            for item in drivers
                            for value in item.derived_technique_ids
                        }
                    )
                ),
                context_scenario_ids=tuple(
                    sorted(
                        {
                            value
                            for item in drivers
                            for value in item.context_scenario_ids
                        }
                    )
                ),
                derived_scenario_ids=tuple(
                    sorted(
                        {
                            value
                            for item in drivers
                            for value in item.derived_scenario_ids
                        }
                    )
                ),
                threat_context_ids=tuple(
                    sorted({item.threat_context_id for item in drivers})
                ),
                mitigation_roles=tuple(
                    sorted(
                        {item.mitigation_role for item in drivers},
                        key=lambda item: item.value,
                    )
                ),
                boundary_roles=tuple(
                    sorted(
                        {item.boundary_role for item in drivers},
                        key=lambda item: item.value,
                    )
                ),
                security_effects=tuple(
                    sorted({item.security_effect for item in drivers})
                ),
                rationale=(
                    f"Aggregate {relevance.value} relevance is determined by "
                    f"{', '.join(item.driver_id for item in winning)}. "
                    + " ".join(item.rationale for item in drivers)
                ),
                drivers=drivers,
                findings=tuple(finding_map[key] for key in sorted(finding_map)),
            )
        )
    return tuple(overlays)


def summarize_threat_priority(
    overlays: Iterable[ThreatInformedControlOverlay],
) -> ThreatPrioritySummary:
    items = tuple(overlays)
    relevance = Counter(item.threat_relevance for item in items)
    proposals = Counter(item.base_proposal.value for item in items)
    roles = Counter(role.value for item in items for role in item.mitigation_roles)
    return ThreatPrioritySummary(
        total_projected_controls=len(items),
        normal=relevance[ThreatRelevance.NORMAL],
        elevated=relevance[ThreatRelevance.ELEVATED],
        high=relevance[ThreatRelevance.HIGH],
        critical=relevance[ThreatRelevance.CRITICAL],
        review_capped_controls=sum(
            item.advisory_action == AdvisoryAction.REVIEW for item in items
        ),
        unique_threat_contexts=len(
            {value for item in items for value in item.threat_context_ids}
        ),
        unique_attack_paths=len(
            {value for item in items for value in item.attack_path_ids}
        ),
        unique_boundaries=len({value for item in items for value in item.boundary_ids}),
        controls_by_base_proposal=tuple(sorted(proposals.items())),
        controls_by_mitigation_role=tuple(sorted(roles.items())),
    )


__all__ = [
    "AdvisoryAction",
    "PriorityFinding",
    "ThreatInformedControlOverlay",
    "ThreatPriorityDriver",
    "ThreatPrioritySummary",
    "ThreatRelevance",
    "prioritize_threat_projections",
    "summarize_threat_priority",
]
