from __future__ import annotations

import json
from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict

from cis_pdf2csv.mandatory.schema import MandatoryAssessment
from cis_pdf2csv.source_identity import SourceIdentity

from ..boundaries import ApplicabilityMode
from ..catalog.registry import SecurityKnowledgeCatalog
from ..mitigation import (
    BoundaryRole,
    MitigationMapping,
    MitigationRole,
    MitigationStrength,
)
from ..provenance import Confidence, LifecycleStatus
from ..schema import Proposal
from .resolution import ResolutionStatus, ThreatResolution
from .schema import ThreatApplicabilityScope


class ProjectionEligibility(str, Enum):
    ELIGIBLE = "eligible"
    REVIEW_REQUIRED = "review_required"
    INELIGIBLE = "ineligible"


class ProjectionFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    source_identity: SourceIdentity | None = None
    mapping_id: str | None = None
    threat_context_id: str | None = None
    message: str


class ThreatControlProjection(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_identity: SourceIdentity
    control_id: str
    title: str | None = None
    base_proposal: Proposal
    mapping_id: str
    threat_context_id: str
    threat_resolution_id: str
    resolution_status: ResolutionStatus
    resolution_confidence: Confidence
    threat_applicability_scope: ThreatApplicabilityScope
    attack_path_ids: tuple[str, ...]
    boundary_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    capability_id: str
    security_effect: str
    mitigation_role: MitigationRole
    mitigation_strength: MitigationStrength
    boundary_role: BoundaryRole
    applicability_mode: ApplicabilityMode
    mapping_confidence: Confidence
    overlap_type: str
    related_control_ids: tuple[str, ...] = ()
    eligibility: str
    findings: tuple[ProjectionFinding, ...] = ()


class ControlProjectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    projections: tuple[ThreatControlProjection, ...] = ()
    findings: tuple[ProjectionFinding, ...] = ()

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


def threat_resolution_id(resolution: ThreatResolution) -> str:
    return f"{resolution.threat_context_id}@{resolution.threat_context_revision}"


def _assessment_index(
    assessments: Iterable[MandatoryAssessment],
) -> dict[str, MandatoryAssessment]:
    indexed: dict[str, MandatoryAssessment] = {}
    for assessment in assessments:
        if assessment.source_identity is not None:
            indexed[assessment.source_identity.serialize()] = assessment
    return indexed


def _identity(value: str) -> SourceIdentity | None:
    try:
        parts = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parts, list) or len(parts) != 6:
        return None
    try:
        return SourceIdentity(
            source_framework=parts[0],
            benchmark_family=parts[1],
            benchmark_name=parts[2],
            benchmark_version=parts[3],
            benchmark_profile=parts[4],
            control_id=parts[5],
        )
    except (TypeError, ValueError):
        return None


def _projection_findings(
    mapping: MitigationMapping,
    resolution: ThreatResolution,
    identity: SourceIdentity,
) -> tuple[str, tuple[ProjectionFinding, ...]]:
    findings: list[ProjectionFinding] = []
    eligibility = ProjectionEligibility.ELIGIBLE

    def add(code: str, message: str) -> None:
        findings.append(
            ProjectionFinding(
                code=code,
                source_identity=identity,
                mapping_id=mapping.mapping_id,
                threat_context_id=resolution.threat_context_id,
                message=message,
            )
        )

    if mapping.lifecycle_status != LifecycleStatus.ACTIVE:
        eligibility = ProjectionEligibility.INELIGIBLE
        add(
            "THREAT_PROJECTION_INACTIVE_MAPPING",
            "The mitigation mapping is not active.",
        )
    if resolution.status not in {
        ResolutionStatus.RESOLVED,
        ResolutionStatus.PARTIALLY_RESOLVED,
    }:
        eligibility = ProjectionEligibility.REVIEW_REQUIRED
        add(
            "THREAT_PROJECTION_RESOLUTION_REVIEW",
            f"The knowledge resolution status is {resolution.status.value}.",
        )
    if resolution.historical_mode:
        eligibility = ProjectionEligibility.INELIGIBLE
        add(
            "THREAT_PROJECTION_HISTORICAL_INELIGIBLE",
            "Historical resolution is retained for analysis but cannot drive active priority.",
        )
    if mapping.confidence != Confidence.HIGH:
        eligibility = ProjectionEligibility.REVIEW_REQUIRED
        add(
            "THREAT_PROJECTION_CONFIDENCE_CAP",
            "Mapping confidence is below High and prevents High relevance.",
        )
    if mapping.applicability_mode != ApplicabilityMode.UNIVERSAL:
        eligibility = ProjectionEligibility.REVIEW_REQUIRED
        add(
            "THREAT_PROJECTION_APPLICABILITY_CAP",
            f"Control applicability is {mapping.applicability_mode.value}.",
        )
    if resolution.applicability_scope == ThreatApplicabilityScope.UNRESOLVED:
        eligibility = ProjectionEligibility.REVIEW_REQUIRED
        add(
            "THREAT_PROJECTION_THREAT_APPLICABILITY_CAP",
            "Threat applicability is unresolved.",
        )
    return eligibility, tuple(sorted(findings, key=lambda item: item.code))


def project_threat_resolutions(
    resolutions: Iterable[ThreatResolution],
    mappings: Iterable[MitigationMapping],
    assessments: Iterable[MandatoryAssessment],
    *,
    catalog: SecurityKnowledgeCatalog | None = None,
) -> ControlProjectionResult:
    """Join resolved knowledge to controls only through atomic mitigation mappings."""
    assessment_by_identity = _assessment_index(assessments)
    findings: list[ProjectionFinding] = []
    projections: list[ThreatControlProjection] = []
    sorted_resolutions = sorted(
        resolutions,
        key=lambda item: (item.threat_context_id, item.threat_context_revision),
    )
    migrated_boundaries = (
        {
            item.legacy_boundary_set_id: item.normative_boundary_definition_id
            for item in catalog.migration_map
            if item.migration_status == "mapped"
        }
        if catalog is not None
        else {}
    )
    for mapping in sorted(mappings, key=lambda item: item.mapping_id):
        identity = _identity(mapping.source_recommendation_id)
        if identity is None:
            findings.append(
                ProjectionFinding(
                    code="THREAT_PROJECTION_INVALID_SOURCE_IDENTITY",
                    mapping_id=mapping.mapping_id,
                    message="The mapping source recommendation ID is not a serialized SourceIdentity.",
                )
            )
            continue
        assessment = assessment_by_identity.get(identity.serialize())
        if assessment is None:
            findings.append(
                ProjectionFinding(
                    code="THREAT_PROJECTION_SOURCE_ASSESSMENT_MISSING",
                    source_identity=identity,
                    mapping_id=mapping.mapping_id,
                    message="No scoped base assessment supplies title and immutable proposal.",
                )
            )
            continue
        for resolution in sorted_resolutions:
            path_by_id = {
                path.attack_path.object_id: path for path in resolution.resolution_paths
            }
            resolved_path = path_by_id.get(mapping.attack_path_id)
            if resolved_path is None:
                continue
            resolved_boundaries = {item.object_id for item in resolved_path.boundaries}
            effective_boundary_id = migrated_boundaries.get(
                mapping.boundary_set_definition_id or "",
                mapping.boundary_definition_id,
            )
            boundary_ids = (
                (effective_boundary_id,)
                if effective_boundary_id in resolved_boundaries
                else ()
            )
            projection_findings: list[ProjectionFinding] = []
            if not boundary_ids:
                projection_findings.append(
                    ProjectionFinding(
                        code="THREAT_PROJECTION_BOUNDARY_NOT_RESOLVED",
                        source_identity=identity,
                        mapping_id=mapping.mapping_id,
                        threat_context_id=resolution.threat_context_id,
                        message="The attack path intersects, but the mapping boundary is absent from this resolved path.",
                    )
                )
            eligibility, eligibility_findings = _projection_findings(
                mapping, resolution, identity
            )
            if not boundary_ids and eligibility != ProjectionEligibility.INELIGIBLE:
                eligibility = ProjectionEligibility.REVIEW_REQUIRED
            projection_findings.extend(eligibility_findings)
            path_techniques = {item.object_id for item in resolved_path.techniques}
            mapping_techniques = set(mapping.technique_ids)
            technique_ids = tuple(
                sorted(mapping_techniques & path_techniques or path_techniques)
            )
            projections.append(
                ThreatControlProjection(
                    source_identity=identity,
                    control_id=identity.control_id,
                    title=assessment.title,
                    base_proposal=Proposal(assessment.proposal),
                    mapping_id=mapping.mapping_id,
                    threat_context_id=resolution.threat_context_id,
                    threat_resolution_id=threat_resolution_id(resolution),
                    resolution_status=resolution.status,
                    resolution_confidence=resolution.confidence,
                    threat_applicability_scope=resolution.applicability_scope,
                    attack_path_ids=(mapping.attack_path_id,),
                    boundary_ids=boundary_ids,
                    technique_ids=technique_ids,
                    capability_id=mapping.capability_id,
                    security_effect=mapping.enforced_sub_boundary,
                    mitigation_role=mapping.mitigation_role,
                    mitigation_strength=mapping.mitigation_strength,
                    boundary_role=mapping.boundary_role,
                    applicability_mode=mapping.applicability_mode,
                    mapping_confidence=mapping.confidence,
                    overlap_type=assessment.overlap_type,
                    related_control_ids=tuple(
                        sorted(set(assessment.related_control_ids))
                    ),
                    eligibility=eligibility,
                    findings=tuple(
                        sorted(projection_findings, key=lambda item: item.code)
                    ),
                )
            )
    projections.sort(
        key=lambda item: (
            item.source_identity.as_tuple(),
            item.threat_context_id,
            item.mapping_id,
            item.attack_path_ids,
        )
    )
    findings.sort(key=lambda item: (item.code, item.mapping_id or ""))
    return ControlProjectionResult(
        projections=tuple(projections), findings=tuple(findings)
    )


__all__ = [
    "ControlProjectionResult",
    "ProjectionEligibility",
    "ProjectionFinding",
    "ThreatControlProjection",
    "project_threat_resolutions",
    "threat_resolution_id",
]
