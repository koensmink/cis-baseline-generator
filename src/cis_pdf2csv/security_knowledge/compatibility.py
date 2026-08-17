from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cis_pdf2csv.mandatory.schema import MandatoryAssessment
from cis_pdf2csv.source_identity import SourceIdentity

from .catalog import SECURITY_KNOWLEDGE_CATALOG
from .catalog.registry import LegacyKnowledgeMigration, SecurityKnowledgeCatalog
from .catalog.validation import ValidationFinding


class CatalogResolution(BaseModel):
    model_config = ConfigDict(frozen=True)
    control_id: str
    source_identity: SourceIdentity | None = None
    legacy_boundary_set_id: str
    boundary_definition_id: str
    boundary_set_definition_id: str
    capability_ids: tuple[str, ...]
    attack_path_ids: tuple[str, ...]
    threat_scenario_ids: tuple[str, ...]
    security_outcome_ids: tuple[str, ...]


class CompatibilityResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    resolutions: tuple[CatalogResolution, ...] = ()
    findings: tuple[ValidationFinding, ...] = ()
    proposal_overrides: dict[str, str] = Field(default_factory=dict)
    proposal_overrides_by_source_identity: dict[str, str] = Field(default_factory=dict)


def resolve_legacy_boundary_set(
    legacy_boundary_set_id: str | None,
    catalog: SecurityKnowledgeCatalog = SECURITY_KNOWLEDGE_CATALOG,
) -> LegacyKnowledgeMigration | None:
    """Resolve one Phase-1 identity without applying a proposal override."""
    return next(
        (
            item
            for item in catalog.migration_map
            if item.legacy_boundary_set_id == legacy_boundary_set_id
        ),
        None,
    )


def adapt_phase1_assessments(
    assessments: list[MandatoryAssessment],
    catalog: SecurityKnowledgeCatalog = SECURITY_KNOWLEDGE_CATALOG,
) -> CompatibilityResult:
    """Resolve Phase-1 IDs without feeding normative objects into classification."""
    resolutions: list[CatalogResolution] = []
    findings: list[ValidationFinding] = []
    overrides: dict[str, str] = {}
    scoped_overrides: dict[str, str] = {}
    control_id_counts: dict[str, int] = {}
    for assessment in assessments:
        control_id_counts[assessment.control_id] = control_id_counts.get(assessment.control_id, 0) + 1
    for assessment in sorted(
        assessments,
        key=lambda item: (
            item.source_identity.as_tuple()
            if item.source_identity is not None
            else ("", "", "", "", "", item.control_id)
        ),
    ):
        if assessment.proposal != "Candidate Mandatory":
            continue
        legacy_id = assessment.boundary_set_id
        migration = resolve_legacy_boundary_set(legacy_id, catalog)
        if migration is None:
            findings.append(
                ValidationFinding(
                    code="CATALOG_RESOLUTION_REQUIRED",
                    severity="error",
                    object_type="phase1_assessment",
                    object_id=assessment.control_id,
                    message=f"No normative migration exists for {legacy_id or 'missing boundary-set identity'}.",
                    required_action="Review the control and add an explicit catalog migration.",
                )
            )
            if assessment.source_identity is not None:
                scoped_overrides[assessment.source_identity.serialize()] = "Review Required"
            if control_id_counts[assessment.control_id] == 1:
                overrides[assessment.control_id] = "Review Required"
            continue
        threat_ids: set[str] = set()
        outcome_ids: set[str] = set()
        for path_id in migration.attack_path_ids:
            try:
                path = catalog.get_attack_path(path_id)
            except KeyError:
                findings.append(
                    ValidationFinding(
                        code="UNRESOLVED_CATALOG_ATTACK_PATH",
                        severity="error",
                        object_type="phase1_assessment",
                        object_id=assessment.control_id,
                        message=f"Migration attack path {path_id} does not resolve.",
                        required_action="Repair the migration before using this resolution.",
                    )
                )
                if assessment.source_identity is not None:
                    scoped_overrides[assessment.source_identity.serialize()] = "Review Required"
                if control_id_counts[assessment.control_id] == 1:
                    overrides[assessment.control_id] = "Review Required"
                continue
            threat_ids.update(path.threat_scenario_ids)
            outcome_ids.update(path.security_outcome_ids)
        if (
            assessment.source_identity is not None
            and assessment.source_identity.serialize() in scoped_overrides
        ) or (
            control_id_counts[assessment.control_id] == 1
            and assessment.control_id in overrides
        ):
            continue
        resolutions.append(
            CatalogResolution(
                control_id=assessment.control_id,
                source_identity=assessment.source_identity,
                legacy_boundary_set_id=migration.legacy_boundary_set_id,
                boundary_definition_id=migration.normative_boundary_definition_id,
                boundary_set_definition_id=migration.normative_boundary_set_id,
                capability_ids=migration.capability_ids,
                attack_path_ids=migration.attack_path_ids,
                threat_scenario_ids=tuple(sorted(threat_ids)),
                security_outcome_ids=tuple(sorted(outcome_ids)),
            )
        )
    return CompatibilityResult(
        resolutions=tuple(resolutions),
        findings=tuple(sorted(findings, key=lambda item: (item.code, item.object_id))),
        proposal_overrides=overrides,
        proposal_overrides_by_source_identity=scoped_overrides,
    )
