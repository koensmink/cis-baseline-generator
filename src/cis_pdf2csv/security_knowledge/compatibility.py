from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cis_pdf2csv.mandatory.schema import MandatoryAssessment

from .catalog import SECURITY_KNOWLEDGE_CATALOG
from .catalog.registry import SecurityKnowledgeCatalog
from .catalog.validation import ValidationFinding


class CatalogResolution(BaseModel):
    model_config = ConfigDict(frozen=True)
    control_id: str
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


def adapt_phase1_assessments(
    assessments: list[MandatoryAssessment],
    catalog: SecurityKnowledgeCatalog = SECURITY_KNOWLEDGE_CATALOG,
) -> CompatibilityResult:
    """Resolve Phase-1 IDs without feeding normative objects into classification."""
    migrations = {item.legacy_boundary_set_id: item for item in catalog.migration_map}
    resolutions: list[CatalogResolution] = []
    findings: list[ValidationFinding] = []
    overrides: dict[str, str] = {}
    for assessment in sorted(assessments, key=lambda item: item.control_id):
        if assessment.proposal != "Candidate Mandatory":
            continue
        legacy_id = assessment.boundary_set_id
        migration = migrations.get(legacy_id or "")
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
                overrides[assessment.control_id] = "Review Required"
                continue
            threat_ids.update(path.threat_scenario_ids)
            outcome_ids.update(path.security_outcome_ids)
        if assessment.control_id in overrides:
            continue
        resolutions.append(
            CatalogResolution(
                control_id=assessment.control_id,
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
    )
