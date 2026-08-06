from __future__ import annotations

from collections import defaultdict
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .attack_paths import AttackPath
from .boundaries import (
    ApplicabilityMode,
    BoundaryDefinition,
    BoundaryEvaluation,
    BoundarySetDefinition,
    CompletenessStatus,
    DecisionScope,
    DeploymentState,
)
from .capabilities import SecurityCapability
from .evidence import EvidenceType
from .mitigation import (
    BoundaryRole,
    CompensatingControlEvaluation,
    EquivalenceType,
    MitigationMapping,
    MitigationStrength,
)
from .provenance import Confidence, LifecycleStatus
from .schema import MandatoryDecision, Proposal
from .techniques import AttackTechnique
from .threats import ThreatScenario


class FindingSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class DecisionEffect(str, Enum):
    INVALID_OBJECT = "invalid_object"
    MAPPING_REJECTED = "mapping_rejected"
    REVIEW_REQUIRED = "review_required"
    COVERAGE_GAP = "coverage_gap"


class ValidationFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str = Field(min_length=1)
    severity: FindingSeverity
    object_type: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    message: str = Field(min_length=1)
    required_action: str = Field(min_length=1)
    decision_effect: DecisionEffect


class KnowledgeCatalog(BaseModel):
    capabilities: dict[str, SecurityCapability] = Field(default_factory=dict)
    boundaries: dict[str, BoundaryDefinition] = Field(default_factory=dict)
    boundary_sets: dict[str, BoundarySetDefinition] = Field(default_factory=dict)
    threats: dict[str, ThreatScenario] = Field(default_factory=dict)
    techniques: dict[str, AttackTechnique] = Field(default_factory=dict)
    attack_paths: dict[str, AttackPath] = Field(default_factory=dict)


def _finding(
    code: str,
    object_type: str,
    object_id: str,
    message: str,
    action: str,
    effect: DecisionEffect,
) -> ValidationFinding:
    return ValidationFinding(
        code=code,
        severity=FindingSeverity.ERROR,
        object_type=object_type,
        object_id=object_id,
        message=message,
        required_action=action,
        decision_effect=effect,
    )


def _active_reference(
    object_id: str,
    target: object | None,
    historical_evaluation: bool,
) -> bool:
    if target is None:
        return False
    status = getattr(target, "lifecycle_status", None)
    return status == LifecycleStatus.ACTIVE or historical_evaluation


def validate_attack_path(
    path: AttackPath,
    threats: dict[str, ThreatScenario],
    *,
    historical_evaluation: bool = False,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    if path.lifecycle_status == LifecycleStatus.ACTIVE:
        active = [
            scenario_id
            for scenario_id in path.threat_scenario_ids
            if _active_reference(
                scenario_id,
                threats.get(scenario_id),
                historical_evaluation,
            )
        ]
        if not active:
            findings.append(
                _finding(
                    "SKV-ATTACK-PATH-SCENARIO",
                    "AttackPath",
                    path.attack_path_id,
                    "Active AttackPath has no active ThreatScenario reference.",
                    "Add an active ThreatScenario or return the path to draft status.",
                    DecisionEffect.INVALID_OBJECT,
                )
            )
    return findings


def validate_mapping(
    mapping: MitigationMapping,
    catalog: KnowledgeCatalog,
    *,
    historical_evaluation: bool = False,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    references = (
        ("capability", mapping.capability_id, catalog.capabilities.get(mapping.capability_id)),
        ("boundary", mapping.boundary_definition_id, catalog.boundaries.get(mapping.boundary_definition_id)),
        ("attack path", mapping.attack_path_id, catalog.attack_paths.get(mapping.attack_path_id)),
    )
    for label, object_id, target in references:
        if not _active_reference(object_id, target, historical_evaluation):
            findings.append(
                _finding(
                    "SKV-INACTIVE-REFERENCE",
                    "MitigationMapping",
                    mapping.mapping_id,
                    f"Referenced {label} {object_id} is missing or not active.",
                    "Reference an active catalog object or use explicit historical evaluation.",
                    DecisionEffect.MAPPING_REJECTED,
                )
            )
    if mapping.boundary_set_definition_id and not _active_reference(
        mapping.boundary_set_definition_id,
        catalog.boundary_sets.get(mapping.boundary_set_definition_id),
        historical_evaluation,
    ):
        findings.append(
            _finding(
                "SKV-INACTIVE-BOUNDARY-SET",
                "MitigationMapping",
                mapping.mapping_id,
                "Referenced BoundarySetDefinition is missing or not active.",
                "Reference an active boundary set or remove the optional reference.",
                DecisionEffect.MAPPING_REJECTED,
            )
        )
    boundary_set = (
        catalog.boundary_sets.get(mapping.boundary_set_definition_id)
        if mapping.boundary_set_definition_id
        else None
    )
    if boundary_set and boundary_set.boundary_definition_id != mapping.boundary_definition_id:
        findings.append(
            _finding(
                "SKV-BOUNDARY-SET-MISMATCH",
                "MitigationMapping",
                mapping.mapping_id,
                "BoundarySetDefinition does not implement the referenced BoundaryDefinition.",
                "Reference a boundary set belonging to the mapping boundary.",
                DecisionEffect.MAPPING_REJECTED,
            )
        )
    if mapping.threat_scenario_id and not _active_reference(
        mapping.threat_scenario_id,
        catalog.threats.get(mapping.threat_scenario_id),
        historical_evaluation,
    ):
        findings.append(
            _finding(
                "SKV-INACTIVE-THREAT",
                "MitigationMapping",
                mapping.mapping_id,
                "Referenced ThreatScenario is missing or not active.",
                "Reference an active ThreatScenario.",
                DecisionEffect.MAPPING_REJECTED,
            )
        )
    for technique_id in mapping.technique_ids:
        if not _active_reference(
            technique_id,
            catalog.techniques.get(technique_id),
            historical_evaluation,
        ):
            findings.append(
                _finding(
                    "SKV-INACTIVE-TECHNIQUE",
                    "MitigationMapping",
                    mapping.mapping_id,
                    f"Referenced AttackTechnique {technique_id} is missing or not active.",
                    "Reference an active technique or remove the optional enrichment.",
                    DecisionEffect.MAPPING_REJECTED,
                )
            )
    path = catalog.attack_paths.get(mapping.attack_path_id)
    if path and mapping.attack_stage not in path.ordered_stages:
        findings.append(
            _finding(
                "SKV-ATTACK-STAGE",
                "MitigationMapping",
                mapping.mapping_id,
                "Mapping attack stage is absent from the referenced AttackPath.",
                "Use an ordered stage declared by the path.",
                DecisionEffect.MAPPING_REJECTED,
            )
        )
    if not mapping.evidence or not any(
        item.evidence_type == EvidenceType.SOURCE_CONTROL for item in mapping.evidence
    ):
        findings.append(
            _finding(
                "SKV-ATTRIBUTABLE-EVIDENCE",
                "MitigationMapping",
                mapping.mapping_id,
                "Mapping lacks source-control evidence for enforced behavior.",
                "Attach attributable source-control evidence.",
                DecisionEffect.MAPPING_REJECTED,
            )
        )
    if mapping.provenance:
        permitted = {
            "title",
            "description",
            "rationale",
            "impact",
            "remediation",
            "default_value",
            "applicability",
        }
        if not set(mapping.provenance.source_fields_used) & permitted:
            findings.append(
                _finding(
                    "SKV-AUDIT-REFERENCE-ONLY",
                    "MitigationMapping",
                    mapping.mapping_id,
                    "Mapping is activated only by audit, reference, or unsupported fields.",
                    "Corroborate the mapping with permitted behavioral source fields.",
                    DecisionEffect.MAPPING_REJECTED,
                )
            )
    source_parts = mapping.source_recommendation_id.split("|")
    if len(source_parts) != 5 or not all(source_parts):
        findings.append(
            _finding(
                "SKV-SOURCE-IDENTITY",
                "MitigationMapping",
                mapping.mapping_id,
                "Source recommendation identity is not framework/benchmark/version/profile/control scoped.",
                "Use the five-part scoped source identity.",
                DecisionEffect.INVALID_OBJECT,
            )
        )
    return findings


def validate_duplicate_effects(mappings: list[MitigationMapping]) -> list[ValidationFinding]:
    grouped: dict[tuple[str, str, ApplicabilityMode], list[MitigationMapping]] = defaultdict(list)
    for mapping in mappings:
        if mapping.mitigation_strength == MitigationStrength.PRIMARY:
            grouped[
                (
                    mapping.boundary_definition_id,
                    mapping.enforced_sub_boundary,
                    mapping.applicability_mode,
                )
            ].append(mapping)
    findings = []
    for duplicates in grouped.values():
        if len({item.source_recommendation_id for item in duplicates}) > 1:
            for mapping in duplicates:
                findings.append(
                    _finding(
                        "SKV-DUPLICATE-PRIMARY-EFFECT",
                        "MitigationMapping",
                        mapping.mapping_id,
                        "Multiple controls claim primary strength for the same boundary effect and scope.",
                        "Select one implementation or classify the relationship as duplicate/alternative.",
                        DecisionEffect.REVIEW_REQUIRED,
                    )
                )
    return findings


def validate_boundary_evaluation(evaluation: BoundaryEvaluation) -> list[ValidationFinding]:
    if evaluation.completeness_status == CompletenessStatus.INCOMPLETE_BOUNDARY:
        return [
            _finding(
                "SKV-INCOMPLETE-BOUNDARY",
                "BoundaryEvaluation",
                evaluation.evaluation_id,
                "A required boundary effect, prerequisite, or alternative remains unresolved.",
                "Complete the boundary or record accepted compensation.",
                DecisionEffect.COVERAGE_GAP,
            )
        ]
    return []


def validate_compensation(
    evaluation: CompensatingControlEvaluation,
    candidate_mapping: MitigationMapping,
) -> list[ValidationFinding]:
    invalid = (
        evaluation.equivalence_type in {EquivalenceType.FULL, EquivalenceType.CONDITIONAL}
        and (
            candidate_mapping.boundary_role
            in {
                BoundaryRole.SUPPORTING_HARDENING,
                BoundaryRole.FINE_TUNING,
                BoundaryRole.DETECTION_ONLY,
                BoundaryRole.INFORMATION_HIDING,
                BoundaryRole.OPERATIONAL,
            }
            or candidate_mapping.mitigation_strength == MitigationStrength.SUPPORTING
        )
    )
    if not invalid:
        return []
    return [
        _finding(
            "SKV-INVALID-COMPENSATION",
            "CompensatingControlEvaluation",
            evaluation.evaluation_id,
            "A supporting control cannot provide full or accepted conditional equivalence.",
            "Downgrade equivalence or select an equivalent primary/core control.",
            DecisionEffect.REVIEW_REQUIRED,
        )
    ]


def _applicability_valid(decision: MandatoryDecision) -> bool:
    if decision.applicability_mode == ApplicabilityMode.UNRESOLVED:
        return False
    if decision.decision_scope == DecisionScope.BENCHMARK:
        if decision.applicability_mode == ApplicabilityMode.UNIVERSAL:
            return decision.deployment_state == DeploymentState.NOT_EVALUATED
        return decision.deployment_state in {DeploymentState.NOT_EVALUATED, DeploymentState.UNKNOWN}
    return decision.deployment_state in {
        DeploymentState.DEPLOYED,
        DeploymentState.NOT_DEPLOYED,
    }


def validate_mandatory_decision(
    decision: MandatoryDecision,
    mappings: dict[str, MitigationMapping],
    boundary_evaluations: dict[str, BoundaryEvaluation],
    catalog: KnowledgeCatalog,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    if not _applicability_valid(decision):
        findings.append(
            _finding(
                "SKV-APPLICABILITY",
                "MandatoryDecision",
                decision.decision_id,
                "Applicability, deployment state, and decision scope are unresolved or invalid.",
                "Resolve the decision context using the normative applicability matrix.",
                DecisionEffect.REVIEW_REQUIRED,
            )
        )
    if decision.proposal not in {Proposal.CANDIDATE, Proposal.DEFINITIVE}:
        return findings

    selected = [mappings[item] for item in decision.mitigation_mapping_ids if item in mappings]
    eligible = [
        mapping
        for mapping in selected
        if mapping.boundary_role
        in {
            BoundaryRole.STANDALONE_PRIMARY_BOUNDARY,
            BoundaryRole.BOUNDARY_SET_CORE_MEMBER,
            BoundaryRole.PREREQUISITE,
        }
        and mapping.mitigation_strength
        in {MitigationStrength.PRIMARY, MitigationStrength.COMPLEMENTARY}
        and mapping.lifecycle_status == LifecycleStatus.ACTIVE
        and mapping.confidence == Confidence.HIGH
        and not validate_mapping(mapping, catalog)
        and mapping.threat_scenario_id is not None
        and catalog.capabilities.get(mapping.capability_id) is not None
        and catalog.capabilities[mapping.capability_id].lifecycle_status == LifecycleStatus.ACTIVE
        and catalog.boundaries.get(mapping.boundary_definition_id) is not None
        and catalog.boundaries[mapping.boundary_definition_id].lifecycle_status
        == LifecycleStatus.ACTIVE
        and catalog.attack_paths.get(mapping.attack_path_id) is not None
        and catalog.attack_paths[mapping.attack_path_id].lifecycle_status == LifecycleStatus.ACTIVE
        and catalog.attack_paths[mapping.attack_path_id].confidence == Confidence.HIGH
        and mapping.threat_scenario_id
        in catalog.attack_paths[mapping.attack_path_id].threat_scenario_ids
        and catalog.threats.get(mapping.threat_scenario_id) is not None
        and catalog.threats[mapping.threat_scenario_id].lifecycle_status == LifecycleStatus.ACTIVE
        and catalog.threats[mapping.threat_scenario_id].confidence == Confidence.HIGH
    ]
    evaluations = [
        boundary_evaluations[item]
        for item in decision.boundary_evaluation_ids
        if item in boundary_evaluations
    ]
    high_chain = (
        decision.confidence == Confidence.HIGH
        and decision.decision_provenance.source_extraction_confidence == Confidence.HIGH
        and bool(eligible)
        and bool(evaluations)
        and all(item.confidence == Confidence.HIGH for item in evaluations)
        and all(
            item.completeness_status
            in {
                CompletenessStatus.COMPLETE_STANDALONE_PRIMARY,
                CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET,
            }
            for item in evaluations
        )
        and bool(decision.evidence)
    )
    if not high_chain:
        findings.append(
            _finding(
                "SKV-CANDIDATE-CONFIDENCE",
                "MandatoryDecision",
                decision.decision_id,
                "Candidate/Definitive decision lacks a complete High-confidence evidence chain.",
                "Supply active eligible mappings, High-confidence boundary evaluation, and evidence.",
                DecisionEffect.REVIEW_REQUIRED,
            )
        )
    if (
        decision.decision_scope == DecisionScope.ENVIRONMENT
        and decision.deployment_state != DeploymentState.DEPLOYED
    ):
        findings.append(
            _finding(
                "SKV-ENVIRONMENT-DEPLOYMENT",
                "MandatoryDecision",
                decision.decision_id,
                "Environment-scoped Mandatory decision requires deployed state.",
                "Confirm deployment or return the decision to review/not-applicable handling.",
                DecisionEffect.REVIEW_REQUIRED,
            )
        )
    return findings


def sorted_findings(findings: list[ValidationFinding]) -> list[ValidationFinding]:
    return sorted(
        findings,
        key=lambda item: (item.object_type, item.object_id, item.code, item.message),
    )
