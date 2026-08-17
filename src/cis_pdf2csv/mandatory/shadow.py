from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.adapters import select_adapter
from cis_pdf2csv.security_knowledge.boundaries import CompletenessStatus
from cis_pdf2csv.security_knowledge.catalog import SECURITY_KNOWLEDGE_CATALOG
from cis_pdf2csv.security_knowledge.catalog.registry import SecurityKnowledgeCatalog
from cis_pdf2csv.security_knowledge.catalog.validation import ValidationFinding
from cis_pdf2csv.security_knowledge.compatibility import resolve_legacy_boundary_set

from .pipeline import assess_controls
from .schema import Confidence, MandatoryAssessment, Proposal

DifferenceCode = Literal[
    "SHADOW-MATCH",
    "SHADOW-NORMATIVE-PROMOTION",
    "SHADOW-NORMATIVE-DEMOTION",
    "SHADOW-BOUNDARY-DIFFERENCE",
    "SHADOW-APPLICABILITY-DIFFERENCE",
    "SHADOW-MISSING-CATALOG-MAPPING",
    "SHADOW-INCOMPLETE-BOUNDARY",
    "SHADOW-CONFIDENCE-DIFFERENCE",
    "SHADOW-VALIDATION-BLOCKED",
]
MappingGapCategory = Literal[
    "qualifying_security_effect_catalog_mapping_missing",
    "optional_non_mandatory_enrichment",
    "security_knowledge_enrichment_opportunity",
    "unresolved_mapping_required_for_decision",
]


class ShadowValidationFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    code: str
    severity: Literal["error", "warning"]
    message: str
    review_required: bool = False


class NormativeMitigationMapping(BaseModel):
    """Atomic, advisory source-to-catalog relationship used only by shadow mode."""

    model_config = ConfigDict(frozen=True)
    mapping_id: str
    control_id: str
    capability_id: str
    boundary_definition_id: str
    boundary_set_definition_id: str
    threat_scenario_id: str
    attack_path_id: str
    security_outcome_ids: tuple[str, ...]
    boundary_role: str
    mitigation_strength: Literal["primary", "complementary", "supporting"]
    enforced_sub_boundary: str
    confidence: Confidence


class ShadowBoundaryEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)
    evaluation_id: str
    boundary_definition_id: str
    boundary_set_definition_id: str
    selected_control_ids: tuple[str, ...]
    required_sub_boundaries: tuple[str, ...]
    satisfied_sub_boundaries: tuple[str, ...]
    missing_sub_boundaries: tuple[str, ...]
    selected_alternatives: tuple[str, ...] = ()
    completeness_status: CompletenessStatus
    residual_attack_path: str
    confidence: Confidence
    evidence: tuple[str, ...]


class ShadowMandatoryAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)
    control_id: str
    legacy_proposal: Proposal
    normative_proposal: Proposal
    proposals_match: bool
    legacy_boundary_set_id: str | None = None
    normative_boundary_definition_ids: tuple[str, ...] = ()
    normative_boundary_set_definition_ids: tuple[str, ...] = ()
    boundary_evaluation_ids: tuple[str, ...] = ()
    mitigation_mapping_ids: tuple[str, ...] = ()
    capability_ids: tuple[str, ...] = ()
    threat_scenario_ids: tuple[str, ...] = ()
    attack_path_ids: tuple[str, ...] = ()
    security_outcome_ids: tuple[str, ...] = ()
    legacy_confidence: Confidence
    normative_confidence: Confidence
    validation_findings: tuple[ShadowValidationFinding, ...] = ()
    mapping_gap_category: MappingGapCategory | None = None
    difference_codes: tuple[DifferenceCode, ...]
    difference_rationale: str
    cutover_eligible: bool


class ShadowAssessmentResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    legacy_assessments: tuple[MandatoryAssessment, ...]
    shadow_assessments: tuple[ShadowMandatoryAssessment, ...]
    mitigation_mappings: tuple[NormativeMitigationMapping, ...]
    boundary_evaluations: tuple[ShadowBoundaryEvaluation, ...]


def _stable_id(prefix: str, *parts: str) -> str:
    value = "\x1f".join(parts).encode()
    return f"{prefix}-{int(hashlib.sha256(value).hexdigest()[:15], 16):018d}"


def _role(legacy: str) -> str:
    return legacy.replace("-", "_").replace(" ", "_")


def _strength(role: str) -> Literal["primary", "complementary", "supporting"]:
    if role == "standalone_primary_boundary":
        return "primary"
    if role in {"boundary_set_core_member", "prerequisite"}:
        return "complementary"
    return "supporting"


def _semantic_boundary_id(control: ControlRecord) -> str | None:
    """Resolve reusable shadow concepts from behavior-bearing title semantics."""
    selection = select_adapter(control)
    if selection.adapter is None:
        return None
    candidates = selection.adapter.identify_boundary_candidates(control)
    return candidates[0].semantic_mapping_id if len(candidates) == 1 else None


def _mapping_gap_category(assessment: MandatoryAssessment) -> MappingGapCategory:
    if assessment.applicability_mode == "unresolved":
        return "unresolved_mapping_required_for_decision"
    role = _role(assessment.relationship)
    if role in {"standalone_primary_boundary", "boundary_set_core_member", "prerequisite"}:
        return "qualifying_security_effect_catalog_mapping_missing"
    if role == "detection_only":
        return "security_knowledge_enrichment_opportunity"
    return "optional_non_mandatory_enrichment"


def _catalog_findings(findings: tuple[ValidationFinding, ...]) -> tuple[ShadowValidationFinding, ...]:
    return tuple(
        ShadowValidationFinding(
            code=item.code,
            severity=item.severity,
            message=f"{item.object_type} {item.object_id}: {item.message}",
            review_required=True,
        )
        for item in findings
    )


def assess_controls_shadow(
    records: Iterable[ControlRecord],
    *,
    catalog: SecurityKnowledgeCatalog = SECURITY_KNOWLEDGE_CATALOG,
) -> ShadowAssessmentResult:
    """Run the unchanged classifier and advisory normative pipeline in parallel."""
    controls = sorted(
        records,
        key=lambda item: (item.benchmark_name, item.benchmark_version, item.profile, item.control_id),
    )
    legacy = assess_controls(controls)
    return compare_shadow_assessments(controls, legacy, catalog=catalog)


def compare_shadow_assessments(
    records: list[ControlRecord],
    legacy_assessments: list[MandatoryAssessment],
    *,
    catalog: SecurityKnowledgeCatalog = SECURITY_KNOWLEDGE_CATALOG,
) -> ShadowAssessmentResult:
    """Evaluate supplied legacy results without mutating or overriding them."""
    controls = {item.control_id: item for item in records}
    catalog_blockers = _catalog_findings(catalog.validate())
    grouped: dict[str, list[MandatoryAssessment]] = defaultdict(list)
    for item in legacy_assessments:
        effective_boundary_id = item.boundary_set_id or _semantic_boundary_id(controls[item.control_id])
        if effective_boundary_id:
            grouped[effective_boundary_id].append(item)

    evaluations: dict[str, ShadowBoundaryEvaluation] = {}
    mappings_by_control: dict[str, list[NormativeMitigationMapping]] = defaultdict(list)
    for legacy_id, members in sorted(grouped.items()):
        migration = resolve_legacy_boundary_set(legacy_id, catalog)
        if migration is None:
            continue
        boundary_set = catalog.get_boundary_set(migration.normative_boundary_set_id)
        selected = tuple(sorted(item.control_id for item in members))
        roles = {_role(item.relationship) for item in members}
        standalone = not legacy_id.startswith("SEM-") and "standalone_primary_boundary" in roles
        core_members = [
            item
            for item in members
            if _role(item.relationship) in {"boundary_set_core_member", "prerequisite"}
        ]
        # Completeness is derived from evaluated effects, never from the legacy
        # proposal.  Phase-1 records explicitly carry missing effects in the
        # review note when their complementary set is incomplete.
        complete_core = bool(core_members) and all(
            "boundary set is incomplete" not in (item.review_note or "").lower()
            for item in core_members
        )
        complete = standalone or complete_core
        required = tuple(sorted(boundary_set.required_sub_boundaries))
        satisfied = required if complete else ()
        missing = tuple(item for item in required if item not in satisfied)
        status = (
            CompletenessStatus.COMPLETE_STANDALONE_PRIMARY
            if standalone
            else CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET
            if complete_core
            else CompletenessStatus.SUPPORTING_ONLY
            if roles <= {"supporting_hardening", "fine_tuning", "detection_only", "information_hiding", "operational"}
            else CompletenessStatus.INCOMPLETE_BOUNDARY
        )
        evaluation_id = _stable_id("BEV-SHADOW", legacy_id, *selected)
        evaluations[legacy_id] = ShadowBoundaryEvaluation(
            evaluation_id=evaluation_id,
            boundary_definition_id=migration.normative_boundary_definition_id,
            boundary_set_definition_id=migration.normative_boundary_set_id,
            selected_control_ids=selected,
            required_sub_boundaries=required,
            satisfied_sub_boundaries=satisfied,
            missing_sub_boundaries=missing,
            completeness_status=status,
            residual_attack_path=(
                "No catalog attack path remains through the evaluated boundary."
                if complete
                else "One or more catalog attack paths remain because required effects are missing."
            ),
            confidence="High" if complete and all(item.confidence == "High" for item in members) else "Medium",
            evidence=tuple(
                sorted(
                    f"{item.control_id}: deterministic legacy boundary role {item.relationship}"
                    for item in members
                )
            ),
        )
        for assessment in sorted(members, key=lambda item: item.control_id):
            role = _role(assessment.relationship)
            strength = _strength(role)
            effect = assessment.enforced_sub_boundary or "catalog boundary effect"
            for capability_id in migration.capability_ids:
                for path_id in migration.attack_path_ids:
                    path = catalog.get_attack_path(path_id)
                    for scenario_id in path.threat_scenario_ids:
                        mapping_id = _stable_id("MAP", assessment.control_id, capability_id, path_id, scenario_id)
                        mappings_by_control[assessment.control_id].append(
                            NormativeMitigationMapping(
                                mapping_id=mapping_id,
                                control_id=assessment.control_id,
                                capability_id=capability_id,
                                boundary_definition_id=migration.normative_boundary_definition_id,
                                boundary_set_definition_id=migration.normative_boundary_set_id,
                                threat_scenario_id=scenario_id,
                                attack_path_id=path_id,
                                security_outcome_ids=tuple(sorted(path.security_outcome_ids)),
                                boundary_role=role,
                                mitigation_strength=strength,
                                enforced_sub_boundary=effect,
                                confidence=assessment.confidence,
                            )
                        )

    shadows: list[ShadowMandatoryAssessment] = []
    for legacy in sorted(legacy_assessments, key=lambda item: item.control_id):
        effective_boundary_id = legacy.boundary_set_id or _semantic_boundary_id(controls[legacy.control_id])
        migration = resolve_legacy_boundary_set(effective_boundary_id, catalog)
        evaluation = evaluations.get(effective_boundary_id or "")
        mappings = tuple(sorted(mappings_by_control[legacy.control_id], key=lambda item: item.mapping_id))
        findings: list[ShadowValidationFinding] = list(catalog_blockers)
        adapter_selection = select_adapter(controls[legacy.control_id])
        if adapter_selection.finding:
            findings.append(
                ShadowValidationFinding(
                    code=adapter_selection.finding,
                    severity="warning",
                    message="Benchmark-family adapter selection did not resolve exactly one supported family.",
                    review_required=True,
                )
            )
        if migration is None:
            findings.append(ShadowValidationFinding(code="CATALOG_MAPPING_MISSING", severity="warning", message="No compatibility migration resolves this control to the normative catalog.", review_required=True))
        if evaluation and evaluation.completeness_status == CompletenessStatus.INCOMPLETE_BOUNDARY:
            findings.append(ShadowValidationFinding(code="BOUNDARY_EVALUATION_INCOMPLETE", severity="warning", message=f"Missing effects: {', '.join(evaluation.missing_sub_boundaries)}", review_required=True))
        if legacy.applicability_mode == "unresolved":
            findings.append(ShadowValidationFinding(code="APPLICABILITY_UNRESOLVED", severity="warning", message="Benchmark-scope applicability is unresolved.", review_required=True))
        if legacy.overlap_type in {"duplicate", "alternative"}:
            findings.append(ShadowValidationFinding(code="OVERLAP_UNRESOLVED", severity="warning", message=f"The {legacy.overlap_type} effect requires adjudication.", review_required=True))

        role = _role(legacy.relationship)
        supporting = role in {"supporting_hardening", "fine_tuning", "detection_only", "information_hiding", "operational"}
        review_blocked = any(item.review_required or item.severity == "error" for item in findings)
        qualifies = bool(
            migration
            and mappings
            and evaluation
            and evaluation.completeness_status
            in {
                CompletenessStatus.COMPLETE_STANDALONE_PRIMARY,
                CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET,
            }
            and role in {"standalone_primary_boundary", "boundary_set_core_member", "prerequisite"}
            and all(item.mitigation_strength in {"primary", "complementary"} for item in mappings)
            and legacy.confidence == "High"
            and legacy.applicability_mode != "unresolved"
            and not review_blocked
        )
        normative: Proposal = (
            "Review Required"
            if legacy.applicability_mode == "unresolved"
            else "Regular Control"
            if supporting
            else "Candidate Mandatory"
            if qualifies
            else "Review Required"
        )
        codes: set[DifferenceCode] = set()
        if normative == legacy.proposal:
            codes.add("SHADOW-MATCH")
        elif normative == "Candidate Mandatory":
            codes.add("SHADOW-NORMATIVE-PROMOTION")
        elif legacy.proposal == "Candidate Mandatory":
            codes.add("SHADOW-NORMATIVE-DEMOTION")
        if migration is None:
            codes.add("SHADOW-MISSING-CATALOG-MAPPING")
        if evaluation and evaluation.completeness_status == CompletenessStatus.INCOMPLETE_BOUNDARY:
            codes.add("SHADOW-INCOMPLETE-BOUNDARY")
        if legacy.applicability_mode == "unresolved":
            codes.add("SHADOW-APPLICABILITY-DIFFERENCE")
        normative_confidence: Confidence = evaluation.confidence if evaluation else "Low"
        if normative_confidence != legacy.confidence:
            codes.add("SHADOW-CONFIDENCE-DIFFERENCE")
        if catalog_blockers:
            codes.add("SHADOW-VALIDATION-BLOCKED")
        if migration and legacy.boundary_set_id != migration.normative_boundary_set_id:
            codes.add("SHADOW-BOUNDARY-DIFFERENCE")
        ordered_codes = tuple(sorted(codes))
        mapping_refs_resolve = bool(mappings) and all(
            item.control_id in controls and item.confidence == "High" for item in mappings
        )
        cutover = bool(
            normative == legacy.proposal
            and mapping_refs_resolve
            and not review_blocked
            and evaluation
            and evaluation.completeness_status
            in {
                CompletenessStatus.COMPLETE_STANDALONE_PRIMARY,
                CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET,
            }
            and normative_confidence == "High"
        )
        shadows.append(
            ShadowMandatoryAssessment(
                control_id=legacy.control_id,
                legacy_proposal=legacy.proposal,
                normative_proposal=normative,
                proposals_match=normative == legacy.proposal,
                legacy_boundary_set_id=legacy.boundary_set_id,
                normative_boundary_definition_ids=(() if migration is None else (migration.normative_boundary_definition_id,)),
                normative_boundary_set_definition_ids=(() if migration is None else (migration.normative_boundary_set_id,)),
                boundary_evaluation_ids=(() if evaluation is None else (evaluation.evaluation_id,)),
                mitigation_mapping_ids=tuple(item.mapping_id for item in mappings),
                capability_ids=tuple(sorted({item.capability_id for item in mappings})),
                threat_scenario_ids=tuple(sorted({item.threat_scenario_id for item in mappings})),
                attack_path_ids=tuple(sorted({item.attack_path_id for item in mappings})),
                security_outcome_ids=tuple(sorted({outcome for item in mappings for outcome in item.security_outcome_ids})),
                legacy_confidence=legacy.confidence,
                normative_confidence=normative_confidence,
                validation_findings=tuple(findings),
                mapping_gap_category=(None if migration is not None else _mapping_gap_category(legacy)),
                difference_codes=ordered_codes,
                difference_rationale="; ".join(ordered_codes) + ". Normative proposal is advisory and did not alter the legacy result.",
                cutover_eligible=cutover,
            )
        )
    return ShadowAssessmentResult(
        legacy_assessments=tuple(legacy_assessments),
        shadow_assessments=tuple(shadows),
        mitigation_mappings=tuple(sorted((item for values in mappings_by_control.values() for item in values), key=lambda item: item.mapping_id)),
        boundary_evaluations=tuple(sorted(evaluations.values(), key=lambda item: item.evaluation_id)),
    )
