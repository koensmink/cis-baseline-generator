from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.adapters import select_adapter
from cis_pdf2csv.security_knowledge.adapters.base import (
    BoundaryCandidate,
    FamilyApplicabilityStatus,
)
from cis_pdf2csv.security_knowledge.boundaries import CompletenessStatus
from cis_pdf2csv.security_knowledge.catalog import SECURITY_KNOWLEDGE_CATALOG
from cis_pdf2csv.security_knowledge.catalog.registry import SecurityKnowledgeCatalog
from cis_pdf2csv.security_knowledge.catalog.validation import ValidationFinding
from cis_pdf2csv.security_knowledge.compatibility import resolve_legacy_boundary_set
from cis_pdf2csv.source_identity import (
    SourceIdentity,
    index_controls_by_source_identity,
)

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
    source_identity: SourceIdentity
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
    source_framework: str
    benchmark_family: str
    benchmark_name: str
    benchmark_version: str
    profile: str
    evaluation_scope: str = "benchmark"
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
    source_identity: SourceIdentity
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


EvaluationKey = tuple[str, str, str, str, str, str, str]


def _assessment_identity(assessment: MandatoryAssessment) -> SourceIdentity:
    if assessment.source_identity is None:
        raise ValueError("MandatoryAssessment is missing composite source identity")
    return assessment.source_identity


def _evaluation_key(
    identity: SourceIdentity,
    mapping_id: str,
    evaluation_scope: str,
) -> EvaluationKey:
    return (*identity.benchmark_scope(), mapping_id, evaluation_scope)


def _role(legacy: str) -> str:
    return legacy.replace("-", "_").replace(" ", "_")


def _strength(role: str) -> Literal["primary", "complementary", "supporting"]:
    if role == "standalone_primary_boundary":
        return "primary"
    if role in {"boundary_set_core_member", "prerequisite"}:
        return "complementary"
    return "supporting"


def _semantic_candidates(control: ControlRecord) -> tuple[BoundaryCandidate, ...]:
    """Resolve every independently evidenced reusable shadow concept."""
    selection = select_adapter(control)
    if selection.adapter is None:
        return ()
    return tuple(
        sorted(
            selection.adapter.identify_boundary_candidates(control),
            key=lambda item: (
                item.semantic_mapping_id,
                item.evaluation_scope,
                item.security_effect,
                item.satisfied_sub_boundaries,
            ),
        )
    )


def _semantic_candidate(control: ControlRecord, mapping_id: str) -> BoundaryCandidate | None:
    selection = select_adapter(control)
    if selection.adapter is None:
        return None
    matches = [
        item
        for item in selection.adapter.identify_boundary_candidates(control)
        if item.semantic_mapping_id == mapping_id
    ]
    return matches[0] if matches else None


def _semantic_applicability(control: ControlRecord) -> FamilyApplicabilityStatus | None:
    selection = select_adapter(control)
    if selection.adapter is None:
        return None
    return selection.adapter.normalize_applicability(control).applicability_status


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
    controls = index_controls_by_source_identity(records)
    identities_by_control_id: dict[str, list[SourceIdentity]] = defaultdict(list)
    for identity in controls:
        identities_by_control_id[identity.control_id].append(identity)
    scoped_legacy: list[MandatoryAssessment] = []
    for assessment in legacy_assessments:
        if assessment.source_identity is not None:
            scoped_legacy.append(assessment)
            continue
        matches = identities_by_control_id.get(assessment.control_id, [])
        if len(matches) != 1:
            raise ValueError(
                "Legacy MandatoryAssessment lacks composite source identity and "
                f"control_id '{assessment.control_id}' is not uniquely resolvable"
            )
        scoped_legacy.append(
            assessment.model_copy(update={"source_identity": matches[0]})
        )
    legacy_assessments = scoped_legacy
    catalog_blockers = _catalog_findings(catalog.validate())
    grouped: dict[
        EvaluationKey,
        list[tuple[MandatoryAssessment, BoundaryCandidate | None]],
    ] = defaultdict(list)
    for item in legacy_assessments:
        identity = _assessment_identity(item)
        candidates = _semantic_candidates(controls[identity])
        if candidates:
            for candidate in candidates:
                key = _evaluation_key(
                    identity,
                    candidate.semantic_mapping_id,
                    candidate.evaluation_scope,
                )
                grouped[key].append((item, candidate))
        elif item.boundary_set_id:
            grouped[_evaluation_key(identity, item.boundary_set_id, "benchmark")].append(
                (item, None)
            )

    evaluations: dict[EvaluationKey, ShadowBoundaryEvaluation] = {}
    mappings_by_control: dict[SourceIdentity, list[NormativeMitigationMapping]] = defaultdict(list)
    for key, entries in sorted(grouped.items()):
        legacy_id, evaluation_scope = key[-2:]
        source_framework, family, benchmark_name, benchmark_version, profile = key[:5]
        members = [item for item, _ in entries]
        migration = resolve_legacy_boundary_set(legacy_id, catalog)
        if migration is None:
            continue
        boundary_set = catalog.get_boundary_set(migration.normative_boundary_set_id)
        selected = tuple(sorted(item.control_id for item in members))
        semantic = legacy_id.startswith("SEM-")
        semantic_candidates = {
            _assessment_identity(item): candidate
            for item, candidate in entries
            if candidate is not None
        }
        roles = {
            semantic_candidates[_assessment_identity(item)].boundary_role
            if _assessment_identity(item) in semantic_candidates
            else _role(item.relationship)
            for item in members
        }
        satisfied_effects = {
            effect
            for candidate in semantic_candidates.values()
            for effect in candidate.satisfied_sub_boundaries
        }
        required = tuple(sorted(boundary_set.required_sub_boundaries))
        semantic_complete = semantic and set(required) <= satisfied_effects
        standalone = (
            semantic_complete and "standalone_primary_boundary" in roles
            if semantic
            else "standalone_primary_boundary" in roles
        )
        core_members = [
            item
            for item in members
            if _role(item.relationship) in {"boundary_set_core_member", "prerequisite"}
        ]
        # Completeness is derived from evaluated effects, never from the legacy
        # proposal.  Phase-1 records explicitly carry missing effects in the
        # review note when their complementary set is incomplete.
        complete_core = (
            semantic_complete and bool(roles & {"boundary_set_core_member", "prerequisite"})
            if semantic
            else bool(core_members) and all(
                "boundary set is incomplete" not in (item.review_note or "").lower()
                for item in core_members
            )
        )
        complete = standalone or complete_core
        satisfied = (
            tuple(sorted(set(required) & satisfied_effects))
            if semantic
            else required if complete else ()
        )
        missing = tuple(item for item in required if item not in satisfied)
        status = (
            CompletenessStatus.COMPLETE_STANDALONE_PRIMARY
            if standalone
            else CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET
            if complete_core
            else CompletenessStatus.SUPPORTING_ONLY
            if roles <= {"supporting_hardening", "risk_adaptive_enhancement", "fine_tuning", "detection_only", "information_hiding", "operational"}
            else CompletenessStatus.INCOMPLETE_BOUNDARY
        )
        evaluation_id = _stable_id(
            "BEV-SHADOW", *key, *selected
        )
        evaluations[key] = ShadowBoundaryEvaluation(
            evaluation_id=evaluation_id,
            boundary_definition_id=migration.normative_boundary_definition_id,
            boundary_set_definition_id=migration.normative_boundary_set_id,
            source_framework=source_framework,
            benchmark_family=family,
            benchmark_name=benchmark_name,
            benchmark_version=benchmark_version,
            profile=profile,
            evaluation_scope=evaluation_scope,
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
        for assessment in sorted(
            members, key=lambda item: _assessment_identity(item).as_tuple()
        ):
            identity = _assessment_identity(assessment)
            mapping_candidate = semantic_candidates.get(identity)
            role = (
                mapping_candidate.boundary_role
                if mapping_candidate
                else _role(assessment.relationship)
            )
            strength = _strength(role)
            effects = (
                mapping_candidate.satisfied_sub_boundaries
                if mapping_candidate
                else (assessment.enforced_sub_boundary or "catalog boundary effect",)
            )
            for capability_id in migration.capability_ids:
                for path_id in (
                    mapping_candidate.attack_path_ids
                    if mapping_candidate and mapping_candidate.attack_path_ids
                    else migration.attack_path_ids
                ):
                    path = catalog.get_attack_path(path_id)
                    for scenario_id in path.threat_scenario_ids:
                        for effect in effects:
                            mapping_id = _stable_id(
                                "MAP", identity.serialize(), capability_id, path_id, scenario_id, effect
                            )
                            mappings_by_control[identity].append(
                                NormativeMitigationMapping(
                                    mapping_id=mapping_id,
                                    control_id=assessment.control_id,
                                    source_identity=identity,
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

    # A tenant-wide/all-user enforcement is an equivalent implementation for
    # the same effect at a narrower subject or resource scope.  Retain both
    # atomic mappings, but do not manufacture duplicate Mandatory controls.
    complete_keys = {
        key for key, value in evaluations.items() if value.completeness_status in {
            CompletenessStatus.COMPLETE_STANDALONE_PRIMARY,
            CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET,
        }
    }
    paths_by_key: dict[EvaluationKey, frozenset[str]] = {}
    for key, entries in grouped.items():
        migration = resolve_legacy_boundary_set(key[-2], catalog)
        if migration is None:
            continue
        paths_by_key[key] = frozenset(
            path_id
            for _, candidate in entries
            for path_id in (
                candidate.attack_path_ids
                if candidate is not None and candidate.attack_path_ids
                else migration.attack_path_ids
            )
        )
    dominant_keys = {
        key for key in complete_keys if key[-1] == "tenant:all_resources|all_users"
    }
    dominated_keys = {
        key for key in complete_keys
        if key[-1] != "tenant:all_resources|all_users"
        and any(
            dominant[:6] == key[:6]
            and paths_by_key.get(key, frozenset()) <= paths_by_key.get(dominant, frozenset())
            for dominant in dominant_keys
        )
    }

    shadows: list[ShadowMandatoryAssessment] = []
    for legacy in sorted(
        legacy_assessments, key=lambda item: _assessment_identity(item).as_tuple()
    ):
        identity = _assessment_identity(legacy)
        control = controls[identity]
        candidates = _semantic_candidates(control)
        boundary_keys = (
            tuple(
                _evaluation_key(identity, item.semantic_mapping_id, item.evaluation_scope)
                for item in candidates
            )
            if candidates
            else (_evaluation_key(identity, legacy.boundary_set_id, "benchmark"),)
            if legacy.boundary_set_id
            else ()
        )
        migrations = {
            key: migration
            for key in boundary_keys
            if (migration := resolve_legacy_boundary_set(key[-2], catalog)) is not None
        }
        control_evaluation_pairs = tuple(
            (key, evaluations[key]) for key in boundary_keys if key in evaluations
        )
        control_evaluations = tuple(item for _, item in control_evaluation_pairs)
        mappings = tuple(sorted(mappings_by_control[identity], key=lambda item: item.mapping_id))
        findings: list[ShadowValidationFinding] = list(catalog_blockers)
        adapter_selection = select_adapter(control)
        if adapter_selection.finding:
            findings.append(
                ShadowValidationFinding(
                    code=adapter_selection.finding,
                    severity="warning",
                    message="Benchmark-family adapter selection did not resolve exactly one supported family.",
                    review_required=True,
                )
            )
        if not migrations:
            findings.append(ShadowValidationFinding(code="CATALOG_MAPPING_MISSING", severity="warning", message="No compatibility migration resolves this control to the normative catalog.", review_required=True))
        complete_evaluations = tuple(
            item for key, item in control_evaluation_pairs
            if key not in dominated_keys and item.completeness_status in {
                CompletenessStatus.COMPLETE_STANDALONE_PRIMARY,
                CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET,
            }
        )
        incomplete_evaluations = tuple(
            item for item in control_evaluations
            if item.completeness_status == CompletenessStatus.INCOMPLETE_BOUNDARY
        )
        equivalent_only = bool(control_evaluations) and not complete_evaluations and all(
            key in dominated_keys
            or item.completeness_status != CompletenessStatus.COMPLETE_STANDALONE_PRIMARY
            for key, item in control_evaluation_pairs
        ) and not incomplete_evaluations
        if incomplete_evaluations and not complete_evaluations:
            missing_effects = sorted(
                {
                    effect
                    for item in incomplete_evaluations
                    for effect in item.missing_sub_boundaries
                }
            )
            findings.append(ShadowValidationFinding(code="BOUNDARY_EVALUATION_INCOMPLETE", severity="warning", message=f"Missing effects: {', '.join(missing_effects)}", review_required=True))
        semantic_applicability = (
            _semantic_applicability(control)
            if candidates
            else None
        )
        applicability_unresolved = legacy.applicability_mode == "unresolved" or semantic_applicability in {
            FamilyApplicabilityStatus.MANDATORY_WHEN_FEATURE_DEPLOYED,
            FamilyApplicabilityStatus.UNRESOLVED,
        }
        if applicability_unresolved:
            findings.append(ShadowValidationFinding(code="APPLICABILITY_UNRESOLVED", severity="warning", message="Benchmark-scope applicability is unresolved.", review_required=True))
        if legacy.overlap_type in {"duplicate", "alternative"}:
            findings.append(ShadowValidationFinding(code="OVERLAP_UNRESOLVED", severity="warning", message=f"The {legacy.overlap_type} effect requires adjudication.", review_required=True))

        roles = {item.boundary_role for item in candidates} or {_role(legacy.relationship)}
        supporting_roles = {"supporting_hardening", "risk_adaptive_enhancement", "fine_tuning", "detection_only", "information_hiding", "operational"}
        supporting = roles <= supporting_roles
        review_blocked = any(item.review_required or item.severity == "error" for item in findings)
        qualifies = bool(
            migrations
            and mappings
            and complete_evaluations
            and bool(roles & {"standalone_primary_boundary", "boundary_set_core_member", "prerequisite"})
            and any(item.mitigation_strength in {"primary", "complementary"} for item in mappings)
            and bool(legacy.non_compensable_reason or any(item.non_compensable for item in candidates))
            and legacy.confidence == "High"
            and not applicability_unresolved
            and not review_blocked
        )
        normative: Proposal = (
            "Review Required"
            if applicability_unresolved
            else "Regular Control"
            if supporting or equivalent_only
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
        if not migrations:
            codes.add("SHADOW-MISSING-CATALOG-MAPPING")
        if incomplete_evaluations:
            codes.add("SHADOW-INCOMPLETE-BOUNDARY")
        if applicability_unresolved:
            codes.add("SHADOW-APPLICABILITY-DIFFERENCE")
        normative_confidence: Confidence = (
            "High" if complete_evaluations and all(item.confidence == "High" for item in complete_evaluations)
            else "Medium" if control_evaluations else "Low"
        )
        if normative_confidence != legacy.confidence:
            codes.add("SHADOW-CONFIDENCE-DIFFERENCE")
        if catalog_blockers:
            codes.add("SHADOW-VALIDATION-BLOCKED")
        if migrations and {
            item.normative_boundary_set_id for item in migrations.values()
        } != {legacy.boundary_set_id}:
            codes.add("SHADOW-BOUNDARY-DIFFERENCE")
        ordered_codes = tuple(sorted(codes))
        mapping_refs_resolve = bool(mappings) and all(
            item.source_identity in controls and item.confidence == "High" for item in mappings
        )
        cutover = bool(
            normative == legacy.proposal
            and mapping_refs_resolve
            and not review_blocked
            and complete_evaluations
            and normative_confidence == "High"
        )
        shadows.append(
            ShadowMandatoryAssessment(
                control_id=legacy.control_id,
                source_identity=identity,
                legacy_proposal=legacy.proposal,
                normative_proposal=normative,
                proposals_match=normative == legacy.proposal,
                legacy_boundary_set_id=legacy.boundary_set_id,
                normative_boundary_definition_ids=tuple(sorted({item.normative_boundary_definition_id for item in migrations.values()})),
                normative_boundary_set_definition_ids=tuple(sorted({item.normative_boundary_set_id for item in migrations.values()})),
                boundary_evaluation_ids=tuple(item.evaluation_id for item in sorted(control_evaluations, key=lambda value: value.evaluation_id)),
                mitigation_mapping_ids=tuple(item.mapping_id for item in mappings),
                capability_ids=tuple(sorted({item.capability_id for item in mappings})),
                threat_scenario_ids=tuple(sorted({item.threat_scenario_id for item in mappings})),
                attack_path_ids=tuple(sorted({item.attack_path_id for item in mappings})),
                security_outcome_ids=tuple(sorted({outcome for item in mappings for outcome in item.security_outcome_ids})),
                legacy_confidence=legacy.confidence,
                normative_confidence=normative_confidence,
                validation_findings=tuple(findings),
                mapping_gap_category=(None if migrations else _mapping_gap_category(legacy)),
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
