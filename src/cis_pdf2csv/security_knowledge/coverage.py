from __future__ import annotations

from collections import defaultdict

from cis_pdf2csv.mandatory.schema import MandatoryAssessment

from .attack_paths import ATTACK_PATHS


def build_normative_coverage_report(
    assessments: list[MandatoryAssessment],
) -> dict[str, object]:
    """Project Phase-1 assessments through the catalog without numeric risk scoring."""
    from .catalog import SECURITY_KNOWLEDGE_CATALOG
    from .compatibility import adapt_phase1_assessments

    result = adapt_phase1_assessments(assessments, SECURITY_KNOWLEDGE_CATALOG)
    represented_paths = {identifier for item in result.resolutions for identifier in item.attack_path_ids}
    represented_capabilities = {identifier for item in result.resolutions for identifier in item.capability_ids}
    represented_threats = {identifier for item in result.resolutions for identifier in item.threat_scenario_ids}
    represented_outcomes = {identifier for item in result.resolutions for identifier in item.security_outcome_ids}
    by_boundary: dict[str, set[str]] = defaultdict(set)
    for assessment in assessments:
        if assessment.boundary_set_id:
            by_boundary[assessment.boundary_set_id].add(assessment.relationship)
    complete_complementary = sorted(
        identifier for identifier, roles in by_boundary.items()
        if "boundary-set core member" in roles and any(item.proposal == "Candidate Mandatory" and item.boundary_set_id == identifier for item in assessments)
    )
    standalone = sorted(
        item.control_id for item in assessments
        if item.proposal == "Candidate Mandatory" and item.relationship == "standalone primary boundary"
    )
    supporting_only = sorted(identifier for identifier, roles in by_boundary.items() if roles <= {"supporting hardening", "fine-tuning"})
    detection_only = sorted(identifier for identifier, roles in by_boundary.items() if roles == {"detection-only"})
    incomplete = sorted({item.boundary_set_id for item in assessments if item.proposal == "Review Required" and item.boundary_set_id})
    return {
        "attack_paths_with_no_effective_mitigation": sorted({path.attack_path_id for path in SECURITY_KNOWLEDGE_CATALOG.attack_paths} - represented_paths),
        "complete_standalone_primary_coverage": standalone,
        "complete_complementary_core_coverage": complete_complementary,
        "supporting_only_coverage": supporting_only,
        "detection_only_coverage": detection_only,
        "incomplete_boundaries": incomplete,
        "capabilities_represented": sorted(represented_capabilities),
        "threat_scenarios_represented": sorted(represented_threats),
        "outcomes_represented": sorted(represented_outcomes),
        "unresolved_migration_mappings": [item.model_dump(mode="json") for item in result.findings],
    }


def build_coverage_report(assessments: list[MandatoryAssessment]) -> dict[str, object]:
    controls: dict[str, set[str]] = defaultdict(set)
    candidates: dict[str, set[str]] = defaultdict(set)
    boundary_sets: dict[str, set[str]] = defaultdict(set)
    strengths: dict[str, set[str]] = defaultdict(set)
    capabilities: set[str] = set()
    boundary_status: dict[tuple[str, str], set[str]] = defaultdict(set)

    for assessment in assessments:
        capabilities.update(assessment.capability_ids)
        for mapping in assessment.attack_path_mappings:
            path_id = mapping.attack_path_id
            controls[path_id].add(assessment.control_id)
            strengths[path_id].add(mapping.mitigation_strength)
            if assessment.proposal == "Candidate Mandatory":
                candidates[path_id].add(assessment.control_id)
            if assessment.boundary_set_id:
                boundary_sets[path_id].add(assessment.boundary_set_id)
                boundary_status[(path_id, assessment.boundary_set_id)].add(assessment.proposal)

    incomplete = [
        {"attack_path_id": path_id, "boundary_set_id": boundary_id}
        for (path_id, boundary_id), proposals in sorted(boundary_status.items())
        if "Review Required" in proposals
    ]
    return {
        "controls_per_attack_path": {
            path.attack_path_id: sorted(controls[path.attack_path_id]) for path in ATTACK_PATHS
        },
        "candidate_mandatory_controls_per_attack_path": {
            path.attack_path_id: sorted(candidates[path.attack_path_id]) for path in ATTACK_PATHS
        },
        "boundary_sets_per_attack_path": {
            path.attack_path_id: sorted(boundary_sets[path.attack_path_id]) for path in ATTACK_PATHS
        },
        "attack_paths_with_no_primary_mitigation": [
            path.attack_path_id
            for path in ATTACK_PATHS
            if controls[path.attack_path_id] and "primary" not in strengths[path.attack_path_id]
        ],
        "attack_paths_with_incomplete_boundary_coverage": incomplete,
        "security_capabilities_represented": sorted(capabilities),
    }
