from __future__ import annotations

from collections import defaultdict

from cis_pdf2csv.mandatory.schema import MandatoryAssessment

from .attack_paths import ATTACK_PATHS


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

