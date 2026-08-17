from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from .schema import MandatoryAssessment
from .shadow import ShadowMandatoryAssessment


def _row(assessment: MandatoryAssessment) -> dict[str, object]:
    data = assessment.model_dump()
    data["mandatory_criteria"] = ";".join(assessment.mandatory_criteria)
    data["exclusion_reasons"] = ";".join(assessment.exclusion_reasons)
    data["related_control_ids"] = ";".join(assessment.related_control_ids)
    data["capability_ids"] = ";".join(assessment.capability_ids)
    data["attack_path_ids"] = ";".join(assessment.attack_path_ids)
    data["attack_path_names"] = ";".join(assessment.attack_path_names)
    data["attack_stages"] = ";".join(assessment.attack_stages)
    data["mitigation_roles"] = ";".join(assessment.mitigation_roles)
    data["mitigation_strengths"] = ";".join(assessment.mitigation_strengths)
    data["mapping_confidences"] = ";".join(assessment.mapping_confidences)
    data["attack_path_mappings"] = json.dumps(
        [item.model_dump() for item in assessment.attack_path_mappings], ensure_ascii=False
    )
    data["benchmark_evidence"] = json.dumps(
        [item.model_dump() for item in assessment.benchmark_evidence], ensure_ascii=False
    )
    return data


def write_assessment_csv(assessments: Iterable[MandatoryAssessment], path: Path) -> None:
    rows = [_row(item) for item in assessments]
    fieldnames = list(MandatoryAssessment.model_fields)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)


def write_summary_json(assessments: Iterable[MandatoryAssessment], path: Path) -> None:
    rows = list(assessments)
    counts: Counter[str] = Counter(item.proposal for item in rows)
    payload = {
        "total_controls": len(rows),
        "proposal_counts": {
            proposal: counts.get(proposal, 0)
            for proposal in ("Regular Control", "Review Required", "Candidate Mandatory")
        },
        "candidate_mandatory_control_ids": [item.control_id for item in rows if item.proposal == "Candidate Mandatory"],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _shadow_payload(item: ShadowMandatoryAssessment) -> dict[str, object]:
    payload = item.model_dump(mode="json")
    payload["normative_status"] = "advisory"
    return payload


def write_shadow_comparison(
    assessments: Iterable[ShadowMandatoryAssessment], output_directory: Path
) -> None:
    """Write byte-stable advisory comparison and summary artifacts."""
    rows = sorted(assessments, key=lambda item: item.control_id)
    json_path = output_directory / "mandatory-shadow-comparison.json"
    csv_path = output_directory / "mandatory-shadow-comparison.csv"
    summary_path = output_directory / "mandatory-shadow-summary.json"
    json_path.write_text(
        json.dumps([_shadow_payload(item) for item in rows], indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    fieldnames = [*ShadowMandatoryAssessment.model_fields, "normative_status"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for item in rows:
            payload = _shadow_payload(item)
            for key, value in tuple(payload.items()):
                if isinstance(value, list):
                    payload[key] = json.dumps(value, sort_keys=True, ensure_ascii=False)
            writer.writerow(payload)

    differences_by_boundary: Counter[str] = Counter()
    differences_by_attack_path: Counter[str] = Counter()
    for item in rows:
        if item.proposals_match:
            continue
        differences_by_boundary.update(item.normative_boundary_definition_ids or ("UNRESOLVED",))
        differences_by_attack_path.update(item.attack_path_ids or ("UNRESOLVED",))
    summary = {
        "normative_status": "advisory",
        "total_controls": len(rows),
        "exact_matches": sum(item.proposals_match for item in rows),
        "promotions": sum("SHADOW-NORMATIVE-PROMOTION" in item.difference_codes for item in rows),
        "demotions": sum("SHADOW-NORMATIVE-DEMOTION" in item.difference_codes for item in rows),
        "review_required_differences": sum(
            not item.proposals_match and item.normative_proposal == "Review Required" for item in rows
        ),
        "missing_catalog_mappings": sum("SHADOW-MISSING-CATALOG-MAPPING" in item.difference_codes for item in rows),
        "blocked_validations": sum("SHADOW-VALIDATION-BLOCKED" in item.difference_codes for item in rows),
        "differences_by_boundary": dict(sorted(differences_by_boundary.items())),
        "differences_by_attack_path": dict(sorted(differences_by_attack_path.items())),
        "cutover_eligible_controls": [item.control_id for item in rows if item.cutover_eligible],
        "legacy_proposal_counts": dict(sorted(Counter(item.legacy_proposal for item in rows).items())),
        "normative_advisory_proposal_counts": dict(sorted(Counter(item.normative_proposal for item in rows).items())),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
