from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from .schema import MandatoryAssessment


def _row(assessment: MandatoryAssessment) -> dict[str, object]:
    data = assessment.model_dump()
    data["mandatory_criteria"] = ";".join(assessment.mandatory_criteria)
    data["exclusion_reasons"] = ";".join(assessment.exclusion_reasons)
    data["related_control_ids"] = ";".join(assessment.related_control_ids)
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
    counts = Counter(item.proposal for item in rows)
    payload = {
        "total_controls": len(rows),
        "proposal_counts": {
            proposal: counts.get(proposal, 0)
            for proposal in ("Regular Control", "Review Required", "Candidate Mandatory")
        },
        "candidate_mandatory_control_ids": [item.control_id for item in rows if item.proposal == "Candidate Mandatory"],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
