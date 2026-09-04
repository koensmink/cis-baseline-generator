from __future__ import annotations

import csv
import json
from pathlib import Path

from pydantic import BaseModel

from .models import AssessmentStatus, BaselineAssessment


def _flat(model: BaseModel) -> dict[str, object]:
    data = model.model_dump(mode="json")
    data.pop("source_identity", None)
    exception = data.pop("exception", None)
    for key, value in tuple(data.items()):
        if isinstance(value, list):
            data[key] = "; ".join(str(item) for item in value)
    if isinstance(exception, dict):
        data["exception_decision"] = exception.get("decision", "")
        data["exception_rationale"] = exception.get("rationale", "")
        data["exception_approved_by"] = exception.get("approved_by", "")
        data["exception_expires_at"] = exception.get("expires_at", "")
    else:
        data["exception_decision"] = ""
        data["exception_rationale"] = ""
        data["exception_approved_by"] = ""
        data["exception_expires_at"] = ""
    return data


def _write_csv(
    path: Path,
    rows: list[dict[str, object]],
    *,
    fieldnames: list[str] | None = None,
) -> None:
    if not rows and fieldnames is None:
        return
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fieldnames if fieldnames is not None else list(rows[0])
        )
        writer.writeheader()
        writer.writerows(rows)


def export_assessment(result: BaselineAssessment, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    controls = list(result.controls)
    _write_csv(output_dir / "assessment.csv", [_flat(item) for item in controls])
    with (output_dir / "assessment.jsonl").open("w", encoding="utf-8") as handle:
        for item in controls:
            handle.write(item.model_dump_json() + "\n")
    (output_dir / "assessment.json").write_text(
        result.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    actionable = [
        item
        for item in controls
        if item.status
        in {
            AssessmentStatus.DECLARED_NON_COMPLIANT,
            AssessmentStatus.POTENTIAL_CONFLICT,
            AssessmentStatus.NOT_MEASURABLE,
            AssessmentStatus.MANUAL_EVIDENCE_REQUIRED,
        }
    ]
    _write_csv(
        output_dir / "action-required.csv",
        [_flat(item) for item in actionable],
        fieldnames=list(_flat(controls[0])) if controls else None,
    )
    summary = {
        "schema_version": result.schema_version,
        "assessed_at_utc": result.assessed_at_utc,
        "current_state_sha256": result.current_state_sha256,
        "current_state_status": result.current_state_status,
        "current_state_source": result.current_state_source,
        "effective_state_observed": result.effective_state_observed,
        "controls": len(controls),
        "status_counts": result.status_counts,
        "warnings": list(result.warnings),
    }
    (output_dir / "assessment-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
