from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from pydantic import BaseModel

from .models import BaselinePlan, DeploymentReadiness


def _flat(model: BaseModel) -> dict[str, object]:
    data = model.model_dump(mode="json")
    data.pop("source_identity", None)
    for key, value in tuple(data.items()):
        if isinstance(value, list):
            data[key] = "; ".join(str(item) for item in value)
    return data


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def export_plan(plan: BaselinePlan, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    controls = list(plan.controls)
    _write_csv(output_dir / "enriched-controls.csv", [_flat(item) for item in controls])
    with (output_dir / "enriched-controls.jsonl").open("w", encoding="utf-8") as handle:
        for item in controls:
            handle.write(item.model_dump_json() + "\n")
    _write_csv(output_dir / "waves.csv", [_flat(item) for item in controls])
    for wave in range(6):
        members = [item for item in controls if item.recommended_wave == wave]
        if members:
            _write_csv(output_dir / f"wave-{wave:02d}.csv", [_flat(item) for item in members])
    for phase in plan.implementation_phases:
        members = [item for item in controls if item.execution_phase == phase.name]
        _write_csv(output_dir / f"phase-{phase.name}.csv", [_flat(item) for item in members])
    _write_csv(output_dir / "work-packages.csv", [_flat(item) for item in plan.work_packages])
    _write_csv(output_dir / "implementation-phases.csv", [_flat(item) for item in plan.implementation_phases])
    _write_csv(
        output_dir / "wave-00-prerequisites.csv",
        [{"sequence": index, "prerequisite": item} for index, item in enumerate(plan.prerequisites, start=1)],
    )
    review = [item for item in controls if item.deployment_readiness != DeploymentReadiness.DEPLOYMENT_READY]
    _write_csv(output_dir / "manual-review.csv", [_flat(item) for item in review])
    summary = {
        "controls": len(controls),
        "waves": dict(sorted(Counter(str(item.recommended_wave) for item in controls).items())),
        "execution_phase_counts": dict(sorted(Counter(item.execution_phase for item in controls).items())),
        "priority_tiers": dict(sorted(Counter(item.priority_tier.value for item in controls).items())),
        "deployment_readiness": dict(sorted(Counter(item.deployment_readiness.value for item in controls).items())),
        "work_packages": len(plan.work_packages),
        "implementation_phases": len(plan.implementation_phases),
        "prerequisites": len(plan.prerequisites),
    }
    (output_dir / "plan-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
