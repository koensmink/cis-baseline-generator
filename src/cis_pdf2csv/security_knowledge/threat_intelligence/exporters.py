from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path

from .prioritization import (
    AdvisoryAction,
    ThreatInformedControlOverlay,
    ThreatPrioritySummary,
    ThreatRelevance,
)
from .projection import ControlProjectionResult
from .resolution import ThreatResolution

THREAT_OVERLAY_CSV_FIELDS = [
    "source_framework",
    "benchmark_family",
    "benchmark_name",
    "benchmark_version",
    "profile",
    "source_identity",
    "control_id",
    "title",
    "base_proposal",
    "threat_relevance",
    "priority_confidence",
    "advisory_action",
    "threat_context_ids",
    "threat_resolution_ids",
    "attack_path_ids",
    "boundary_ids",
    "technique_ids",
    "context_technique_ids",
    "derived_technique_ids",
    "context_scenario_ids",
    "derived_scenario_ids",
    "mitigation_roles",
    "mitigation_strengths",
    "boundary_roles",
    "applicability",
    "security_effects",
    "rationale",
    "findings",
]


def _csv_row(item: ThreatInformedControlOverlay) -> dict[str, str]:
    identity = item.source_identity
    return {
        "source_framework": identity.source_framework,
        "benchmark_family": identity.benchmark_family,
        "benchmark_name": identity.benchmark_name,
        "benchmark_version": identity.benchmark_version,
        "profile": identity.benchmark_profile,
        "source_identity": identity.serialize(),
        "control_id": item.control_id,
        "title": item.title or "",
        "base_proposal": item.base_proposal.value,
        "threat_relevance": item.threat_relevance.value,
        "priority_confidence": item.priority_confidence.value,
        "advisory_action": item.advisory_action.value,
        "threat_context_ids": ";".join(item.threat_context_ids),
        "threat_resolution_ids": ";".join(
            sorted({driver.threat_resolution_id for driver in item.drivers})
        ),
        "attack_path_ids": ";".join(item.attack_path_ids),
        "boundary_ids": ";".join(item.boundary_ids),
        "technique_ids": ";".join(item.technique_ids),
        "context_technique_ids": ";".join(item.context_technique_ids),
        "derived_technique_ids": ";".join(item.derived_technique_ids),
        "context_scenario_ids": ";".join(item.context_scenario_ids),
        "derived_scenario_ids": ";".join(item.derived_scenario_ids),
        "mitigation_roles": ";".join(role.value for role in item.mitigation_roles),
        "mitigation_strengths": ";".join(
            sorted({driver.mitigation_strength.value for driver in item.drivers})
        ),
        "boundary_roles": ";".join(role.value for role in item.boundary_roles),
        "applicability": ";".join(
            sorted({driver.applicability_mode.value for driver in item.drivers})
        ),
        "security_effects": ";".join(item.security_effects),
        "rationale": item.rationale,
        "findings": json.dumps(
            [finding.model_dump(mode="json") for finding in item.findings],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
    }


def write_threat_overlay_csv(
    overlays: Iterable[ThreatInformedControlOverlay], path: Path
) -> None:
    rows = sorted(overlays, key=lambda item: item.source_identity.as_tuple())
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=THREAT_OVERLAY_CSV_FIELDS, quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(_csv_row(item) for item in rows)


def write_threat_overlay_artifacts(
    overlays: Iterable[ThreatInformedControlOverlay],
    projections: ControlProjectionResult,
    resolutions: Iterable[ThreatResolution],
    summary: ThreatPrioritySummary,
    output: Path,
) -> tuple[Path, ...]:
    rows = tuple(sorted(overlays, key=lambda item: item.source_identity.as_tuple()))
    resolved = tuple(
        sorted(
            resolutions,
            key=lambda item: (item.threat_context_id, item.threat_context_revision),
        )
    )
    high_path = output.with_name(f"{output.stem}-high.csv")
    review_path = output.with_name(f"{output.stem}-review.csv")
    json_path = output.with_name(f"{output.stem}.json")
    summary_path = output.with_name(f"{output.stem}-summary.json")
    write_threat_overlay_csv(rows, output)
    write_threat_overlay_csv(
        (
            item
            for item in rows
            if item.threat_relevance in {ThreatRelevance.HIGH, ThreatRelevance.CRITICAL}
        ),
        high_path,
    )
    write_threat_overlay_csv(
        (item for item in rows if item.advisory_action == AdvisoryAction.REVIEW),
        review_path,
    )
    json_path.write_text(
        json.dumps(
            [item.model_dump(mode="json") for item in rows],
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    summary_payload = {
        "priority_summary": summary.model_dump(mode="json"),
        "projection_findings": [
            item.model_dump(mode="json") for item in projections.findings
        ],
        "threat_resolutions": [item.model_dump(mode="json") for item in resolved],
    }
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    return output, high_path, review_path, json_path, summary_path


__all__ = [
    "THREAT_OVERLAY_CSV_FIELDS",
    "write_threat_overlay_artifacts",
    "write_threat_overlay_csv",
]
