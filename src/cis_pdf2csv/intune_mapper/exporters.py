from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import IntuneMapping, MappingConflict, SuggestedMapping


def _to_dict(row: Any) -> dict:
    """
    Support both Pydantic models and plain dict rows.
    """
    if hasattr(row, "model_dump"):
        return row.model_dump()
    if isinstance(row, dict):
        return row
    raise TypeError(f"Unsupported row type for export: {type(row)!r}")


def write_baseline_csv(mappings: Iterable[IntuneMapping], out_path: Path) -> None:
    rows = list(mappings)
    fieldnames = [
        "source_framework",
        "benchmark_family",
        "benchmark_name",
        "benchmark_version",
        "profile",
        "cis_id",
        "title",
        "implementation_type",
        "intune_area",
        "setting_name",
        "value",
        "confidence",
        "rule_id",
        "reason_code",
        "parsed_value_type",
        "quality_flags",
        "notes",
    ]

    with out_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            data = _to_dict(row)
            if isinstance(data.get("quality_flags"), list):
                data["quality_flags"] = ";".join(str(x) for x in data["quality_flags"])
            writer.writerow(data)


def write_manual_review_csv(mappings: Iterable[IntuneMapping], out_path: Path) -> None:
    manual = [m for m in mappings if m.implementation_type == "manual_review"]
    write_baseline_csv(manual, out_path)


def write_conflicts_csv(conflicts: Iterable[MappingConflict], out_path: Path) -> None:
    rows = list(conflicts)
    fieldnames = [
        "cis_id",
        "title",
        "selected_rule_id",
        "selected_implementation_type",
        "matched_rule_ids",
        "matched_implementation_types",
    ]

    with out_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            data = _to_dict(row)
            if isinstance(data.get("matched_rule_ids"), list):
                data["matched_rule_ids"] = ";".join(str(x) for x in data["matched_rule_ids"])
            if isinstance(data.get("matched_implementation_types"), list):
                data["matched_implementation_types"] = ";".join(
                    str(x) for x in data["matched_implementation_types"]
                )
            writer.writerow(data)


def write_intune_policies_json(mappings: Iterable[IntuneMapping], out_path: Path) -> None:
    grouped: dict[str, list[dict]] = {}

    for mapping in mappings:
        area = mapping.intune_area
        grouped.setdefault(area, []).append(
            {
                "source_framework": mapping.source_framework,
                "benchmark_family": mapping.benchmark_family,
                "benchmark_name": mapping.benchmark_name,
                "benchmark_version": mapping.benchmark_version,
                "profile": mapping.profile,
                "cis_id": mapping.cis_id,
                "title": mapping.title,
                "implementation_type": mapping.implementation_type,
                "setting_name": mapping.setting_name,
                "value": mapping.value,
                "confidence": mapping.confidence,
                "rule_id": mapping.rule_id,
                "reason_code": mapping.reason_code,
                "parsed_value_type": mapping.parsed_value_type,
                "quality_flags": mapping.quality_flags,
            }
        )

    payload = {
        "policies": [
            {
                "intune_area": area,
                "settings": settings,
            }
            for area, settings in sorted(grouped.items())
        ]
    }

    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_suggested_mappings_jsonl(
    suggestions: Iterable[SuggestedMapping | dict],
    out_path: Path,
) -> None:
    with out_path.open("w", encoding="utf-8") as f:
        for suggestion in suggestions:
            payload = _to_dict(suggestion)
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
