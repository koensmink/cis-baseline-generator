from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import IntuneMapping, MappingConflict, MappingStatus, SuggestedMapping

BASELINE_FIELDS = [
    "platform",
    "source_framework",
    "benchmark_family",
    "benchmark_name",
    "benchmark_version",
    "profile",
    "cis_id",
    "title",
    "implementation_type",
    "implementation_method",
    "intune_area",
    "setting_name",
    "value",
    "confidence",
    "candidate_confidence",
    "candidate_source",
    "mapping_status",
    "canonical_identifier",
    "verification_source",
    "verification_catalog_version",
    "verification_match_method",
    "verification_reason_codes",
    "rule_id",
    "reason_code",
    "parsed_value_type",
    "quality_flags",
    "notes",
]


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
    rows = [item for item in mappings if item.mapping_status == MappingStatus.VERIFIED]

    with out_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=BASELINE_FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow(_mapping_csv_row(row))


def _mapping_csv_row(mapping: IntuneMapping) -> dict[str, object]:
    verification = mapping.verification
    return {
        "platform": mapping.platform,
        "source_framework": mapping.source_framework,
        "benchmark_family": mapping.benchmark_family,
        "benchmark_name": mapping.benchmark_name,
        "benchmark_version": mapping.benchmark_version,
        "profile": mapping.profile,
        "cis_id": mapping.cis_id,
        "title": mapping.title,
        "implementation_type": mapping.implementation_type,
        "implementation_method": mapping.implementation_method.value,
        "intune_area": mapping.intune_area,
        "setting_name": mapping.setting_name,
        "value": mapping.value,
        "confidence": mapping.confidence,
        "candidate_confidence": mapping.candidate_confidence,
        "candidate_source": mapping.candidate_source.value,
        "mapping_status": mapping.mapping_status.value,
        "canonical_identifier": mapping.canonical_identifier or "",
        "verification_source": verification.source or "",
        "verification_catalog_version": verification.catalog_version or "",
        "verification_match_method": verification.match_method or "",
        "verification_reason_codes": ";".join(verification.reason_codes),
        "rule_id": mapping.rule_id,
        "reason_code": mapping.reason_code or "",
        "parsed_value_type": mapping.parsed_value_type or "",
        "quality_flags": ";".join(mapping.quality_flags),
        "notes": mapping.notes or "",
    }


def write_manual_review_csv(mappings: Iterable[IntuneMapping], out_path: Path) -> None:
    manual = [
        item
        for item in mappings
        if item.mapping_status
        in {MappingStatus.UNVERIFIED, MappingStatus.MANUAL_REVIEW}
    ]
    with out_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=BASELINE_FIELDS, quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(_mapping_csv_row(item) for item in manual)


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
                data["matched_rule_ids"] = ";".join(
                    str(x) for x in data["matched_rule_ids"]
                )
            if isinstance(data.get("matched_implementation_types"), list):
                data["matched_implementation_types"] = ";".join(
                    str(x) for x in data["matched_implementation_types"]
                )
            writer.writerow(data)


def write_intune_policies_json(
    mappings: Iterable[IntuneMapping], out_path: Path
) -> None:
    grouped: dict[str, list[dict]] = {}

    for mapping in mappings:
        if mapping.mapping_status != MappingStatus.VERIFIED:
            continue
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
                "implementation_method": mapping.implementation_method.value,
                "setting_name": mapping.setting_name,
                "value": mapping.value,
                "confidence": mapping.confidence,
                "candidate_confidence": mapping.candidate_confidence,
                "candidate_source": mapping.candidate_source.value,
                "mapping_status": mapping.mapping_status.value,
                "canonical_identifier": mapping.canonical_identifier,
                "verification": mapping.verification.model_dump(mode="json"),
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

    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_suggested_mappings_jsonl(
    suggestions: Iterable[SuggestedMapping | dict],
    out_path: Path,
) -> None:
    with out_path.open("w", encoding="utf-8") as f:
        for suggestion in suggestions:
            payload = _to_dict(suggestion)
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
