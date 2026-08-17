from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import ValidationError

from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.exporters import write_coverage_json

from .exporters import write_assessment_csv, write_shadow_comparison, write_summary_json
from .pipeline import assess_controls
from .shadow import assess_controls_shadow


def _load_jsonl(path: Path) -> list[ControlRecord]:
    records: list[ControlRecord] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(ControlRecord.model_validate_json(line))
            except (ValidationError, ValueError) as exc:
                raise ValueError(f"Invalid ControlRecord on line {line_number}: {exc}") from exc
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic Mandatory-control preselection")
    parser.add_argument("input", help="Parser-produced ControlRecord JSONL")
    parser.add_argument("-o", "--output", required=True, help="Full assessment CSV")
    parser.add_argument(
        "--shadow-normative",
        action="store_true",
        help="Also run the normative catalog pipeline in advisory shadow mode",
    )
    args = parser.parse_args(argv)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    records = _load_jsonl(Path(args.input))
    shadow_result = assess_controls_shadow(records) if args.shadow_normative else None
    assessments = list(shadow_result.legacy_assessments) if shadow_result else assess_controls(records)
    write_assessment_csv(assessments, output)
    write_assessment_csv(
        (item for item in assessments if item.proposal == "Candidate Mandatory"),
        output.with_name(f"{output.stem}-candidate-mandatory.csv"),
    )
    write_assessment_csv(
        (item for item in assessments if item.proposal == "Review Required"),
        output.with_name(f"{output.stem}-review-required.csv"),
    )
    write_summary_json(assessments, output.with_name(f"{output.stem}-summary.json"))
    write_coverage_json(
        assessments,
        output.with_name(f"{output.stem}-attack-path-coverage.json"),
    )
    if shadow_result:
        write_shadow_comparison(shadow_result.shadow_assessments, output.parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
