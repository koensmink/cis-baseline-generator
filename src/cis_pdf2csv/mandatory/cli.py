from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.exporters import write_coverage_json

from .exporters import write_assessment_csv, write_shadow_comparison, write_summary_json
from .pipeline import assess_controls
from .schema import MandatoryAssessment
from .shadow import assess_controls_shadow

console = Console()


def _print_summary(
    assessments: list[MandatoryAssessment], output: Path, shadow: bool
) -> None:
    counts = Counter(item.proposal for item in assessments)
    table = Table(title="cis-mandatory-analyze summary")
    table.add_column("Classification")
    table.add_column("Count", justify="right")
    for proposal in ("Candidate Mandatory", "Review Required", "Regular Control"):
        table.add_row(proposal, str(counts[proposal]))
    table.add_row("Total", str(len(assessments)))
    console.print(table)

    candidate_output = output.with_name(f"{output.stem}-candidate-mandatory.csv")
    review_output = output.with_name(f"{output.stem}-review-required.csv")
    console.print(f"Candidate output:\n  {candidate_output}")
    console.print(f"Review output:\n  {review_output}")
    console.print(f"Full assessment:\n  {output}")
    if shadow:
        console.print(
            f"[yellow]Advisory shadow output:[/yellow] "
            f"{output.with_name(f'{output.stem}-shadow-comparison.csv')}"
        )


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
    input_path = Path(args.input)
    if not input_path.is_file():
        parser.error(f"input file not found: {input_path}")
    if not output.parent.exists():
        parser.error(f"output directory does not exist: {output.parent}")
    try:
        records = _load_jsonl(input_path)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
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
        write_shadow_comparison(
            shadow_result.shadow_assessments,
            output.parent,
            output.stem,
        )
    _print_summary(assessments, output, shadow_result is not None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
