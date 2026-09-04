from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from cis_pdf2csv.schema import ControlRecord

from .engine import build_plan
from .exporters import export_plan

console = Console()


def _load_controls(path: Path) -> list[ControlRecord]:
    controls: list[ControlRecord] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                controls.append(ControlRecord.model_validate_json(line))
            except (ValidationError, ValueError) as exc:
                raise ValueError(f"Invalid ControlRecord on line {line_number}: {exc}") from exc
    if not controls:
        raise ValueError("Input contains no ControlRecord objects")
    return controls


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create an enriched CIS implementation and wave plan")
    parser.add_argument("input", help="Parser-produced ControlRecord JSONL")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory")
    parser.add_argument(
        "--max-phase-size",
        type=int,
        default=75,
        help="Maximum controls per execution phase (default: 75)",
    )
    args = parser.parse_args(argv)
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    if not input_path.is_file():
        parser.error(f"input file not found: {input_path}")
    try:
        controls = _load_controls(input_path)
        plan = build_plan(controls, max_phase_size=args.max_phase_size)
        export_plan(plan, output_dir)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    waves = Counter(item.recommended_wave for item in plan.controls)
    table = Table(title="cis-baseline-plan summary")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    table.add_row("Controls", str(len(plan.controls)))
    table.add_row("Work packages", str(len(plan.work_packages)))
    table.add_row("Execution phases", str(len(plan.implementation_phases)))
    table.add_row("Wave 0 prerequisites", str(len(plan.prerequisites)))
    for wave, count in sorted(waves.items()):
        table.add_row(f"Wave {wave}", str(count))
    console.print(table)
    console.print(f"Implementation plan:\n  {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
