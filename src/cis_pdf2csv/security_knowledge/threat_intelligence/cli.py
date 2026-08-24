from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.catalog import SECURITY_KNOWLEDGE_CATALOG
from cis_pdf2csv.security_knowledge.phase1_mapping_adapter import (
    adapt_phase1_assessments_to_mappings,
)

from .exporters import write_threat_overlay_artifacts
from .prioritization import (
    ThreatPrioritySummary,
    prioritize_threat_projections,
    summarize_threat_priority,
)
from .projection import project_threat_resolutions
from .resolution import ThreatResolution, resolve_threat_context
from .schema import ThreatContext
from .validation import validate_catalog_references, validate_threat_context

console = Console()


def _load_controls(path: Path) -> list[ControlRecord]:
    records: list[ControlRecord] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(ControlRecord.model_validate_json(line))
            except (ValidationError, ValueError) as exc:
                raise ValueError(
                    f"Invalid ControlRecord on line {line_number}: {exc}"
                ) from exc
    return records


def _load_threat_context(path: Path) -> ThreatContext:
    try:
        return ThreatContext.model_validate_json(path.read_text(encoding="utf-8"))
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid ThreatContext in {path}: {exc}") from exc


def _evaluation_time(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid --at-time value: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("--at-time must include a timezone offset")
    return parsed


def _validate_and_resolve(
    contexts: list[ThreatContext],
    *,
    at_time: datetime,
    historical_mode: bool,
) -> tuple[ThreatResolution, ...]:
    resolutions: list[ThreatResolution] = []
    for context in sorted(contexts, key=lambda item: item.threat_context_id):
        findings = (
            *validate_threat_context(context, at_time=at_time),
            *validate_catalog_references(
                context,
                SECURITY_KNOWLEDGE_CATALOG,
                historical_mode=historical_mode,
            ),
        )
        blocking = sorted(
            (item for item in findings if item.blocking),
            key=lambda item: (item.code, item.object_id, item.message),
        )
        if blocking:
            details = "; ".join(f"{item.code}: {item.message}" for item in blocking)
            raise ValueError(
                f"Blocking ThreatContext validation for {context.threat_context_id}: {details}"
            )
        resolutions.append(
            resolve_threat_context(
                context,
                SECURITY_KNOWLEDGE_CATALOG,
                at_time=at_time,
                historical_mode=historical_mode,
            )
        )
    return tuple(resolutions)


def _print_summary(
    context_count: int, summary: ThreatPrioritySummary, output: Path
) -> None:
    metrics = summary.model_dump()
    table = Table(title="cis-threat-analyze summary")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    for label, value in (
        ("Threat contexts", context_count),
        ("Projected controls", metrics["total_projected_controls"]),
        ("Normal", metrics["normal"]),
        ("Elevated", metrics["elevated"]),
        ("High", metrics["high"]),
        ("Critical", metrics["critical"]),
        ("Review capped", metrics["review_capped_controls"]),
    ):
        table.add_row(label, str(value))
    console.print(table)
    if metrics["total_projected_controls"] == 0:
        console.print("No active projected controls were found.")
    console.print(f"Full overlay:\n  {output}")
    console.print(
        f"High/Critical overlay:\n  {output.with_name(f'{output.stem}-high.csv')}"
    )
    console.print(f"Review overlay:\n  {output.with_name(f'{output.stem}-review.csv')}")
    console.print(f"Structured overlay:\n  {output.with_name(f'{output.stem}.json')}")
    console.print(
        f"Summary metadata:\n  {output.with_name(f'{output.stem}-summary.json')}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis-threat-analyze",
        description="Deterministic advisory threat relevance analysis",
    )
    parser.add_argument("input", help="Parser-produced ControlRecord JSONL")
    parser.add_argument(
        "--threat-context",
        action="append",
        required=True,
        metavar="JSON",
        help="Validated ThreatContext JSON; repeat for multiple contexts",
    )
    parser.add_argument("-o", "--output", required=True, help="Full threat overlay CSV")
    parser.add_argument(
        "--historical",
        action="store_true",
        help="Resolve inactive catalog objects explicitly for historical analysis",
    )
    parser.add_argument(
        "--at-time",
        help="Timezone-aware ISO-8601 evaluation time; defaults to current UTC time",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    threat_paths = [Path(value) for value in args.threat_context]
    output = Path(args.output)
    if not input_path.is_file():
        parser.error(f"input file not found: {input_path}")
    for path in threat_paths:
        if not path.is_file():
            parser.error(f"threat context file not found: {path}")
    if not output.parent.is_dir():
        parser.error(f"output directory does not exist: {output.parent}")
    if output.exists() and not output.is_file():
        parser.error(f"output path is not a file: {output}")

    try:
        at_time = _evaluation_time(args.at_time)
        controls = _load_controls(input_path)
        contexts = [_load_threat_context(path) for path in threat_paths]
        resolutions = _validate_and_resolve(
            contexts, at_time=at_time, historical_mode=args.historical
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    assessments = assess_controls(controls)
    compatibility = adapt_phase1_assessments_to_mappings(controls, assessments)
    projections = project_threat_resolutions(
        resolutions,
        compatibility.mappings,
        assessments,
        catalog=SECURITY_KNOWLEDGE_CATALOG,
    )
    overlays = prioritize_threat_projections(projections.projections)
    summary = summarize_threat_priority(overlays)
    try:
        write_threat_overlay_artifacts(
            overlays, projections, resolutions, summary, output
        )
    except OSError as exc:
        parser.error(f"cannot write threat overlay artifacts: {exc}")
    _print_summary(len(contexts), summary, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
