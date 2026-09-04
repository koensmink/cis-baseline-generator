from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from cis_pdf2csv.environment_scan.models import CurrentStateSnapshot
from cis_pdf2csv.schema import ControlRecord

from .engine import assess_baseline
from .exporters import export_assessment
from .models import ExceptionRecord

console = Console()


def _load_controls(path: Path) -> list[ControlRecord]:
    controls: list[ControlRecord] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    controls.append(ControlRecord.model_validate_json(line))
                except (ValidationError, ValueError) as exc:
                    raise ValueError(
                        f"Invalid ControlRecord on line {line_number}: {exc}"
                    ) from exc
    except OSError as exc:
        raise ValueError(f"Cannot read controls file {path}: {exc}") from exc
    if not controls:
        raise ValueError("Controls input contains no ControlRecord objects")
    return controls


def _load_snapshot(path: Path) -> tuple[CurrentStateSnapshot, str]:
    try:
        raw = path.read_bytes()
        snapshot = CurrentStateSnapshot.model_validate_json(raw)
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid current-state snapshot {path}: {exc}") from exc
    return snapshot, hashlib.sha256(raw).hexdigest()


def _load_exceptions(path: Path | None) -> tuple[ExceptionRecord, ...]:
    if path is None:
        return ()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list):
            raise TypeError("exception file must contain a JSON array")
        return tuple(ExceptionRecord.model_validate(item) for item in value)
    except (OSError, TypeError, ValidationError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid exception file {path}: {exc}") from exc


def _at_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("--at-time must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("--at-time must include a timezone offset")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis-baseline-assess",
        description="Compare CIS controls with a current-state environment snapshot",
    )
    parser.add_argument("input", help="Parser-produced ControlRecord JSONL")
    parser.add_argument("--current-state", required=True, help="Environment-scan JSON")
    parser.add_argument("--exceptions", help="Optional approved exception records JSON")
    parser.add_argument("--at-time", help="Reproducible ISO 8601 assessment time")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory")
    args = parser.parse_args(argv)

    try:
        controls = _load_controls(Path(args.input))
        snapshot, snapshot_hash = _load_snapshot(Path(args.current_state))
        exceptions = _load_exceptions(
            Path(args.exceptions) if args.exceptions else None
        )
        result = assess_baseline(
            controls,
            snapshot,
            current_state_sha256=snapshot_hash,
            exceptions=exceptions,
            at_time=_at_time(args.at_time),
        )
        export_assessment(result, Path(args.output_dir))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    table = Table(title="cis-baseline-assess summary")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    table.add_row("Controls", str(len(result.controls)))
    for status, count in result.status_counts.items():
        table.add_row(status, str(count))
    console.print(table)
    console.print(f"Assessment:\n  {args.output_dir}")
    return 2 if result.current_state_status == "partial" else 0


if __name__ == "__main__":
    raise SystemExit(main())
