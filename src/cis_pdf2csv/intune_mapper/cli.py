from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from .exporters import (
    write_baseline_csv,
    write_conflicts_csv,
    write_intune_policies_json,
    write_manual_review_csv,
    write_suggested_mappings_jsonl,
)
from .llm_fallback import OpenAILLMClient
from .models import MappingInputControl, MappingStatus
from .resolver import resolve_controls
from .suggestion_normalizer import normalize_suggestions

console = Console()


def _load_controls_jsonl(path: Path) -> list[MappingInputControl]:
    controls: list[MappingInputControl] = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                controls.append(MappingInputControl(**json.loads(line)))
            except (json.JSONDecodeError, ValidationError, TypeError) as exc:
                raise ValueError(
                    f"Invalid mapping input on line {line_number}: {exc}"
                ) from exc

    return controls


def _build_llm_client(enabled: bool, output_dir: Path):
    if not enabled:
        return None

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        console.print(
            "[yellow]LLM fallback requested, but OPENAI_API_KEY is not set. "
            "Heuristic fallback will be used.[/yellow]"
        )
        return None

    try:
        cache_path = output_dir / "llm_cache.json"
        return OpenAILLMClient(
            api_key=api_key,
            model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            cache_path=cache_path,
        )
    except (OSError, ValueError) as e:
        console.print(
            f"[yellow]Failed to initialize OpenAI client: {e}. "
            "Heuristic fallback will be used.[/yellow]"
        )
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis-intune-map",
        description="Map parsed CIS controls to Intune baseline artifacts",
    )
    parser.add_argument("input", help="Input controls JSONL exported by cis-pdf2csv")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory")
    parser.add_argument(
        "--llm-fallback",
        action="store_true",
        help="Use LLM fallback for controls that cannot be mapped deterministically",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    if not input_path.is_file():
        parser.error(f"input file not found: {input_path}")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        parser.error(f"cannot create output directory {output_dir}: {exc}")

    try:
        controls = _load_controls_jsonl(input_path)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    llm_client = _build_llm_client(args.llm_fallback, output_dir)

    result = resolve_controls(
        controls,
        llm_client=llm_client,
    )

    mappings = result.mappings
    conflicts = result.conflicts
    suggestions = result.suggestions

    normalized_suggestions = normalize_suggestions(
        [suggestion.model_dump(mode="json") for suggestion in suggestions]
    )

    write_baseline_csv(mappings, output_dir / "baseline.csv")
    write_intune_policies_json(mappings, output_dir / "intune_policies.json")
    write_manual_review_csv(mappings, output_dir / "manual_review.csv")
    write_suggested_mappings_jsonl(
        normalized_suggestions,
        output_dir / "suggested_mappings.jsonl",
    )
    write_conflicts_csv(conflicts, output_dir / "conflicts.csv")

    verified_count = sum(
        item.mapping_status == MappingStatus.VERIFIED for item in mappings
    )
    unverified_count = sum(
        item.mapping_status == MappingStatus.UNVERIFIED for item in mappings
    )
    manual_count = sum(
        item.mapping_status == MappingStatus.MANUAL_REVIEW for item in mappings
    )
    needs_validation_count = len(
        [s for s in normalized_suggestions if s.get("needs_validation")]
    )

    table = Table(title="cis-intune-map summary")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    for label, count in (
        ("Controls", len(controls)),
        ("Verified", verified_count),
        ("Unverified", unverified_count),
        ("Manual review", manual_count),
        ("Conflicts", len(conflicts)),
        ("Suggestions", len(normalized_suggestions)),
        ("Needs validation", needs_validation_count),
    ):
        table.add_row(label, str(count))

    console.print(table)

    if args.llm_fallback:
        if llm_client is not None:
            console.print("[green]OpenAI LLM fallback enabled[/green]")
        else:
            console.print("[yellow]Heuristic fallback used instead of LLM[/yellow]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
