from __future__ import annotations

import argparse
import csv
import importlib
import inspect
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from .parser import UnsupportedBenchmarkIdentityError, parse_controls
from .schema import ControlRecord

console = Console()


def _clean_csv_value(v):
    """
    Normalize values so multiline text (Audit/Remediation/etc.)
    does not break CSV rows in terminal/Excel.
    """
    if v is None:
        return ""

    if not isinstance(v, str):
        return v

    # normalize line endings
    v = v.replace("\r\n", "\n").replace("\r", "\n")

    # convert newlines to visible tokens inside the cell
    v = v.replace("\n", "\\n")

    # collapse weird whitespace
    v = re.sub(r"[ \t]+", " ", v)

    return v.strip()


def _write_csv(records: list[ControlRecord], out_path: Path) -> None:
    fieldnames = list(ControlRecord.model_fields.keys())
    with out_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        for r in records:
            row = r.model_dump()
            row = {k: _clean_csv_value(v) for k, v in row.items()}
            writer.writerow(row)


def _write_jsonl(records: list[ControlRecord], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r.model_dump(), ensure_ascii=False) + "\n")


def _all_have_suffix(paths: list[str], suffix: str) -> bool:
    return all(Path(p).suffix.lower() == suffix.lower() for p in paths)


def _resolve_intune_mapper() -> tuple[str, Callable[..., Any]] | None:
    """
    Try to resolve an existing intune mapper entrypoint dynamically.

    Supported modules:
    - cis_pdf2csv.intune_mapper.mapper
    - cis_pdf2csv.intune_mapper.cli

    Supported function names:
    - generate_intune_baseline
    - generate_baseline
    - map_controls
    - run
    - main
    """
    module_candidates = [
        ".intune_mapper.mapper",
        ".intune_mapper.cli",
    ]
    function_candidates = [
        "generate_intune_baseline",
        "generate_baseline",
        "map_controls",
        "run",
        "main",
    ]

    for module_name in module_candidates:
        try:
            module = importlib.import_module(module_name, package=__package__)
        except ImportError:
            continue

        for fn_name in function_candidates:
            fn = getattr(module, fn_name, None)
            if callable(fn):
                return fn_name, fn

    return None


def _invoke_mapper_function(
    fn_name: str,
    fn: Callable[..., Any],
    input_path: Path,
    output_path: Path,
    llm_fallback: bool,
) -> int:
    """
    Invoke resolved mapper function with a best-effort signature match.
    """
    # Special case: argparse-style main(argv)
    if fn_name == "main":
        argv = [str(input_path), "-o", str(output_path)]
        if llm_fallback:
            argv.append("--llm-fallback")
        result = fn(argv)
        return int(result) if isinstance(result, int) else 0

    sig = inspect.signature(fn)
    kwargs: dict[str, Any] = {}

    arg_aliases = {
        "input_path": input_path,
        "controls_path": input_path,
        "jsonl_path": input_path,
        "source_path": input_path,
        "in_path": input_path,
        "output_path": output_path,
        "out_path": output_path,
        "output_dir": output_path,
        "destination": output_path,
        "llm_fallback": llm_fallback,
        "use_llm_fallback": llm_fallback,
    }

    for param_name in sig.parameters:
        if param_name in arg_aliases:
            kwargs[param_name] = arg_aliases[param_name]

    result = fn(**kwargs)
    return int(result) if isinstance(result, int) else 0


def _run_intune_mapper(input_path: Path, output_path: Path, llm_fallback: bool) -> int:
    resolved = _resolve_intune_mapper()
    if not resolved:
        console.print(
            "[red]No intune mapper entrypoint could be resolved.[/red]\n"
            "Expected one of:\n"
            "- cis_pdf2csv.intune_mapper.mapper.generate_intune_baseline\n"
            "- cis_pdf2csv.intune_mapper.mapper.generate_baseline\n"
            "- cis_pdf2csv.intune_mapper.mapper.map_controls\n"
            "- cis_pdf2csv.intune_mapper.mapper.run\n"
            "- cis_pdf2csv.intune_mapper.cli.main"
        )
        return 2

    fn_name, fn = resolved

    console.print(
        f"[cyan]Detected JSONL input[/cyan] → invoking [bold]{fn.__module__}.{fn_name}[/bold]"
    )

    try:
        return _invoke_mapper_function(
            fn_name=fn_name,
            fn=fn,
            input_path=input_path,
            output_path=output_path,
            llm_fallback=llm_fallback,
        )
    except TypeError as e:
        console.print(
            f"[red]Resolved mapper entrypoint could not be called with the expected arguments:[/red] {e}"
        )
        return 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="cis-pdf2csv",
        description="Parse CIS Benchmark PDF(s) into CSV/JSONL or pass JSONL into an intune mapper",
    )
    p.add_argument(
        "pdfs",
        nargs="+",
        help="Input file(s): CIS Benchmark PDF(s) for parsing, or a JSONL file for intune mapping.",
    )
    p.add_argument(
        "-p",
        "--profile",
        default=None,
        help="Filter: L1, L2, or NG (default: all)",
    )
    p.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output file path (csv or jsonl), or output path/directory for intune mapping.",
    )
    p.add_argument(
        "--format",
        choices=["csv", "jsonl"],
        default=None,
        help="Force output format (default: based on extension)",
    )
    p.add_argument(
        "--llm-fallback",
        action="store_true",
        help="Enable LLM fallback for unmapped controls when JSONL is passed into the intune mapper.",
    )

    args = p.parse_args(argv)

    out_path = Path(args.output)
    input_paths = [Path(value) for value in args.pdfs]
    missing = [str(path) for path in input_paths if not path.is_file()]
    if missing:
        console.print(f"[red]Input file not found:[/red] {missing[0]}")
        return 2
    if not out_path.parent.exists():
        console.print(f"[red]Output directory does not exist:[/red] {out_path.parent}")
        return 2

    # Mode 1: JSONL -> intune mapper
    if len(args.pdfs) == 1 and Path(args.pdfs[0]).suffix.lower() == ".jsonl":
        return _run_intune_mapper(
            input_path=Path(args.pdfs[0]),
            output_path=out_path,
            llm_fallback=args.llm_fallback,
        )

    # Mode 2: PDF(s) -> structured export
    if not _all_have_suffix(args.pdfs, ".pdf"):
        console.print(
            "[red]Unsupported input mix.[/red] Use either:\n"
            "- one or more PDF files for parsing, or\n"
            "- one JSONL file for intune mapping."
        )
        return 2

    out_fmt = args.format or (out_path.suffix.lower().lstrip(".") if out_path.suffix else "csv")
    if out_fmt not in ("csv", "jsonl"):
        console.print(f"[red]Unsupported output format[/red]: {out_fmt}")
        return 2

    all_records: list[ControlRecord] = []
    try:
        for pdf in args.pdfs:
            controls = parse_controls(pdf, profile_filter=args.profile)
            for c in controls:
                all_records.append(ControlRecord(**c))
    except UnsupportedBenchmarkIdentityError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    # Deterministic order: by benchmark then control_id
    all_records.sort(key=lambda r: (r.benchmark_name, r.benchmark_version, r.control_id))

    if out_fmt == "csv":
        _write_csv(all_records, out_path)
    else:
        _write_jsonl(all_records, out_path)

    # Pretty summary
    t = Table(title="cis-pdf2csv summary")
    t.add_column("Benchmarks", justify="right")
    t.add_column("Controls", justify="right")
    t.add_column("Profile", justify="left")
    t.add_row(
        str(len({(r.benchmark_name, r.benchmark_version) for r in all_records})),
        str(len(all_records)),
        str(args.profile or "ALL"),
    )
    console.print(t)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
