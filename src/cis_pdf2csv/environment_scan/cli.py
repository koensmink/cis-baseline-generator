from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from .gpo import GpoParseError, gpo_report_paths, parse_gpo_reports
from .intune import UrllibGraphTransport, collect_graph_bundle, normalize_intune_bundle
from .models import EnvironmentSource, ObservedPolicy
from .service import build_snapshot, sha256_files

console = Console()


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read Intune export {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TypeError(f"Intune export must contain a JSON object: {path}")
    return value


def _intune_snapshot(args: argparse.Namespace):
    input_path = Path(args.input) if args.input else None
    if input_path:
        if not input_path.is_file():
            raise ValueError(f"Intune export not found: {input_path}")
        bundle = _load_json_object(input_path)
        input_sha256 = sha256_files((input_path,))
        source_reference = str(input_path)
    else:
        token = os.getenv(args.access_token_env)
        if not token:
            raise ValueError(
                f"Intune live scan requires {args.access_token_env}; "
                "set it locally or supply --input with an exported Graph bundle"
            )
        transport = UrllibGraphTransport(token, timeout_seconds=args.timeout_seconds)
        bundle = collect_graph_bundle(transport, base_url=args.graph_base_url)
        input_sha256 = None
        source_reference = args.graph_base_url
    policies, assets, errors = normalize_intune_bundle(bundle)
    return build_snapshot(
        source=EnvironmentSource.INTUNE,
        policies=policies,
        assets=assets,
        errors=errors,
        input_sha256=input_sha256,
        tenant_id=args.tenant_id,
        source_reference=source_reference,
    )


def _gpo_snapshot(args: argparse.Namespace):
    if not args.input:
        raise ValueError("GPO scan requires --input with a GPO XML report or directory")
    paths = gpo_report_paths(Path(args.input))
    policies: list[ObservedPolicy] = []
    errors: list[str] = []
    for path in paths:
        try:
            policies.extend(parse_gpo_reports(path))
        except GpoParseError as exc:
            errors.append(str(exc))
    if not policies:
        raise ValueError("No valid GPO reports could be parsed")
    return build_snapshot(
        source=EnvironmentSource.GPO,
        policies=tuple(policies),
        errors=tuple(errors),
        input_sha256=sha256_files(paths),
        source_reference=str(Path(args.input)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis-environment-scan",
        description="Inventory declared Intune or GPO configuration for CIS gap analysis",
    )
    parser.add_argument("--source", required=True, choices=("intune", "gpo"))
    parser.add_argument(
        "--input",
        help="Offline Intune Graph bundle, GPO XML report, or GPO report directory",
    )
    parser.add_argument(
        "-o", "--output", required=True, help="Current-state JSON output"
    )
    parser.add_argument(
        "--access-token-env",
        default="MS_GRAPH_ACCESS_TOKEN",
        help="Environment variable containing the Graph token for an Intune live scan",
    )
    parser.add_argument(
        "--graph-base-url",
        default="https://graph.microsoft.com",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--tenant-id", help="Optional tenant identifier recorded as provenance"
    )
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")

    try:
        snapshot = (
            _intune_snapshot(args) if args.source == "intune" else _gpo_snapshot(args)
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(snapshot.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except (OSError, TypeError, ValueError, ValidationError) as exc:
        parser.error(str(exc))

    table = Table(title="cis-environment-scan summary")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    for label, count in (
        ("Policies", snapshot.policy_count),
        ("Settings", snapshot.setting_count),
        ("Assets", snapshot.asset_count),
        ("Potential conflicts", len(snapshot.potential_conflicts)),
        ("Collection errors", len(snapshot.collection_errors)),
    ):
        table.add_row(label, str(count))
    console.print(table)
    console.print(f"Current state:\n  {output}")
    return 2 if snapshot.collection_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
