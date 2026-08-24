from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from ...catalog import SECURITY_KNOWLEDGE_CATALOG
from .approval import material_assertion_ids
from .approval_exporters import ThreatApprovalSummary, write_approval_artifacts
from .approval_workflow import (
    ApprovalBlockedError,
    ProposedInterpretationArtifact,
    review_proposed_interpretation,
)
from .schema import (
    ApprovalModification,
    ApprovalStatus,
    ProposedThreatInterpretation,
)

console = Console()


def _aware_datetime(value: str, option: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {option}: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{option} must include a timezone offset")
    return parsed


def _load_artifact(path: Path) -> ProposedInterpretationArtifact:
    try:
        return ProposedInterpretationArtifact.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValidationError, ValueError) as exc:
        raise ValueError(f"invalid proposed interpretation artifact {path}: {exc}") from exc


def _modifications(args: argparse.Namespace) -> tuple[ApprovalModification, ...]:
    values = (
        ("proposed_confidence", args.set_confidence),
        ("proposed_severity", args.set_severity),
        ("valid_from", args.set_valid_from),
        ("valid_until", args.set_valid_until),
        ("proposed_applicability_scope", args.set_applicability_scope),
    )
    return tuple(
        ApprovalModification(
            field_name=field,
            value=value,
            rationale=args.rationale,
        )
        for field, value in values
        if value is not None
    )


def _list_assertions(item: ProposedThreatInterpretation) -> None:
    material = material_assertion_ids(item)
    table = Table(title="cis-threat-approve assertions")
    for column in ("Assertion", "Type", "Value", "Support", "Confidence", "Explicit", "Material"):
        table.add_column(column)
    for assertion in sorted(item.evidence_assertions, key=lambda value: value.assertion_id):
        table.add_row(
            assertion.assertion_id,
            assertion.assertion_type,
            assertion.value,
            assertion.support_type.value,
            assertion.confidence.value,
            "yes" if assertion.explicitly_stated else "no",
            "yes" if assertion.assertion_id in material else "no",
        )
    console.print(table)


def _print_summary(
    summary: ThreatApprovalSummary,
    output: Path,
    approval_path: Path,
) -> None:
    table = Table(title="cis-threat-approve summary")
    table.add_column("Metric")
    table.add_column("Value")
    for label, value in (
        ("Interpretation", summary.interpretation_id),
        ("Revision", summary.interpretation_revision),
        ("Decision", summary.decision),
        ("Reviewer", summary.reviewer),
        ("Accepted assertions", summary.accepted_assertions),
        ("Rejected assertions", summary.rejected_assertions),
        ("Modifications", summary.modifications),
        ("ThreatContext created", "yes" if summary.threat_context_created else "no"),
        ("Blocking findings", summary.blocking_findings),
    ):
        table.add_row(label, str(value))
    console.print(table)
    if summary.threat_context_created:
        console.print(f"ThreatContext:\n  {output}")
    console.print(f"Approval record:\n  {approval_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis-threat-approve",
        description="Record explicit human review and optionally create a ThreatContext",
    )
    parser.add_argument("proposal", help="cis-threat-interpret JSON artifact")
    parser.add_argument("--list-assertions", action="store_true")
    parser.add_argument("--reviewer")
    parser.add_argument(
        "--approval",
        choices=("approved", "rejected", "needs_revision"),
        help="Explicit human decision; never defaults to approved",
    )
    parser.add_argument("--reviewed-at", help="Timezone-aware ISO-8601; defaults to current UTC")
    parser.add_argument("--accept", action="append", default=[], metavar="ASSERTION_ID")
    parser.add_argument("--reject", action="append", default=[], metavar="ASSERTION_ID")
    parser.add_argument("--rationale")
    parser.add_argument("--set-confidence", choices=("High", "Medium", "Low"))
    parser.add_argument("--set-severity", choices=("Low", "Medium", "High", "Critical"))
    parser.add_argument("--set-valid-from")
    parser.add_argument("--set-valid-until")
    parser.add_argument(
        "--set-applicability-scope",
        choices=(
            "global", "technology_family", "product_family", "deployment_specific",
            "sector_specific", "environment_specific", "unresolved",
        ),
    )
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)

    proposal_path = Path(args.proposal)
    if not proposal_path.is_file():
        parser.error(f"proposal file not found: {proposal_path}")
    try:
        artifact = _load_artifact(proposal_path)
    except ValueError as exc:
        parser.error(str(exc))
    if args.list_assertions:
        _list_assertions(artifact.interpretation)
        return 0
    if args.approval is None:
        parser.error("--approval is required unless --list-assertions is used")
    if not args.reviewer:
        parser.error("--reviewer is required")
    if not args.rationale:
        parser.error("--rationale is required")
    if not args.output:
        parser.error("--output is required")
    output = Path(args.output)
    if output.suffix.lower() != ".json":
        parser.error("output must use a .json suffix")
    if not output.parent.is_dir():
        parser.error(f"output directory does not exist: {output.parent}")
    try:
        reviewed_at = (
            _aware_datetime(args.reviewed_at, "--reviewed-at")
            if args.reviewed_at
            else datetime.now(timezone.utc)
        )
        modifications = _modifications(args)
        result = review_proposed_interpretation(
            artifact,
            reviewer=args.reviewer,
            reviewed_at=reviewed_at,
            status=ApprovalStatus(args.approval),
            accepted_assertion_ids=tuple(args.accept),
            rejected_assertion_ids=tuple(args.reject),
            modifications=modifications,
            rationale=args.rationale,
            catalog=SECURITY_KNOWLEDGE_CATALOG,
        )
        approval_path, _, summary = write_approval_artifacts(artifact, result, output)
    except ApprovalBlockedError as exc:
        console.print(f"[red]{exc.code}: {exc}[/red]")
        return 4
    except (OSError, ValueError, ValidationError) as exc:
        parser.error(str(exc))
    _print_summary(summary, output, approval_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
