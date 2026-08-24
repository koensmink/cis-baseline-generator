from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from ...catalog import SECURITY_KNOWLEDGE_CATALOG
from ..schema import ThreatSourceType
from .contract import (
    DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT,
    build_document_id,
    content_hash,
)
from .provenance import AdvisoryDocumentProvenance
from .provider_exporters import ProviderInterpretationSummary, write_provider_artifacts
from .providers import (
    AIProviderError,
    OpenAIProviderConfig,
    OpenAIThreatInterpretationProvider,
)
from .schema import AdvisoryContentFormat, ThreatAdvisoryDocument

console = Console()

_SOURCE_ALIASES = {
    "vendor_advisory": ThreatSourceType.VENDOR,
    "government_advisory": ThreatSourceType.GOVERNMENT,
}


def _aware_datetime(value: str, option: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {option}: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{option} must include a timezone offset")
    return parsed


def _source_type(value: str) -> ThreatSourceType:
    try:
        if value in _SOURCE_ALIASES:
            return _SOURCE_ALIASES[value]
        return ThreatSourceType(value)
    except ValueError as exc:
        raise ValueError(f"unsupported --source-type: {value}") from exc


def _provider(config: OpenAIProviderConfig) -> OpenAIThreatInterpretationProvider:
    return OpenAIThreatInterpretationProvider(config)


def _print_summary(summary: ProviderInterpretationSummary, output: Path) -> None:
    table = Table(title="cis-threat-interpret summary")
    table.add_column("Metric")
    table.add_column("Value")
    for label, value in (
        ("Provider", summary.provider),
        ("Model", summary.model),
        ("Contract", f"{summary.contract_id} v{summary.contract_version}"),
        ("Validation", summary.validation),
        ("Confidence", summary.confidence),
        ("Severity", summary.severity),
        ("Activity state", summary.activity_state),
        ("Technique proposals", summary.technique_proposals),
        ("Attack-path proposals", summary.attack_path_proposals),
        ("Blocking findings", summary.blocking_findings),
        ("Review findings", summary.review_findings),
    ):
        table.add_row(label, str(value))
    console.print(table)
    console.print(f"Output:\n  {output}")
    console.print(f"Summary:\n  {output.with_name(f'{output.stem}-summary.json')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis-threat-interpret",
        description="Create an untrusted structured threat proposal from a local advisory",
    )
    parser.add_argument("advisory", help="Local advisory text file; URLs are not accepted")
    parser.add_argument("--source-type", required=True)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--source-reference", required=True)
    parser.add_argument("--provider", choices=("openai",), default="openai")
    parser.add_argument("--model", required=True)
    parser.add_argument("--generated-at", required=True, help="Timezone-aware generation instant")
    parser.add_argument("--published-at")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--max-output-tokens", type=int, default=8_000)
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args(argv)

    advisory_path = Path(args.advisory)
    output = Path(args.output)
    if "://" in args.advisory:
        parser.error("URL inputs are not supported")
    if not advisory_path.is_file():
        parser.error(f"advisory file not found: {advisory_path}")
    if output.suffix.lower() != ".json":
        parser.error("output must use a .json suffix")
    if not output.parent.is_dir():
        parser.error(f"output directory does not exist: {output.parent}")
    try:
        generated_at = _aware_datetime(args.generated_at, "--generated-at")
        published_at = _aware_datetime(args.published_at, "--published-at") if args.published_at else None
        source_type = _source_type(args.source_type)
        content = advisory_path.read_text(encoding="utf-8")
        digest = content_hash(content)
        document = ThreatAdvisoryDocument(
            document_id=build_document_id(args.source_name, f"{args.source_reference}:{digest}"),
            source_type=source_type,
            source_name=args.source_name,
            source_reference=args.source_reference,
            published_at=published_at,
            retrieved_at=generated_at,
            content_hash=digest,
            title=advisory_path.stem,
            content=content,
            content_format=AdvisoryContentFormat.PLAIN_TEXT,
            provenance=AdvisoryDocumentProvenance(
                supplied_by="cis-threat-interpret", collection_method="local_file"
            ),
        )
        config = OpenAIProviderConfig(
            model=args.model,
            generated_at=generated_at,
            timeout_seconds=args.timeout_seconds,
            max_retries=args.max_retries,
            max_output_tokens=args.max_output_tokens,
        )
        provider = _provider(config)
        result = provider.interpret(
            document,
            DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT,
            SECURITY_KNOWLEDGE_CATALOG,
        )
        summary = write_provider_artifacts(result, output)
    except (OSError, UnicodeError, ValueError, ValidationError) as exc:
        parser.error(str(exc))
    except AIProviderError as exc:
        console.print(f"[red]{exc}[/red]")
        return exc.exit_code
    _print_summary(summary, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
