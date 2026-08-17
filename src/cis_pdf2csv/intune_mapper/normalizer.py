from __future__ import annotations

from cis_pdf2csv.parser import detect_benchmark_identity
from cis_pdf2csv.source_identity import SourceIdentity

from .models import MappingInputControl, NormalizedControl
from .value_parser import parse_recommendation


def _benchmark_family(control: MappingInputControl) -> str:
    if control.benchmark_family not in {"", "unknown"}:
        return control.benchmark_family

    detected = detect_benchmark_identity([control.benchmark_name])
    if detected.family != "unknown":
        return detected.family

    name = control.benchmark_name.casefold()
    applicability = (control.applicability or "").casefold()
    if "microsoft 365" in name or "e3 level" in applicability or "e5 level" in applicability:
        return "microsoft-365-foundations"
    if "windows server" in name:
        return "microsoft-windows-server"
    return "unknown"


def normalize_control(control: MappingInputControl) -> NormalizedControl:
    parsed = parse_recommendation(control.recommendation or control.default_value)

    normalized_title = " ".join(control.title.split()).strip()
    profile = (control.profile or "Unknown").strip()
    family = _benchmark_family(control)
    target = (
        "windows_server_2025"
        if family == "microsoft-windows-server"
        else None
    )
    identity = SourceIdentity(
        source_framework=control.source_framework,
        benchmark_family=family,
        benchmark_name=control.benchmark_name,
        benchmark_version=control.benchmark_version,
        benchmark_profile=profile,
        control_id=control.control_id,
    )

    flags = list(parsed.quality_flags)
    if profile.lower() == "unknown":
        flags.append("missing_profile")

    return NormalizedControl(
        control_id=control.control_id,
        source_framework=control.source_framework,
        benchmark_family=family,
        benchmark_name=control.benchmark_name,
        benchmark_version=control.benchmark_version,
        title=normalized_title,
        source_identity=identity,
        target=target,
        profile=profile,
        assessment=control.assessment,
        applicability=control.applicability,
        recommendation=control.recommendation,
        parsed_recommendation=parsed,
        description=control.description,
        rationale=control.rationale,
        impact=control.impact,
        audit=control.audit,
        remediation=control.remediation,
        default_value=control.default_value,
        references=control.references,
        quality_flags=flags,
    )
