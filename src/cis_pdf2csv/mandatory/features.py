from __future__ import annotations

import re
from dataclasses import dataclass

from cis_pdf2csv.schema import ControlRecord

from .schema import BenchmarkEvidence

AMBIGUITY_MARKERS = ("where applicable", "if applicable", "as appropriate", "organization-defined", "depends on", "when required")
ADDITIVE_MARKERS = ("additional", "defense in depth", "supplemental", "supplementary", "enhance")
UX_MARKERS = ("user experience", "display", "hide", "information disclosure", "show last", "notification")
FINE_TUNING_MARKERS = ("timeout", "log size", "retention period", "threshold", "frequency", "number of", "duration", "fine-tun")
IMPLEMENTATION_MARKERS = ("implementation dependent", "environment dependent", "business requirement", "organization-specific")
COMPENSABLE_MARKERS = ("compensating control", "alternative control", "equivalent protection", "can be compensated")
SECURITY_SUBJECT_TERMS = frozenset(
    {
        "access", "account", "administrator", "antivirus", "application",
        "audit", "authentication", "boundary", "credential", "defender",
        "elevation", "encryption", "execution", "extension", "firewall",
        "isolation", "logging", "logon", "macro", "malware", "network",
        "password", "privilege", "protocol", "remote", "sandbox", "script",
        "security", "signing", "smb", "transport", "tls", "winrm",
    }
)


@dataclass(frozen=True)
class ControlFeatures:
    criterion_text: str
    supporting_evidence_text: str
    evidence: tuple[BenchmarkEvidence, ...]
    eligible: bool
    eligibility_failures: tuple[str, ...]
    exclusion_reasons: tuple[str, ...]
    subjects: frozenset[str]


def _excerpt(value: str, limit: int = 240) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


def _has_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _strip_urls(text: str) -> str:
    return re.sub(r"\b(?:https?|ftp)://\S+", " ", text, flags=re.IGNORECASE)


def _subjects(text: str) -> frozenset[str]:
    words = set(re.findall(r"[a-z0-9]+", text.lower()))
    return frozenset(words & SECURITY_SUBJECT_TERMS)


def extract_features(control: ControlRecord) -> ControlFeatures:
    fields = ("title", "description", "rationale", "impact", "audit", "remediation", "default_value", "applicability", "references")
    values = {name: (getattr(control, name) or "").strip() for name in fields}
    criterion_fields = ("title", "description", "rationale", "impact", "remediation", "default_value")
    criterion_text = " ".join(
        _strip_urls(values[name]) for name in criterion_fields if values[name]
    ).lower()
    supporting_evidence_text = " ".join(
        value for value in (criterion_text, values["audit"], values["references"]) if value
    ).lower()
    pages = f"{control.page_start}-{control.page_end}"
    evidence = tuple(
        BenchmarkEvidence(field=name, excerpt=_excerpt(value), pages=pages)
        for name, value in values.items()
        if value and name in {"title", "description", "rationale", "impact", "audit", "remediation", "applicability"}
    )

    failures: list[str] = []
    if not control.control_id.strip():
        failures.append("ELIG-001 missing control ID")
    if not control.title.strip():
        failures.append("ELIG-002 missing title")
    if not control.profile.strip() or control.profile.lower() == "unknown":
        failures.append("ELIG-003 unknown profile")
    individually_testable = control.assessment.lower() == "automated" or bool(values["audit"] and values["remediation"])
    if not individually_testable:
        failures.append("ELIG-004 recommendation is not individually testable")
    sufficient = bool(values["rationale"] and values["audit"] and values["remediation"])
    if not sufficient:
        failures.append("ELIG-005 insufficient benchmark evidence")
    ambiguous = _has_any(" ".join((values["applicability"], values["rationale"])).lower(), AMBIGUITY_MARKERS)
    if ambiguous:
        failures.append("ELIG-006 materially ambiguous applicability")

    exclusions: list[str] = []
    for code, markers in (
        ("EXCL-001 additive or defense-in-depth effect", ADDITIVE_MARKERS),
        ("EXCL-002 user experience or information hiding", UX_MARKERS),
        ("EXCL-003 fine-tuning of a primary control", FINE_TUNING_MARKERS),
        ("EXCL-004 strongly implementation-dependent", IMPLEMENTATION_MARKERS),
        ("EXCL-005 reasonably compensable", COMPENSABLE_MARKERS),
    ):
        if _has_any(criterion_text, markers):
            exclusions.append(code)
    if not sufficient:
        exclusions.append("EXCL-006 insufficient benchmark evidence")
    if ambiguous:
        exclusions.append("EXCL-007 ambiguous applicability")

    return ControlFeatures(
        criterion_text=criterion_text,
        supporting_evidence_text=supporting_evidence_text,
        evidence=evidence,
        eligible=not failures,
        eligibility_failures=tuple(failures),
        exclusion_reasons=tuple(exclusions),
        subjects=_subjects(criterion_text),
    )
