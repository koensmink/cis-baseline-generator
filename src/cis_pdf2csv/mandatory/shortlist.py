from __future__ import annotations

from cis_pdf2csv.schema import ControlRecord

from .comparison import ComparisonResult
from .criteria import criterion_label
from .features import ControlFeatures
from .schema import Confidence, MandatoryAssessment, Proposal

BLOCKING_RELATIONSHIPS = {
    "supporting control",
    "fine-tuning control",
    "detection-only control",
    "duplicate or overlapping control",
}


def build_assessment(
    control: ControlRecord,
    features: ControlFeatures,
    comparison: ComparisonResult,
    family: str,
    criteria: list[str],
) -> MandatoryAssessment:
    exclusions = list(features.exclusion_reasons)
    if comparison.relationship == "fine-tuning control" and not any(item.startswith("EXCL-003") for item in exclusions):
        exclusions.append("EXCL-003 fine-tuning of a primary control")
    if comparison.relationship in {"supporting control", "detection-only control"}:
        exclusions.append(f"EXCL-008 {comparison.relationship} is not the primary preventive boundary")
    if comparison.relationship == "duplicate or overlapping control":
        exclusions.append("EXCL-009 duplicate or overlapping control requires analyst selection")

    evidence_fields = {item.field for item in features.evidence}
    high = features.eligible and {"rationale", "audit", "remediation"}.issubset(evidence_fields) and not comparison.ambiguous
    confidence: Confidence = "High" if high else "Medium" if features.evidence else "Low"
    non_compensable = None
    if criteria and not any(item.startswith("EXCL-005") for item in exclusions):
        labels = ", ".join(criterion_label(code) for code in criteria)
        non_compensable = (
            f"The recommendation '{control.title}' directly enforces {labels}; "
            "omitting this technology-specific boundary leaves the named mechanism unprotected."
        )

    blocking = bool(exclusions) or comparison.relationship in BLOCKING_RELATIONSHIPS
    candidate = features.eligible and bool(criteria) and not blocking and bool(non_compensable) and confidence == "High"
    if candidate:
        proposal: Proposal = "Candidate Mandatory"
        review_note = "Human approval is required before any Definitive Mandatory designation."
    elif not features.eligible or comparison.ambiguous or comparison.relationship == "duplicate or overlapping control":
        proposal = "Review Required"
        review_note = "; ".join(features.eligibility_failures) or "Related-control comparison is ambiguous."
    else:
        proposal = "Regular Control"
        review_note = None

    matched = ", ".join(criterion_label(code) for code in criteria) or "no explicit Mandatory criterion"
    rationale = (
        f"Control {control.control_id}, '{control.title}', addresses {matched}. "
        f"It is assessed as a {comparison.relationship} using its title, rationale, audit, remediation, applicability and benchmark hierarchy."
    )
    return MandatoryAssessment(
        control_id=control.control_id,
        proposal=proposal,
        control_family=family,
        mandatory_criteria=criteria,
        exclusion_reasons=exclusions,
        non_compensable_reason=non_compensable,
        benchmark_evidence=list(features.evidence),
        related_control_ids=list(comparison.related_control_ids),
        relationship=comparison.relationship,
        rationale=rationale,
        confidence=confidence,
        review_note=review_note,
    )
