from __future__ import annotations

from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.source_identity import source_identity_for_control

from .boundary_sets import BoundaryContext, applicability_mode
from .comparison import ComparisonResult
from .criteria import criterion_label
from .features import ControlFeatures
from .schema import Confidence, MandatoryAssessment, Proposal

BLOCKING_RELATIONSHIPS = {
    "supporting hardening",
    "fine-tuning",
    "detection-only",
    "information-hiding",
    "operational",
}
ELIGIBLE_BOUNDARY_RELATIONSHIPS = {
    "standalone primary boundary",
    "boundary-set core member",
    "prerequisite",
}

BOUNDARY_RISKS: dict[str, tuple[str, str, str]] = {
    "MC-CRIT-001": ("removal of an explicitly unsafe or legacy mechanism", "an attacker can continue using the deprecated mechanism", "a parallel hardening setting cannot remove acceptance of that mechanism"),
    "MC-CRIT-002": ("the identity-verification boundary", "an unauthenticated or weakly authenticated identity can cross the access boundary", "authorization and monitoring cannot replace authentication at entry"),
    "MC-CRIT-003": ("the privileged-access boundary", "administrative authority remains reachable without the required protection", "downstream controls cannot remove an unprotected privileged path"),
    "MC-CRIT-004": ("the credential-material boundary", "reusable credentials or credential derivatives remain exposed", "another policy cannot retroactively protect credentials stored or delegated here"),
    "MC-CRIT-005": ("the elevated-execution boundary", "code can obtain elevated execution without the required mediation", "malware scanning cannot substitute for elevation enforcement"),
    "MC-CRIT-006": ("the remote-access boundary", "a remote principal, credential, or redirected resource can cross the host boundary", "local controls cannot close the remote path governed by this setting"),
    "MC-CRIT-007": ("the direct code-execution boundary", "untrusted code, scripts, macros, or extensions can execute", "detection after execution cannot substitute for preventing the execution path"),
    "MC-CRIT-008": ("the network-prevention boundary", "malicious network traffic can reach the protected host or service", "host hardening cannot compensate for an open network path"),
    "MC-CRIT-009": ("the firewall enforcement boundary", "traffic prohibited by policy can still enter or leave", "logging or service hardening cannot enforce the missing packet boundary"),
    "MC-CRIT-010": ("the protected-transport boundary", "a peer can negotiate an unprotected or weak transport", "endpoint controls cannot protect data exposed in transit"),
    "MC-CRIT-011": ("the authenticity and integrity boundary", "unsigned or tampered content can be accepted", "encryption or logging cannot prove origin and integrity"),
    "MC-CRIT-012": ("the cryptographic confidentiality boundary", "plaintext credentials or data remain readable in transit or storage", "access controls cannot compensate once plaintext is exposed"),
    "MC-CRIT-013": ("the isolation boundary", "untrusted activity can interact directly with the host", "monitoring cannot recreate a missing containment boundary"),
    "MC-CRIT-014": ("the application allow/deny boundary", "unapproved applications can execute", "antivirus alone cannot enforce the approved application set"),
    "MC-CRIT-015": ("the essential investigation evidence boundary", "the high-impact event cannot be reliably detected or reconstructed", "no alternative configured source records the required event evidence"),
    "MC-CRIT-016": ("the active malware-prevention boundary", "malicious behavior can execute without real-time blocking", "scheduled scanning or notifications cannot replace active prevention"),
}


def _non_compensable_reason(
    control: ControlRecord,
    criteria: list[str],
    relationship: str,
    boundary_context: BoundaryContext,
) -> str | None:
    if not criteria or relationship not in ELIGIBLE_BOUNDARY_RELATIONSHIPS:
        return None
    membership = boundary_context.membership
    if membership and not membership.standalone:
        return (
            f"'{control.title}' enforces {membership.enforced_sub_boundary} within "
            f"{membership.definition.boundary_set_name}. If omitted, {membership.attack_path_if_omitted}. "
            "The remaining core members enforce different sub-boundaries and cannot compensate for "
            f"the missing {membership.effect} effect; the minimum effective boundary set is incomplete."
        )
    boundary, attack_path, compensation = BOUNDARY_RISKS[criteria[0]]
    role = "a required prerequisite for" if relationship == "prerequisite" else "the primary control enforcing"
    return (
        f"'{control.title}' is {role} {boundary}. If omitted, {attack_path}. "
        f"It is non-compensable at this decision point because {compensation}; "
        "supporting hardening may reduce likelihood but does not close this attack path."
    )


def build_assessment(
    control: ControlRecord,
    features: ControlFeatures,
    comparison: ComparisonResult,
    boundary_context: BoundaryContext,
    family: str,
    criteria: list[str],
) -> MandatoryAssessment:
    exclusions = list(features.exclusion_reasons)
    if (
        boundary_context.membership
        and not boundary_context.membership.standalone
        and boundary_context.complete
    ):
        # A recognized core effect is necessary to complete its boundary. Generic
        # benchmark wording such as "additional protection" does not turn it into
        # optional defense in depth.
        exclusions = [item for item in exclusions if not item.startswith("EXCL-001")]
    if comparison.relationship == "fine-tuning" and not any(item.startswith("EXCL-003") for item in exclusions):
        exclusions.append("EXCL-003 fine-tuning of a primary control")
    if comparison.relationship in {
        "supporting hardening",
        "detection-only",
        "information-hiding",
        "operational",
    }:
        exclusions.append(f"EXCL-008 {comparison.relationship} is not the primary preventive boundary")
    if boundary_context.overlap_type in {"duplicate", "alternative"}:
        exclusions.append(f"EXCL-009 {boundary_context.overlap_type} boundary implementation requires analyst selection")

    mode = applicability_mode(control, boundary_context.membership)

    evidence_fields = {item.field for item in features.evidence}
    high = features.eligible and {"rationale", "audit", "remediation"}.issubset(evidence_fields) and not comparison.ambiguous
    confidence: Confidence = "High" if high else "Medium" if features.evidence else "Low"
    non_compensable = None
    if not any(item.startswith("EXCL-005") for item in exclusions):
        non_compensable = _non_compensable_reason(
            control,
            criteria,
            comparison.relationship,
            boundary_context,
        )

    blocking = bool(exclusions) or comparison.relationship in BLOCKING_RELATIONSHIPS
    incomplete_set = (
        comparison.relationship == "boundary-set core member"
        and not boundary_context.complete
    )
    confidence_allowed = confidence == "High" or (
        confidence == "Medium" and mode == "mandatory_when_deployed"
    )
    candidate = (
        features.eligible
        and bool(criteria)
        and comparison.relationship in ELIGIBLE_BOUNDARY_RELATIONSHIPS
        and mode != "unresolved"
        and not incomplete_set
        and not blocking
        and bool(non_compensable)
        and confidence_allowed
    )
    if candidate:
        proposal: Proposal = "Candidate Mandatory"
        review_note = "Human approval is required before any Definitive Mandatory designation."
    elif (
        not features.eligible
        or comparison.ambiguous
        or mode == "unresolved"
        or incomplete_set
        or boundary_context.overlap_type in {"duplicate", "alternative"}
    ):
        proposal = "Review Required"
        if incomplete_set and boundary_context.membership:
            review_note = f"Boundary set is incomplete; required complementary effects need review: {', '.join(boundary_context.missing_required_effects)}."
        elif mode == "unresolved":
            review_note = "Technology deployment applicability is unresolved."
        else:
            review_note = "; ".join(features.eligibility_failures) or "Related-control overlap requires analyst selection."
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
        source_identity=source_identity_for_control(control),
        title=control.title,
        proposal=proposal,
        control_family=family,
        mandatory_criteria=criteria,
        exclusion_reasons=exclusions,
        non_compensable_reason=non_compensable,
        benchmark_evidence=list(features.evidence),
        related_control_ids=list(comparison.related_control_ids),
        relationship=comparison.relationship,
        applicability_mode=mode,
        overlap_type=boundary_context.overlap_type,
        boundary_set_id=boundary_context.membership.definition.boundary_set_id if boundary_context.membership else None,
        boundary_set_name=boundary_context.membership.definition.boundary_set_name if boundary_context.membership else None,
        boundary_set_role=("standalone" if boundary_context.membership and boundary_context.membership.standalone else "core member" if boundary_context.membership else None),
        related_core_member_ids=list(boundary_context.related_core_member_ids),
        enforced_sub_boundary=boundary_context.membership.enforced_sub_boundary if boundary_context.membership else None,
        attack_path_if_omitted=boundary_context.membership.attack_path_if_omitted if boundary_context.membership else None,
        remaining_members_cannot_compensate=(
            f"Other members of {boundary_context.membership.definition.boundary_set_name} enforce different effects and cannot replace {boundary_context.membership.effect}."
            if boundary_context.membership and not boundary_context.membership.standalone
            else None
        ),
        rationale=rationale,
        confidence=confidence,
        review_note=review_note,
    )
