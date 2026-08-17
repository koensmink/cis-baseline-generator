from __future__ import annotations

from pydantic import BaseModel, Field

from cis_pdf2csv.mandatory.schema import MandatoryAssessment
from cis_pdf2csv.schema import ControlRecord

from .boundaries import ApplicabilityMode
from .evidence import EvidenceItem, EvidenceType
from .mitigation import (
    BoundaryRole,
    MitigationMapping,
    MitigationRole,
    MitigationStrength,
)
from .provenance import Confidence, LifecycleStatus, MappingEvidenceProvenance
from .schema import Proposal
from .validation import (
    DecisionEffect,
    FindingSeverity,
    ValidationFinding,
    sorted_findings,
)

BOUNDARY_DEFINITION_BY_SET_PREFIX = {
    "BS-HOST-FIREWALL": "BND-NETWORK-INBOUND",
    "BS-SMB-SECURITY": "BND-NETWORK-ADMINISTRATION",
    "BS-LDAP-SECURITY": "BND-IDENTITY-AUTHENTICATION",
    "BS-NTLM-SESSION": "BND-IDENTITY-AUTHENTICATION",
    "BS-WINRM-SECURITY": "BND-REMOTE-MANAGEMENT",
    "BS-RDP-SECURITY": "BND-REMOTE-MANAGEMENT",
    "BS-MALWARE-PROTECTION": "BND-MALWARE-PROTECTION",
    "BS-PRIVILEGED-CREDENTIALS": "BND-PRIVILEGE-ELEVATION",
}

BOUNDARY_BY_CAPABILITY = {
    "CAP-01": "BND-IDENTITY-AUTHENTICATION",
    "CAP-02": "BND-CREDENTIAL-STORAGE",
    "CAP-03": "BND-PRIVILEGE-ELEVATION",
    "CAP-04": "BND-NETWORK-INBOUND",
    "CAP-05": "BND-REMOTE-MANAGEMENT",
    "CAP-06": "BND-EXECUTION-CONTROL",
    "CAP-07": "BND-MALWARE-PROTECTION",
    "CAP-08": "BND-TRANSPORT-PROTECTION",
    "CAP-09": "BND-MONITORING-EVIDENCE",
    "CAP-10": "BND-DATA-PROTECTION",
}

BOUNDARY_ROLE_ADAPTER = {
    "standalone primary boundary": BoundaryRole.STANDALONE_PRIMARY_BOUNDARY,
    "boundary-set core member": BoundaryRole.BOUNDARY_SET_CORE_MEMBER,
    "prerequisite": BoundaryRole.PREREQUISITE,
    "supporting hardening": BoundaryRole.SUPPORTING_HARDENING,
    "fine-tuning": BoundaryRole.FINE_TUNING,
    "detection-only": BoundaryRole.DETECTION_ONLY,
    "information-hiding": BoundaryRole.INFORMATION_HIDING,
    "operational": BoundaryRole.OPERATIONAL,
}


class CompatibilityResult(BaseModel):
    mappings: list[MitigationMapping] = Field(default_factory=list)
    findings: list[ValidationFinding] = Field(default_factory=list)
    proposal_by_control_id: dict[str, Proposal] = Field(default_factory=dict)
    adaptation_notes: list[str] = Field(default_factory=list)


def _source_id(control: ControlRecord) -> str:
    return (
        f"CIS|{control.benchmark_name}|{control.benchmark_version}|"
        f"{control.profile}|{control.control_id}"
    )


def _boundary_id(assessment: MandatoryAssessment, capability_id: str) -> str | None:
    boundary_set_id = assessment.boundary_set_id or ""
    for prefix, boundary_id in BOUNDARY_DEFINITION_BY_SET_PREFIX.items():
        if boundary_set_id.startswith(prefix):
            return boundary_id
    return BOUNDARY_BY_CAPABILITY.get(capability_id)


def adapt_phase1_assessments_to_mappings(
    controls: list[ControlRecord],
    assessments: list[MandatoryAssessment],
) -> CompatibilityResult:
    controls_by_id = {item.control_id: item for item in controls}
    mappings: list[MitigationMapping] = []
    findings: list[ValidationFinding] = []
    proposals: dict[str, Proposal] = {}
    sequence = 1000

    for assessment in sorted(assessments, key=lambda item: item.control_id):
        control = controls_by_id.get(assessment.control_id)
        proposal = Proposal(assessment.proposal)
        proposals[assessment.control_id] = proposal
        if control is None:
            findings.append(
                ValidationFinding(
                    code="SKC-SOURCE-MISSING",
                    severity=FindingSeverity.ERROR,
                    object_type="MandatoryAssessment",
                    object_id=assessment.control_id,
                    message="Phase-1 assessment has no matching scoped ControlRecord.",
                    required_action="Supply the source record and rerun adaptation.",
                    decision_effect=DecisionEffect.REVIEW_REQUIRED,
                )
            )
            proposals[assessment.control_id] = Proposal.REVIEW
            continue

        for legacy in assessment.attack_path_mappings:
            boundary_id = _boundary_id(assessment, legacy.capability_id)
            if boundary_id is None or not legacy.evidence:
                findings.append(
                    ValidationFinding(
                        code="SKC-NORMATIVE-MAPPING-INCOMPLETE",
                        severity=FindingSeverity.ERROR,
                        object_type="ControlAttackPathMapping",
                        object_id=f"{assessment.control_id}:{legacy.attack_path_id}",
                        message="Phase-1 mapping lacks a normative boundary or attributable evidence.",
                        required_action="Review the mapping and supply missing normative fields.",
                        decision_effect=DecisionEffect.REVIEW_REQUIRED,
                    )
                )
                proposals[assessment.control_id] = Proposal.REVIEW
                continue

            evidence = [
                EvidenceItem(
                    evidence_type=EvidenceType.SOURCE_CONTROL,
                    source=_source_id(control),
                    locator=f"pages:{control.page_start}-{control.page_end}",
                    assertion=item,
                    collection_method="Phase-1 compatibility adapter",
                    confidence=Confidence(legacy.confidence),
                )
                for item in legacy.evidence
            ]
            source_fields = [item.field for item in assessment.benchmark_evidence]
            provenance = MappingEvidenceProvenance(
                source_fields_used=source_fields or ["description"],
                evidence_reference_ids=[f"legacy:{assessment.control_id}:{legacy.attack_path_id}"],
                mapping_method="phase1_compatibility_adapter",
                rule_version="phase1",
                ontology_version="1.0",
            )
            mappings.append(
                MitigationMapping(
                    mapping_id=f"MAP-{sequence}",
                    source_recommendation_id=_source_id(control),
                    capability_id=legacy.capability_id,
                    boundary_definition_id=boundary_id,
                    boundary_set_definition_id=assessment.boundary_set_id,
                    threat_scenario_id=f"TS-{int(legacy.attack_path_id.removeprefix('AP-')):03d}",
                    attack_path_id=legacy.attack_path_id,
                    attack_stage=legacy.attack_stage,
                    boundary_role=BOUNDARY_ROLE_ADAPTER[assessment.relationship],
                    mitigation_role=MitigationRole(legacy.mitigation_role),
                    mitigation_strength=MitigationStrength(legacy.mitigation_strength),
                    enforced_sub_boundary=assessment.enforced_sub_boundary or assessment.control_family,
                    attack_path_if_omitted=assessment.attack_path_if_omitted or legacy.rationale,
                    evidence=evidence,
                    confidence=Confidence(legacy.confidence),
                    applicability_mode=ApplicabilityMode(assessment.applicability_mode),
                    lifecycle_status=LifecycleStatus.ACTIVE,
                    rule_version="phase1",
                    ontology_version="1.0",
                    provenance=provenance,
                )
            )
            sequence += 1

        if proposal == Proposal.CANDIDATE and not any(
            item.source_recommendation_id == _source_id(control) for item in mappings
        ):
            findings.append(
                ValidationFinding(
                    code="SKC-ATTACK-PATH-MAPPING-REQUIRED",
                    severity=FindingSeverity.ERROR,
                    object_type="MandatoryAssessment",
                    object_id=assessment.control_id,
                    message="Candidate Mandatory lacks an adaptable normative mapping.",
                    required_action="Review and create an atomic High-confidence mapping.",
                    decision_effect=DecisionEffect.REVIEW_REQUIRED,
                )
            )
            proposals[assessment.control_id] = Proposal.REVIEW

    return CompatibilityResult(
        mappings=mappings,
        findings=sorted_findings(findings),
        proposal_by_control_id=proposals,
        adaptation_notes=[
            "Phase-1 narrative evidence is retained as typed source-control evidence.",
            "BoundaryDefinition IDs are explicit adapter mappings, not source facts.",
            "No Phase-1 MandatoryAssessment is mutated by adaptation.",
        ],
    )
