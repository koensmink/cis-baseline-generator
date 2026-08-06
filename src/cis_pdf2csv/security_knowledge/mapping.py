from __future__ import annotations

from dataclasses import dataclass

from cis_pdf2csv.mandatory.criteria import match_criteria
from cis_pdf2csv.mandatory.schema import MandatoryAssessment
from cis_pdf2csv.schema import ControlRecord

from .attack_paths import ATTACK_PATH_BY_ID
from .schema import (
    ControlAttackPathMapping,
    LegacyMitigationRole,
    LegacyMitigationStrength,
)


@dataclass(frozen=True)
class MappingRule:
    attack_path_id: str
    capability_id: str
    mitigation_role: LegacyMitigationRole
    attack_stage: str


BOUNDARY_RULES: dict[str, tuple[MappingRule, ...]] = {
    "BS-HOST-FIREWALL": (
        MappingRule("AP-007", "CAP-04", "restrict", "initial access"),
        MappingRule("AP-003", "CAP-04", "restrict", "lateral movement"),
    ),
    "BS-SMB-SECURITY": (
        MappingRule("AP-001", "CAP-01", "protect", "authentication"),
        MappingRule("AP-003", "CAP-04", "restrict", "lateral movement"),
    ),
    "BS-LDAP-SECURITY": (
        MappingRule("AP-001", "CAP-01", "protect", "authentication"),
        MappingRule("AP-001", "CAP-08", "protect", "credential access"),
    ),
    "BS-NTLM-SESSION": (
        MappingRule("AP-001", "CAP-01", "prevent", "authentication"),
        MappingRule("AP-009", "CAP-02", "protect", "credential access"),
    ),
    "BS-WINRM-SECURITY": (
        MappingRule("AP-004", "CAP-05", "restrict", "initial access"),
        MappingRule("AP-003", "CAP-05", "protect", "lateral movement"),
    ),
    "BS-RDP-SECURITY": (
        MappingRule("AP-004", "CAP-05", "restrict", "authentication"),
        MappingRule("AP-003", "CAP-05", "protect", "lateral movement"),
    ),
    "BS-MALWARE-PROTECTION": (
        MappingRule("AP-005", "CAP-07", "prevent", "execution"),
        MappingRule("AP-006", "CAP-07", "protect", "defense evasion"),
    ),
}

CRITERION_RULES: dict[str, tuple[MappingRule, ...]] = {
    "MC-CRIT-002": (MappingRule("AP-001", "CAP-01", "prevent", "authentication"),),
    "MC-CRIT-003": (MappingRule("AP-008", "CAP-03", "restrict", "privilege escalation"),),
    "MC-CRIT-004": (MappingRule("AP-002", "CAP-02", "protect", "credential access"),),
    "MC-CRIT-005": (MappingRule("AP-008", "CAP-03", "restrict", "privilege escalation"),),
    "MC-CRIT-006": (MappingRule("AP-004", "CAP-05", "restrict", "initial access"),),
    "MC-CRIT-007": (MappingRule("AP-005", "CAP-06", "prevent", "execution"),),
    "MC-CRIT-008": (MappingRule("AP-007", "CAP-04", "restrict", "initial access"),),
    "MC-CRIT-009": (MappingRule("AP-007", "CAP-04", "prevent", "initial access"),),
    "MC-CRIT-010": (MappingRule("AP-001", "CAP-08", "protect", "authentication"),),
    "MC-CRIT-011": (MappingRule("AP-001", "CAP-08", "protect", "authentication"),),
    "MC-CRIT-012": (MappingRule("AP-009", "CAP-10", "protect", "credential access"),),
    "MC-CRIT-014": (MappingRule("AP-005", "CAP-06", "restrict", "execution"),),
    "MC-CRIT-015": (MappingRule("AP-010", "CAP-09", "investigate", "investigation"),),
    "MC-CRIT-016": (MappingRule("AP-006", "CAP-07", "prevent", "defense evasion"),),
}


def _strength(assessment: MandatoryAssessment) -> LegacyMitigationStrength:
    if assessment.relationship == "boundary-set core member":
        return "complementary"
    if assessment.relationship in {"standalone primary boundary", "prerequisite"}:
        return "primary"
    return "supporting"


def _evidence(control: ControlRecord, assessment: MandatoryAssessment) -> list[str]:
    values = []
    if assessment.enforced_sub_boundary:
        values.append(f"boundary effect: {assessment.enforced_sub_boundary}")
    for field in ("description", "rationale", "impact", "remediation"):
        value = getattr(control, field)
        if value:
            values.append(f"{field}: {' '.join(value.split())[:240]}")
    return values


def _boundary_rules(assessment: MandatoryAssessment) -> tuple[MappingRule, ...]:
    boundary_id = assessment.boundary_set_id or ""
    if boundary_id == "BS-PRIVILEGED-CREDENTIALS":
        effect = assessment.enforced_sub_boundary or ""
        if any(term in effect for term in ("credential", "password", "LSASS", "hash")):
            return (
                MappingRule("AP-002", "CAP-02", "protect", "credential access"),
                MappingRule("AP-009", "CAP-02", "protect", "credential access"),
            )
        return (MappingRule("AP-008", "CAP-03", "restrict", "privilege escalation"),)
    for prefix, rules in BOUNDARY_RULES.items():
        if boundary_id.startswith(prefix):
            return rules
    return ()


def map_control(
    control: ControlRecord,
    assessment: MandatoryAssessment,
) -> list[ControlAttackPathMapping]:
    """Map using boundary identity first and structured assessment evidence second."""
    rules = _boundary_rules(assessment)
    boundary_driven = bool(rules)
    behavior_text = " ".join(
        value or ""
        for value in (
            control.description,
            control.rationale,
            control.impact,
            control.remediation,
        )
    )
    corroborated_criteria = set(match_criteria(behavior_text)) & set(
        assessment.mandatory_criteria
    )
    if not rules and corroborated_criteria and control.rationale and control.remediation:
        rules = tuple(
            rule
            for criterion in sorted(corroborated_criteria)
            for rule in CRITERION_RULES.get(criterion, ())
        )
    if not rules:
        return []

    evidence = _evidence(control, assessment)
    confidence = "High" if boundary_driven and len(evidence) >= 3 else assessment.confidence
    strength = _strength(assessment)
    unique_rules = {
        (rule.attack_path_id, rule.capability_id, rule.mitigation_role, rule.attack_stage): rule
        for rule in rules
    }
    mappings = []
    for key in sorted(unique_rules):
        rule = unique_rules[key]
        attack_path = ATTACK_PATH_BY_ID[rule.attack_path_id]
        boundary = assessment.boundary_set_name or assessment.control_family
        mappings.append(
            ControlAttackPathMapping(
                control_id=control.control_id,
                attack_path_id=rule.attack_path_id,
                capability_id=rule.capability_id,
                mitigation_role=rule.mitigation_role,
                attack_stage=rule.attack_stage,
                mitigation_strength=strength,
                evidence=evidence,
                rationale=(
                    f"{boundary} enforces {assessment.enforced_sub_boundary or 'the assessed security boundary'}; "
                    f"this {rule.mitigation_role} mitigation interrupts {attack_path.name.lower()} "
                    f"at the {rule.attack_stage} stage."
                ),
                confidence=confidence,
            )
        )
    return mappings
