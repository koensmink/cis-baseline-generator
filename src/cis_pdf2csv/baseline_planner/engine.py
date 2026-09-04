from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from cis_pdf2csv.intune_mapper.models import MappingInputControl, MappingStatus
from cis_pdf2csv.intune_mapper.resolver import resolve_control
from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.mandatory.schema import MandatoryAssessment
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.source_identity import source_identity_for_control

from .models import (
    BaselinePlan,
    DeploymentReadiness,
    EnrichedControl,
    ImplementationPhase,
    PlanningLevel,
    PriorityTier,
    SecurityCategory,
    WorkPackage,
)


@dataclass(frozen=True)
class CategoryRule:
    category: SecurityCategory
    work_package: str
    keywords: tuple[str, ...]
    prevents: tuple[str, ...]
    objective: str


CATEGORY_RULES = (
    # Specific rules must precede broader rules when scores are equal.
    CategoryRule(SecurityCategory.ACCOUNT_POLICY, "Account Policy", ("account policy", "password history", "password age", "password length", "minimum password", "maximum password", "password must", "store passwords", "reversible encryption", "account lockout", "lockout duration", "lockout threshold"), ("weak account protection", "password-based compromise"), "Apply consistent account and password safeguards."),
    CategoryRule(SecurityCategory.AUDIT_LOGGING, "Security Logging and Monitoring", ("audit", "event log", "logging", "log file", "syslog"), ("undetected malicious activity", "insufficient forensic evidence"), "Establish reliable security telemetry and audit evidence."),
    CategoryRule(SecurityCategory.DATA_PROTECTION, "Encryption and Data Protection", ("bitlocker", "encrypt", "encryption", "recovery key", "filevault"), ("data exposure", "offline access to protected data"), "Protect sensitive data at rest and in transit."),
    CategoryRule(SecurityCategory.IDENTITY_ACCESS, "Authentication and Access Hardening", ("authentication", "credential", "ntlm", "password", "sign-in", "logon"), ("credential compromise", "unauthorized access"), "Strengthen authentication and access-control boundaries."),
    CategoryRule(SecurityCategory.PRIVILEGED_ACCESS, "Privileged Access Management", ("administrator", "privilege", "sudo", "admin account", "user rights"), ("privilege escalation", "unauthorized administrative activity"), "Reduce and monitor privileged access."),
    CategoryRule(SecurityCategory.REMOTE_ACCESS, "Remote Access Hardening", ("remote desktop", "rdp", "remote access", "winrm", "ssh"), ("unauthorized remote access", "lateral movement"), "Constrain and protect remote administration paths."),
    CategoryRule(SecurityCategory.NETWORK_SECURITY, "Network and Firewall Hardening", ("firewall", "network", "smb", "dns", "tls", "snmp", "port", "protocol"), ("network-based exploitation", "unauthorized lateral movement"), "Reduce exposed network paths and insecure protocols."),
    CategoryRule(SecurityCategory.ENDPOINT_PROTECTION, "Endpoint Protection", ("defender", "antivirus", "malware", "attack surface", "exploit guard", "edr"), ("malware execution", "endpoint compromise"), "Prevent and contain malicious code on endpoints."),
    CategoryRule(SecurityCategory.UPDATE_MANAGEMENT, "Patch and Update Management", ("update", "patch", "software update", "security intelligence"), ("exploitation of known vulnerabilities", "outdated security protection"), "Maintain supported and current software."),
    CategoryRule(SecurityCategory.APPLICATION_CONTROL, "Application and Browser Control", ("application", "app installer", "browser", "safari", "store", "macro", "script"), ("untrusted code execution", "unsafe application behavior"), "Restrict untrusted applications and risky application behavior."),
)

DEFAULT_RULE = CategoryRule(
    SecurityCategory.SYSTEM_HARDENING,
    "Platform Hardening",
    (),
    ("configuration-based compromise", "security-control bypass"),
    "Reduce the platform attack surface through secure configuration.",
)

CATEGORY_WEIGHT = {
    SecurityCategory.IDENTITY_ACCESS: 18,
    SecurityCategory.PRIVILEGED_ACCESS: 18,
    SecurityCategory.REMOTE_ACCESS: 16,
    SecurityCategory.NETWORK_SECURITY: 14,
    SecurityCategory.DATA_PROTECTION: 14,
    SecurityCategory.ENDPOINT_PROTECTION: 14,
    SecurityCategory.AUDIT_LOGGING: 10,
    SecurityCategory.UPDATE_MANAGEMENT: 10,
    SecurityCategory.APPLICATION_CONTROL: 10,
    SecurityCategory.ACCOUNT_POLICY: 12,
    SecurityCategory.SYSTEM_HARDENING: 8,
}


def _category(control: ControlRecord) -> CategoryRule:
    title = control.title.casefold()
    title_matches = [
        (
            sum(title.count(keyword) * len(keyword) for keyword in rule.keywords),
            index,
            rule,
        )
        for index, rule in enumerate(CATEGORY_RULES)
    ]
    score, _, rule = max(title_matches, key=lambda item: (item[0], -item[1]))
    if score:
        return rule

    # Remediation is an implementation signal. Narrative rationale and impact text
    # can mention adjacent technologies and must not determine categorisation.
    remediation = (control.remediation or "").casefold()
    remediation_matches = [
        (sum(remediation.count(keyword) * len(keyword) for keyword in rule.keywords), index, rule)
        for index, rule in enumerate(CATEGORY_RULES)
    ]
    score, _, rule = max(remediation_matches, key=lambda item: (item[0], -item[1]))
    return rule if score else DEFAULT_RULE


def _operational_impact(control: ControlRecord, rule: CategoryRule) -> PlanningLevel:
    text = f"{control.title} {control.impact or ''}".casefold()
    if any(word in text for word in ("service interruption", "loss of connectivity", "cannot connect", "deny logon", "prevent access", "incompatible")):
        return PlanningLevel.HIGH
    if rule.category == SecurityCategory.AUDIT_LOGGING:
        return PlanningLevel.LOW
    return PlanningLevel.MEDIUM


def _user_impact(control: ControlRecord) -> PlanningLevel:
    text = f"{control.title} {control.impact or ''}".casefold()
    if any(word in text for word in ("user cannot", "users cannot", "sign-in", "logon", "password", "screen lock", "remote desktop")):
        return PlanningLevel.HIGH
    if any(word in text for word in ("prompt", "notification", "restart", "browser", "macro", "application")):
        return PlanningLevel.MEDIUM
    return PlanningLevel.LOW


def _rollback_complexity(control: ControlRecord, operational_impact: PlanningLevel) -> PlanningLevel:
    text = f"{control.title} {control.remediation or ''}".casefold()
    if any(word in text for word in ("encryption", "bitlocker", "filevault", "certificate", "deny logon", "ntlm")):
        return PlanningLevel.HIGH
    return operational_impact


def _complexity(control: ControlRecord, impact: PlanningLevel) -> PlanningLevel:
    if control.assessment == "Manual" or impact == PlanningLevel.HIGH:
        return PlanningLevel.HIGH
    if control.assessment == "Unknown":
        return PlanningLevel.HIGH
    return PlanningLevel.MEDIUM


def _readiness(status: MappingStatus, control: ControlRecord) -> DeploymentReadiness:
    if status == MappingStatus.VERIFIED:
        return DeploymentReadiness.DEPLOYMENT_READY
    if control.assessment == "Manual":
        return DeploymentReadiness.MANUAL_IMPLEMENTATION
    return DeploymentReadiness.NEEDS_VALIDATION


def _priority_score(control: ControlRecord, assessment: MandatoryAssessment, rule: CategoryRule, impact: PlanningLevel) -> int:
    score = {"Candidate Mandatory": 55, "Review Required": 40, "Regular Control": 25}[assessment.proposal]
    score += CATEGORY_WEIGHT[rule.category]
    score += 10 if control.profile in {"L1", "BL"} else 3
    score += 5 if control.assessment == "Automated" else 0
    score -= 5 if impact == PlanningLevel.HIGH else 0
    return max(0, min(100, score))


def _priority_tier(score: int) -> PriorityTier:
    if score >= 85:
        return PriorityTier.CRITICAL
    if score >= 70:
        return PriorityTier.HIGH
    if score >= 50:
        return PriorityTier.ELEVATED
    return PriorityTier.NORMAL


def _dependencies(control: ControlRecord, rule: CategoryRule, impact: PlanningLevel) -> tuple[str, ...]:
    dependencies: list[str] = []
    if impact == PlanningLevel.HIGH:
        dependencies.extend(("Document rollback procedure", "Validate application and service compatibility"))
    if rule.category in {SecurityCategory.IDENTITY_ACCESS, SecurityCategory.PRIVILEGED_ACCESS, SecurityCategory.REMOTE_ACCESS}:
        dependencies.append("Confirm break-glass and administrative access")
    if rule.category == SecurityCategory.AUDIT_LOGGING:
        dependencies.append("Wave 0: Logging pipeline and retention")
    text = f"{control.title} {control.remediation or ''}".casefold()
    if any(word in text for word in ("bitlocker", "recovery key", "filevault")):
        dependencies.append("Wave 0: Recovery-key escrow and recovery test")
    if "ntlm" in text:
        dependencies.append("Wave 0: NTLM usage inventory")
    if any(word in text for word in ("attack surface reduction", "asr rule", "edr")):
        dependencies.append("Endpoint Protection: Defender prerequisites")
    return tuple(dependencies)


def _wave(control: ControlRecord, rule: CategoryRule, impact: PlanningLevel, readiness: DeploymentReadiness, assessment: MandatoryAssessment) -> tuple[int, str]:
    if control.assessment == "Manual" or control.profile == "L2":
        return 5, "Manual or Level 2 hardening is scheduled after the core baseline."
    if impact == PlanningLevel.HIGH and readiness != DeploymentReadiness.DEPLOYMENT_READY:
        return 4, "High operational impact requires compatibility testing and an approved rollback."
    if rule.category in {SecurityCategory.IDENTITY_ACCESS, SecurityCategory.PRIVILEGED_ACCESS, SecurityCategory.REMOTE_ACCESS, SecurityCategory.NETWORK_SECURITY}:
        return 3, "Identity and network hardening follows foundational controls and prerequisite validation."
    if rule.category == SecurityCategory.AUDIT_LOGGING and impact == PlanningLevel.LOW:
        return 1, "Low-impact visibility improvement supports validation of later waves."
    if assessment.proposal == "Candidate Mandatory":
        return 2, "Foundational security boundary with manageable implementation impact."
    return 2, "Core baseline hardening with moderate implementation impact."


def _risk_statement(control: ControlRecord, rule: CategoryRule) -> str:
    return f"Without '{control.title}', the environment may remain exposed to {rule.prevents[0]}."


def build_plan(controls: list[ControlRecord], *, max_phase_size: int = 75) -> BaselinePlan:
    if max_phase_size < 1:
        raise ValueError("max_phase_size must be at least 1")
    assessments = assess_controls(controls)
    assessments_by_identity = {
        item.source_identity.serialize(): item
        for item in assessments
        if item.source_identity is not None
    }
    enriched: list[EnrichedControl] = []
    for control in controls:
        identity = source_identity_for_control(control)
        assessment = assessments_by_identity[identity.serialize()]
        mapping, _ = resolve_control(MappingInputControl.model_validate(control.model_dump()))
        rule = _category(control)
        impact = _operational_impact(control, rule)
        user_impact = _user_impact(control)
        rollback_complexity = _rollback_complexity(control, impact)
        complexity = _complexity(control, impact)
        readiness = _readiness(mapping.mapping_status, control)
        score = _priority_score(control, assessment, rule, impact)
        wave, wave_rationale = _wave(control, rule, impact, readiness, assessment)
        dependencies = _dependencies(control, rule, impact)
        enriched.append(
            EnrichedControl(
                source_identity=identity,
                benchmark_name=control.benchmark_name,
                benchmark_version=control.benchmark_version,
                control_id=control.control_id,
                profile=control.profile,
                assessment=control.assessment,
                title=control.title,
                risk_statement=_risk_statement(control, rule),
                prevents=rule.prevents,
                security_category=rule.category,
                work_package=rule.work_package,
                implementation_complexity=complexity,
                operational_impact=impact,
                user_impact=user_impact,
                testing_requirement=("Pilot with representative systems and validate rollback." if impact == PlanningLevel.HIGH else "Validate in a representative test group."),
                rollback_complexity=rollback_complexity,
                mandatory_proposal=assessment.proposal,
                intune_mapping_status=mapping.mapping_status.value,
                deployment_readiness=readiness,
                priority_score=score,
                priority_tier=_priority_tier(score),
                recommended_wave=wave,
                execution_phase=str(wave),
                wave_rationale=wave_rationale,
                dependencies=dependencies,
                evidence_sources=("cis_control", "mandatory_engine", "intune_verifier"),
            )
        )
    ordered = tuple(sorted(enriched, key=lambda item: item.source_identity.as_tuple()))
    phased = _assign_execution_phases(ordered, max_phase_size=max_phase_size)
    return BaselinePlan(
        controls=phased,
        work_packages=_work_packages(phased),
        implementation_phases=_implementation_phases(phased),
        prerequisites=(
            "Confirm scope, control ownership, exceptions, and measurable success criteria",
            "Validate required licences, platform versions, and management enrolment",
            "Inventory current configuration, policy conflicts, and application compatibility",
            "Define exclusions and confirm emergency and break-glass access",
            "Validate monitoring, evidence collection, alerting, and retention",
            "Document rollback thresholds and test configuration recovery procedures",
            "Confirm encryption-key escrow and test device recovery where applicable",
            "Inventory legacy authentication and protocol usage before blocking it",
            "Prepare pilot, validation, and phased assignment groups",
        ),
    )


def _phase_label(wave: int, index: int, count: int) -> str:
    if count == 1:
        return str(wave)
    letters = ""
    number = index + 1
    while number:
        number, remainder = divmod(number - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return f"{wave}{letters}"


def _assign_execution_phases(controls: tuple[EnrichedControl, ...], *, max_phase_size: int) -> tuple[EnrichedControl, ...]:
    groups: dict[tuple[int, str], list[EnrichedControl]] = defaultdict(list)
    for item in controls:
        groups[(item.recommended_wave, item.work_package)].append(item)
    updated: dict[tuple[str, ...], EnrichedControl] = {}
    chunks_by_wave: dict[int, list[list[EnrichedControl]]] = defaultdict(list)
    for (wave, _), members in sorted(groups.items()):
        members.sort(key=lambda item: (-item.priority_score, item.source_identity.as_tuple()))
        chunks = [members[index : index + max_phase_size] for index in range(0, len(members), max_phase_size)]
        chunks_by_wave[wave].extend(chunks)
    for wave, chunks in chunks_by_wave.items():
        for index, chunk in enumerate(chunks):
            label = _phase_label(wave, index, len(chunks))
            for item in chunk:
                updated[item.source_identity.as_tuple()] = item.model_copy(update={"execution_phase": label})
    return tuple(updated[item.source_identity.as_tuple()] for item in controls)


def _work_packages(controls: tuple[EnrichedControl, ...]) -> tuple[WorkPackage, ...]:
    groups: dict[str, list[EnrichedControl]] = defaultdict(list)
    for control in controls:
        groups[control.work_package].append(control)
    tier_order = {tier: index for index, tier in enumerate(PriorityTier)}
    level_order = {level: index for index, level in enumerate(PlanningLevel)}
    packages: list[WorkPackage] = []
    for name, members in sorted(groups.items()):
        rule = next((item for item in CATEGORY_RULES if item.work_package == name), DEFAULT_RULE)
        packages.append(
            WorkPackage(
                name=name,
                security_category=members[0].security_category,
                execution_phases=tuple(sorted({item.execution_phase for item in members})),
                control_count=len(members),
                control_ids=tuple(sorted(item.control_id for item in members)),
                objective=rule.objective,
                dependencies=tuple(sorted({dependency for item in members for dependency in item.dependencies})),
                highest_priority=max(
                    (item.priority_tier for item in members),
                    key=lambda value: tier_order[value],
                ),
                highest_operational_impact=max(
                    (item.operational_impact for item in members),
                    key=lambda value: level_order[value],
                ),
                deployment_ready_controls=sum(item.deployment_readiness == DeploymentReadiness.DEPLOYMENT_READY for item in members),
                review_required_controls=sum(item.deployment_readiness != DeploymentReadiness.DEPLOYMENT_READY for item in members),
            )
        )
    return tuple(packages)


def _implementation_phases(controls: tuple[EnrichedControl, ...]) -> tuple[ImplementationPhase, ...]:
    groups: dict[str, list[EnrichedControl]] = defaultdict(list)
    level_order = {level: index for index, level in enumerate(PlanningLevel)}
    for control in controls:
        groups[control.execution_phase].append(control)
    package_phases: dict[tuple[int, str], list[str]] = defaultdict(list)
    for name, members in groups.items():
        key = (members[0].recommended_wave, members[0].work_package)
        package_phases[key].append(name)
    for names in package_phases.values():
        names.sort()
    phases: list[ImplementationPhase] = []
    for name, members in sorted(groups.items(), key=lambda item: (item[1][0].recommended_wave, item[0])):
        package_name = members[0].work_package
        sibling_phases = package_phases[(members[0].recommended_wave, package_name)]
        suffix = ""
        if len(sibling_phases) > 1:
            suffix = f" (part {sibling_phases.index(name) + 1}/{len(sibling_phases)})"
        phases.append(ImplementationPhase(
            name=name,
            title=f"Wave {members[0].recommended_wave} / {package_name}{suffix}",
            wave=members[0].recommended_wave,
            control_count=len(members),
            work_packages=tuple(sorted({item.work_package for item in members})),
            control_ids=tuple(sorted(item.control_id for item in members)),
            dependencies=tuple(sorted({dependency for item in members for dependency in item.dependencies})),
            highest_operational_impact=max((item.operational_impact for item in members), key=lambda value: level_order[value]),
        ))
    return tuple(phases)
