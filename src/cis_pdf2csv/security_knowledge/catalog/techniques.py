from __future__ import annotations

from .capabilities import PROVENANCE
from .registry import AttackTechnique, ExternalMapping

_TECHNIQUES = (
    ("TEC-001", "Authentication relay", "Relay a captured authentication exchange to another accepting service.", "authentication", "T1557"),
    ("TEC-002", "Adversary in the middle", "Interpose on a communication path to observe or alter exchanges.", "credential access", "T1557"),
    ("TEC-003", "Remote service abuse", "Use a reachable remote service to gain or extend control.", "lateral movement", "T1021"),
    ("TEC-004", "Network service exposure", "Reach an unintended listening service through an open network path.", "initial access", None),
    ("TEC-005", "Authentication downgrade", "Force negotiation toward a weaker authentication behavior.", "authentication", None),
    ("TEC-006", "Credential material extraction", "Recover reusable secrets or derivatives from storage or memory.", "credential access", "T1003"),
    ("TEC-007", "Privilege elevation", "Cross from a less privileged context into an administrative context.", "privilege escalation", "T1548"),
    ("TEC-008", "Malicious code execution", "Cause untrusted executable content to run.", "execution", "T1059"),
    ("TEC-009", "Defense impairment", "Disable or weaken a security protection mechanism.", "defense evasion", "T1562.001"),
    ("TEC-010", "Audit-log suppression", "Prevent, remove, or impair security-event evidence.", "defense evasion", "T1070"),
    ("TEC-011", "Plaintext credential interception", "Observe credentials transmitted without adequate protection.", "credential access", "T1557"),
    ("TEC-012", "Data access through missing encryption", "Read data exposed because cryptographic storage protection is absent.", "collection", None),
    ("TEC-013", "Password guessing", "Attempt candidate passwords until an account accepts one.", "credential access", "T1110"),
    ("TEC-014", "Credential phishing", "Induce a user to disclose or exercise authentication material through a deceptive verifier.", "credential access", None),
    ("TEC-015", "Multifactor authentication bypass", "Defeat or abuse an additional authentication factor through fatigue, interception, or weak factor choice.", "authentication", None),
    ("TEC-016", "Session token replay", "Reuse authenticated session material outside its intended context.", "credential access", None),
    ("TEC-017", "Device trust bypass", "Present missing, false, or transferred device trust context to an authentication decision.", "defense evasion", None),
    ("TEC-018", "Unauthorized application identity creation", "Create an application identity outside the intended administrative registration process.", "persistence", None),
    ("TEC-019", "Application permission grant abuse", "Induce or exercise an overbroad delegated or administrative application permission grant.", "privilege escalation", None),
    ("TEC-020", "Non-human principal privilege abuse", "Use excessive or stale non-human principal authorization to access protected resources.", "privilege escalation", None),
    ("TEC-021", "Workload federation trust abuse", "Present a federated workload token whose claims are accepted outside the intended trust relationship.", "credential access", None),
)

TECHNIQUES = tuple(
    AttackTechnique(
        technique_id=identifier,
        name=name,
        description=description,
        attack_stage=stage,
        affected_technologies=("technology-independent implementations",),
        prerequisites=("The relevant attack surface is reachable.",),
        external_mappings=(() if mitre is None else (ExternalMapping(
            framework="mitre-attack", external_id=mitre,
            external_url=f"https://attack.mitre.org/techniques/{mitre.replace('.', '/')}/",
            mapping_type="related adversary behavior", confidence="High", provenance=PROVENANCE,
        ),)),
        provenance=PROVENANCE,
    )
    for identifier, name, description, stage, mitre in _TECHNIQUES
)
