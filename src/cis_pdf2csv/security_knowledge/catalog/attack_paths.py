from __future__ import annotations

from .capabilities import PROVENANCE
from .registry import AttackPath

_PATHS = (
    ("AP-001", "Credential relay and authentication interception", ("TS-103", "TS-104", "TS-105"), ("TEC-001", "TEC-002", "TEC-005"), ("OUT-002", "OUT-004"), ("BND-NETWORK-SMB-SESSION", "BND-IDENTITY-LDAP-CHANNEL", "BND-IDENTITY-NTLM-SESSION")),
    ("AP-002", "Credential extraction from operating-system memory", ("TS-110",), ("TEC-006",), ("OUT-003", "OUT-012"), ("BND-IDENTITY-PRIVILEGED-CREDENTIALS",)),
    ("AP-003", "Lateral movement over administrative protocols", ("TS-102",), ("TEC-003",), ("OUT-005", "OUT-012"), ("BND-NETWORK-SMB-SESSION", "BND-REMOTE-WINRM", "BND-REMOTE-RDP")),
    ("AP-004", "Abuse of remote-management interfaces", ("TS-107", "TS-108"), ("TEC-002", "TEC-003", "TEC-004"), ("OUT-005", "OUT-006"), ("BND-REMOTE-WINRM", "BND-REMOTE-RDP")),
    ("AP-005", "Malicious code and script execution", ("TS-114",), ("TEC-008",), ("OUT-006",), ("BND-EXECUTION-APPLICATION-CONTROL", "BND-EXECUTION-SCRIPT-CONTROL")),
    ("AP-006", "Malware evasion and protection disablement", ("TS-112", "TS-113"), ("TEC-008", "TEC-009"), ("OUT-007", "OUT-008"), ("BND-ENDPOINT-MALWARE-PROTECTION",)),
    ("AP-007", "Unauthorized inbound network access", ("TS-101",), ("TEC-004",), ("OUT-001", "OUT-006"), ("BND-NETWORK-HOST-FIREWALL",)),
    ("AP-008", "Privilege elevation through weak consent boundaries", ("TS-111",), ("TEC-007",), ("OUT-004", "OUT-012"), ("BND-IDENTITY-PRIVILEGED-CREDENTIALS",)),
    ("AP-009", "Plaintext or weakly protected credential storage", ("TS-109",), ("TEC-006",), ("OUT-003", "OUT-002"), ("BND-IDENTITY-PRIVILEGED-CREDENTIALS",)),
    ("AP-010", "Security-event suppression and loss of forensic evidence", ("TS-115", "TS-116"), ("TEC-010",), ("OUT-013",), ("BND-MONITORING-SECURITY-AUDIT",)),
    ("AP-011", "Unsigned or untrusted application execution", ("TS-114",), ("TEC-008",), ("OUT-006",), ("BND-EXECUTION-APPLICATION-CONTROL", "BND-EXECUTION-SCRIPT-CONTROL")),
    ("AP-012", "Unencrypted transport interception", ("TS-106", "TS-107", "TS-117", "TS-121"), ("TEC-002", "TEC-011"), ("OUT-003", "OUT-009", "OUT-010"), ("BND-CRYPTO-TRANSPORT", "BND-IDENTITY-LDAP-CHANNEL", "BND-IDENTITY-NTLM-SESSION", "BND-REMOTE-WINRM", "BND-REMOTE-RDP", "BND-IDENTITY-WEAK-AUTHENTICATION")),
    ("AP-013", "Unencrypted data-at-rest exposure", ("TS-118",), ("TEC-012",), ("OUT-009", "OUT-014"), ("BND-DATA-STORAGE-ENCRYPTION",)),
    ("AP-014", "Password guessing and weak-secret authentication", ("TS-119",), ("TEC-013",), ("OUT-002", "OUT-012"), ("BND-IDENTITY-PASSWORD-AUTHENTICATION",)),
    ("AP-015", "Authentication through unapproved external identity trust", ("TS-120",), ("TEC-005",), ("OUT-002", "OUT-004"), ("BND-IDENTITY-EXTERNAL-AUTHENTICATION",)),
    ("AP-016", "Privilege escalation through unapproved role activation", ("TS-122",), ("TEC-007",), ("OUT-004", "OUT-012"), ("BND-IDENTITY-PRIVILEGED-ACTIVATION",)),
    ("AP-017", "Password-only authentication compromise", ("TS-123", "TS-124"), ("TEC-014", "TEC-015"), ("OUT-002", "OUT-003", "OUT-012"), ("BND-IDENTITY-MULTIFACTOR-AUTHENTICATION",)),
    ("AP-018", "Phishing-resistant authentication bypass", ("TS-124", "TS-125"), ("TEC-014", "TEC-015", "TEC-016"), ("OUT-002", "OUT-003", "OUT-012"), ("BND-IDENTITY-PHISHING-RESISTANT-AUTHENTICATION", "BND-IDENTITY-AUTHENTICATION-STRENGTH")),
    ("AP-019", "Session replay and authentication transfer", ("TS-126",), ("TEC-016",), ("OUT-002", "OUT-009", "OUT-012"), ("BND-IDENTITY-AUTHENTICATION-SESSION-BINDING",)),
    ("AP-020", "Stale authenticated-session abuse", ("TS-127",), ("TEC-016",), ("OUT-002", "OUT-009", "OUT-012"), ("BND-IDENTITY-SESSION-ASSURANCE",)),
    ("AP-021", "Untrusted-device authentication access", ("TS-128",), ("TEC-017",), ("OUT-002", "OUT-009", "OUT-012"), ("BND-IDENTITY-MANAGED-DEVICE-TRUST",)),
    ("AP-022", "Non-user resource-key authentication bypass", ("TS-121",), ("TEC-011",), ("OUT-002", "OUT-009", "OUT-012"), ("BND-IDENTITY-WEAK-AUTHENTICATION",)),
)

ATTACK_PATHS = tuple(
    AttackPath(
        attack_path_id=identifier, name=name,
        description=f"A reusable sequence through which an adversary achieves {name.lower()}.",
        ordered_stages=("establish entry condition", "abuse the exposed weakness", "reach the security outcome"),
        entry_conditions=("At least one referenced threat-scenario precondition holds.",),
        intermediate_conditions=("The referenced security boundary is absent or incomplete.",),
        attacker_goals=("Reach one or more specified security outcomes.",),
        affected_assets=("assets identified by the referenced threat scenarios",),
        security_outcome_ids=outcomes, threat_scenario_ids=scenarios,
        technique_ids=techniques, boundary_ids=boundaries,
        residual_path_description="If only supporting controls are present, the core adversary sequence remains feasible.",
        provenance=PROVENANCE,
    )
    for identifier, name, scenarios, techniques, outcomes, boundaries in _PATHS
)
