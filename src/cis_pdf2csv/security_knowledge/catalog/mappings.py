from __future__ import annotations

from .registry import LegacyKnowledgeMigration

_MAPPINGS = (
    ("BS-HOST-FIREWALL-DOMAIN", "BS-NETWORK-HOST-FIREWALL-PRIVATE", "BND-NETWORK-HOST-FIREWALL", ("CAP-04",), ("AP-003", "AP-007"), "The legacy domain-profile set resolves to the generic host-firewall boundary; profile remains evaluation context."),
    ("BS-HOST-FIREWALL-PRIVATE", "BS-NETWORK-HOST-FIREWALL-PRIVATE", "BND-NETWORK-HOST-FIREWALL", ("CAP-04",), ("AP-003", "AP-007"), "Direct profile-aware migration."),
    ("BS-HOST-FIREWALL-PUBLIC", "BS-NETWORK-HOST-FIREWALL-PUBLIC", "BND-NETWORK-HOST-FIREWALL", ("CAP-04",), ("AP-003", "AP-007"), "Direct profile-aware migration."),
    ("BS-SMB-SECURITY", "BS-NETWORK-SMB-SESSION", "BND-NETWORK-SMB-SESSION", ("CAP-01", "CAP-04", "CAP-08"), ("AP-001", "AP-003"), "Legacy SMB effects become normative session-security mappings."),
    ("BS-LDAP-SECURITY", "BS-IDENTITY-LDAP-CHANNEL", "BND-IDENTITY-LDAP-CHANNEL", ("CAP-01", "CAP-08"), ("AP-001", "AP-012"), "Signing and encryption remain complementary effects."),
    ("BS-NTLM-SESSION", "BS-IDENTITY-NTLM-SESSION", "BND-IDENTITY-NTLM-SESSION", ("CAP-01", "CAP-02", "CAP-08"), ("AP-001", "AP-012"), "Authentication and session effects remain distinct."),
    ("BS-WINRM-SECURITY", "BS-REMOTE-WINRM", "BND-REMOTE-WINRM", ("CAP-02", "CAP-05", "CAP-08"), ("AP-003", "AP-004", "AP-012"), "Remote-management transport and credential effects are retained."),
    ("BS-RDP-SECURITY", "BS-REMOTE-RDP", "BND-REMOTE-RDP", ("CAP-01", "CAP-05", "CAP-08"), ("AP-003", "AP-004", "AP-012"), "Remote desktop is conditional when deployed."),
    ("BS-MALWARE-PROTECTION", "BS-ENDPOINT-MALWARE-PROTECTION", "BND-ENDPOINT-MALWARE-PROTECTION", ("CAP-07",), ("AP-005", "AP-006"), "Core prevention effects remain separate from scan tuning."),
    ("BS-PRIVILEGED-CREDENTIALS", "BS-IDENTITY-PRIVILEGED-CREDENTIALS", "BND-IDENTITY-PRIVILEGED-CREDENTIALS", ("CAP-02", "CAP-03"), ("AP-002", "AP-008", "AP-009"), "Credential and elevation effects share one evaluated boundary set."),
    ("SEM-PASSWORD-AUTHENTICATION-STRENGTH", "BS-IDENTITY-PASSWORD-AUTHENTICATION", "BND-IDENTITY-PASSWORD-AUTHENTICATION", ("CAP-01", "CAP-02"), ("AP-014",), "Semantic mapping for reusable password-authentication-strength recommendations."),
    ("SEM-EXTERNAL-IDENTITY-AUTHENTICATION", "BS-IDENTITY-EXTERNAL-AUTHENTICATION", "BND-IDENTITY-EXTERNAL-AUTHENTICATION", ("CAP-01",), ("AP-015",), "Semantic mapping for external, consumer, and peer online-identity trust restrictions."),
    ("SEM-WEAK-PLAINTEXT-AUTHENTICATION", "BS-IDENTITY-WEAK-AUTHENTICATION", "BND-IDENTITY-WEAK-AUTHENTICATION", ("CAP-01", "CAP-02", "CAP-08"), ("AP-012",), "Semantic mapping for rejection of Basic or plaintext authentication."),
    ("SEM-PRIVILEGED-ROLE-ACTIVATION", "BS-IDENTITY-PRIVILEGED-ACTIVATION", "BND-IDENTITY-PRIVILEGED-ACTIVATION", ("CAP-01", "CAP-03"), ("AP-016",), "Semantic mapping for independently approved activation of eligible privileged roles."),
)

LEGACY_MIGRATION_MAP = tuple(
    LegacyKnowledgeMigration(
        legacy_boundary_set_id=row[0], normative_boundary_set_id=row[1],
        normative_boundary_definition_id=row[2], capability_ids=row[3],
        attack_path_ids=row[4], notes=row[5],
    )
    for row in _MAPPINGS
)
