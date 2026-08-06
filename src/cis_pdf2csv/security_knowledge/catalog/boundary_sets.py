from __future__ import annotations

from .capabilities import PROVENANCE
from .registry import BoundarySetDefinition

_SETS = (
    ("BS-NETWORK-HOST-FIREWALL-PRIVATE", "BND-NETWORK-HOST-FIREWALL", "Private host firewall", ("firewall enabled", "default inbound deny")),
    ("BS-NETWORK-HOST-FIREWALL-PUBLIC", "BND-NETWORK-HOST-FIREWALL", "Public host firewall", ("firewall enabled", "default inbound deny")),
    ("BS-NETWORK-SMB-SESSION", "BND-NETWORK-SMB-SESSION", "SMB session security", ("protocol floor", "session signing", "insecure session rejection")),
    ("BS-IDENTITY-LDAP-CHANNEL", "BND-IDENTITY-LDAP-CHANNEL", "LDAP channel security", ("channel signing", "channel sealing or encryption")),
    ("BS-IDENTITY-NTLM-SESSION", "BND-IDENTITY-NTLM-SESSION", "NTLM session security", ("weak authentication refusal", "session integrity", "session encryption")),
    ("BS-REMOTE-WINRM", "BND-REMOTE-WINRM", "WinRM secure management", ("unencrypted traffic rejected", "weak authentication rejected", "credential retention constrained")),
    ("BS-REMOTE-RDP", "BND-REMOTE-RDP", "RDP secure access", ("network-level authentication", "TLS security layer", "high encryption", "restricted remote-logon right")),
    ("BS-ENDPOINT-MALWARE-PROTECTION", "BND-ENDPOINT-MALWARE-PROTECTION", "Malware protection stack", ("real-time prevention", "behavior monitoring", "network protection", "disablement resistance")),
    ("BS-IDENTITY-PRIVILEGED-CREDENTIALS", "BND-IDENTITY-PRIVILEGED-CREDENTIALS", "Privileged credential and execution protection", ("privileged consent", "credential isolation", "weak credential storage disabled")),
)

BOUNDARY_SETS = tuple(
    BoundarySetDefinition(
        boundary_set_id=identifier,
        boundary_definition_id=boundary,
        name=name,
        description=f"Minimum effective complementary controls for {name.lower()}.",
        required_sub_boundaries=effects,
        minimum_effective_roles=("boundary_set_core_member", "prerequisite"),
        completeness_rules=("Every required sub-boundary has one active primary or complementary mapping.", "Unresolved alternatives make the evaluation incomplete."),
        alternatives=("Equivalent mechanisms are accepted only after explicit equivalence review.",),
        prerequisites=("The protected technology is deployed or the benchmark decision is conditional when deployed.",),
        optional_supporting_effects=("Additional hardening may improve resilience but cannot satisfy a missing core effect.",),
        compensation_rules=("Only full or explicitly accepted conditional equivalence replaces a core effect.",),
        applicability_expectations=("universal or mandatory_when_deployed",),
        provenance=PROVENANCE,
    )
    for identifier, boundary, name, effects in _SETS
)
