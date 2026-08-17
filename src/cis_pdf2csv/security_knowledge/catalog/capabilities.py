from __future__ import annotations

from .registry import CatalogProvenance, SecurityCapability

PROVENANCE = CatalogProvenance(
    authority="cis-pdf2csv security knowledge governance",
    method="human-curated technology-independent catalog definition",
    catalog_version="1.1.0",
    reviewed_by="security architecture review",
    reviewed_at="2026-08-17",
)

_DEFINITIONS = (
    ("CAP-01", "Identity and authentication protection", "Establish and verify identities while resisting authentication misuse.", "Only authenticated and authorized identities gain access.", ("identity validation", "authentication protocol protection"), ("credential storage", "network reachability"), ("strong peer authentication", "anonymous-access restriction")),
    ("CAP-02", "Credential protection", "Protect reusable secrets and credential derivatives throughout their lifecycle.", "Credential material remains unavailable to unauthorized actors.", ("secret isolation", "credential storage protection"), ("general data encryption", "identity proofing"), ("protected credential processes", "non-reversible password storage")),
    ("CAP-03", "Privileged execution control", "Mediate transitions into elevated execution contexts.", "Privileged actions require an enforced authorization boundary.", ("elevation consent", "privileged token mediation"), ("ordinary authentication", "application allowlisting"), ("secure elevation", "privileged-right restriction")),
    ("CAP-04", "Network boundary protection", "Restrict network paths crossing a protected system boundary.", "Only intended traffic reaches protected network services.", ("inbound filtering", "service exposure restriction"), ("transport encryption", "event logging"), ("host firewalling", "network segmentation")),
    ("CAP-05", "Secure remote management", "Protect administrative access through remote-management channels.", "Remote administration is authenticated, authorized, and transport protected.", ("secure management transport", "remote logon restriction"), ("local administration", "generic firewall logging"), ("encrypted management sessions", "restricted remote operators")),
    ("CAP-06", "Application and code execution control", "Control whether executable content may run.", "Only trusted and authorized code executes.", ("application allowlisting", "script policy enforcement"), ("malware scanning alone", "user-interface hiding"), ("signed-code enforcement", "script restriction")),
    ("CAP-07", "Malware prevention and response", "Prevent, contain, and respond to malicious software behavior.", "Malicious behavior is blocked or contained before material impact.", ("real-time prevention", "behavior blocking"), ("scan scheduling", "notification preferences"), ("endpoint behavior monitoring", "network protection")),
    ("CAP-08", "Cryptographic and transport protection", "Provide confidentiality, integrity, and peer authenticity through cryptographic mechanisms.", "Information is protected in transit and at cryptographic trust boundaries.", ("channel encryption", "message signing"), ("identity authorization", "data classification"), ("TLS enforcement", "protocol signing")),
    ("CAP-09", "Security monitoring and investigation", "Preserve visibility and evidence for detecting and investigating security events.", "Security-relevant activity is observable and attributable.", ("security auditing", "forensic evidence retention"), ("preventive access control", "cosmetic status display"), ("audit event generation", "protected logging")),
    ("CAP-10", "Data protection", "Protect data against unauthorized disclosure, alteration, and loss.", "Stored and processed data retains confidentiality, integrity, and availability.", ("storage encryption", "protected data access"), ("transport security only", "credential authentication"), ("volume encryption", "protected backups")),
)

CAPABILITIES = tuple(
    SecurityCapability(
        capability_id=identifier,
        name=name,
        definition=definition,
        security_objective=objective,
        included_security_effects=included,
        excluded_effects=excluded,
        examples=examples,
        provenance=PROVENANCE,
    )
    for identifier, name, definition, objective, included, excluded, examples in _DEFINITIONS
)
