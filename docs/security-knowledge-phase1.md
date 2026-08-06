# Security Knowledge — Phase 1

The deterministic Security Knowledge module enriches parser-produced controls
and Mandatory assessments. It does not parse documents, assign a numeric risk
score, or replace analyst approval.

## Capability, boundary set, and attack path

A **security capability** is a technology-independent security outcome, such as
credential protection or secure remote management. A **boundary set** is the
smallest group of concrete benchmark controls that implements a security
boundary for a technology. An **attack path** describes how an attacker reaches
an adverse outcome across one or more stages. One boundary may mitigate several
attack paths, and several complementary controls may mitigate one path.

An attack path is not a MITRE ATT&CK technique. A path describes the complete
security-relevant progression used by this engine; optional MITRE identifiers
only provide external references to techniques that may occur within it.

## Mitigation role and strength

Roles describe what the control does at an attack stage: prevent, restrict,
isolate, protect, detect, investigate, or recover. Strength describes the
control's position in the boundary: primary, complementary, or supporting.
Supporting hardening cannot satisfy the attack-path evidence requirement for a
Candidate Mandatory control.

The existing boundary-set identity is the primary mapping signal. Criteria,
family, structured control text, and the existing assessment provide secondary
corroboration. Title text alone never creates a mapping. A control that otherwise
qualifies as Candidate Mandatory is changed to Review Required with
`ATTACK_PATH_MAPPING_REQUIRED` when no High-confidence primary or complementary
mapping exists.

## Current scope and limitations

Phase 1 covers the Windows Server host-firewall, SMB, LDAP, NTLM, WinRM, RDP,
malware-protection, and privileged-execution/credential boundary sets. Mapping
is deterministic and intentionally conservative. It cannot infer undocumented
deployment architecture, compensating controls, or organization-specific attack
paths. Future extensions can add versioned capability and attack-path rules,
additional benchmark technologies, and analyst-reviewed mappings without
changing the parser or introducing a graph database.

