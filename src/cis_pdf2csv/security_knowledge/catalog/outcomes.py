from __future__ import annotations

from .capabilities import PROVENANCE
from .registry import SecurityOutcome

_OUTCOMES = (
    ("OUT-001", "Unauthorized network access"), ("OUT-002", "Unauthorized authentication"),
    ("OUT-003", "Credential theft"), ("OUT-004", "Privilege escalation"),
    ("OUT-005", "Lateral movement"), ("OUT-006", "Remote code execution"),
    ("OUT-007", "Malware execution"), ("OUT-008", "Security protection impairment"),
    ("OUT-009", "Loss of confidentiality"), ("OUT-010", "Loss of integrity"),
    ("OUT-011", "Loss of availability"), ("OUT-012", "Administrative or domain compromise"),
    ("OUT-013", "Loss of forensic evidence"), ("OUT-014", "Unauthorized data access"),
)

SECURITY_OUTCOMES = tuple(
    SecurityOutcome(
        outcome_id=identifier, name=name,
        description=f"A reusable technical outcome in which an attack causes {name.lower()}.",
        technical_impact=name, provenance=PROVENANCE,
    )
    for identifier, name in _OUTCOMES
)
