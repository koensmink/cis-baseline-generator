from __future__ import annotations

import re
from typing import Annotated, TypeAlias

from pydantic import StringConstraints

CapabilityId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^CAP-[0-9]{2,3}$")]
BoundaryId: TypeAlias = Annotated[
    str, StringConstraints(pattern=r"^BND-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
]
BoundarySetId: TypeAlias = Annotated[
    str, StringConstraints(pattern=r"^BS-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
]
BoundaryEvaluationId: TypeAlias = Annotated[
    str, StringConstraints(pattern=r"^BEV-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
]
ThreatScenarioId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^TS-[0-9]{3,}$")]
TechniqueId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^TEC-[0-9]{3,}$")]
AttackPathId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^AP-[0-9]{3,}$")]
OutcomeId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^OUT-[0-9]{3,}$")]
RiskId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^RISK-[0-9]{3,}$")]
MappingId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^MAP-[0-9]{3,}$")]
MandatoryDecisionId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^MD-[0-9]{3,}$")]

IDENTIFIER_PATTERNS = {
    "CAP": re.compile(r"^CAP-[0-9]{2,3}$"),
    "BND": re.compile(r"^BND-[A-Z0-9]+(?:-[A-Z0-9]+)*$"),
    "BS": re.compile(r"^BS-[A-Z0-9]+(?:-[A-Z0-9]+)*$"),
    "BEV": re.compile(r"^BEV-[A-Z0-9]+(?:-[A-Z0-9]+)*$"),
    "TS": re.compile(r"^TS-[0-9]{3,}$"),
    "TEC": re.compile(r"^TEC-[0-9]{3,}$"),
    "AP": re.compile(r"^AP-[0-9]{3,}$"),
    "OUT": re.compile(r"^OUT-[0-9]{3,}$"),
    "RISK": re.compile(r"^RISK-[0-9]{3,}$"),
    "MAP": re.compile(r"^MAP-[0-9]{3,}$"),
    "MD": re.compile(r"^MD-[0-9]{3,}$"),
}


def validate_identifier(value: str) -> str:
    """Validate without normalizing; malformed or lowercase IDs are rejected."""
    prefix = value.split("-", 1)[0] if "-" in value else ""
    pattern = IDENTIFIER_PATTERNS.get(prefix)
    if pattern is None or pattern.fullmatch(value) is None:
        raise ValueError(f"Invalid or unknown security-knowledge identifier: {value!r}")
    return value

