from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .identifiers import (
    AttackPathId,
    BoundaryId,
    OutcomeId,
    TechniqueId,
    ThreatScenarioId,
)
from .provenance import CatalogObjectProvenance, Confidence, LifecycleStatus


class AttackPath(BaseModel):
    model_config = ConfigDict(frozen=True)

    attack_path_id: AttackPathId
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    ordered_stages: list[str] = Field(min_length=1)
    entry_conditions: list[str] = Field(min_length=1)
    intermediate_conditions: list[str] = Field(default_factory=list)
    attacker_goals: list[str] = Field(min_length=1)
    affected_assets: list[str] = Field(min_length=1)
    security_outcome_ids: list[OutcomeId] = Field(min_length=1)
    threat_scenario_ids: list[ThreatScenarioId] = Field(default_factory=list)
    technique_ids: list[TechniqueId] = Field(default_factory=list)
    boundary_ids: list[BoundaryId] = Field(min_length=1)
    residual_path_description: str = Field(min_length=1)
    lifecycle_status: LifecycleStatus
    confidence: Confidence
    provenance: CatalogObjectProvenance

    @model_validator(mode="after")
    def active_path_has_scenario(self) -> AttackPath:
        if self.lifecycle_status == LifecycleStatus.ACTIVE and not self.threat_scenario_ids:
            raise ValueError("Active AttackPath requires at least one ThreatScenario reference")
        return self

    @property
    def stages(self) -> list[str]:
        """Deprecated Phase-1 alias."""
        return self.ordered_stages

    @property
    def security_outcomes(self) -> list[str]:
        """Deprecated Phase-1 alias."""
        return list(self.security_outcome_ids)

    @property
    def mitre_technique_ids(self) -> list[str]:
        """Deprecated Phase-1 alias; MITRE IDs now live on technique mappings."""
        return []


_PROVENANCE = CatalogObjectProvenance(
    catalog_authority="cis-pdf2csv security knowledge",
    catalog_version="1.0",
    object_version="1.0",
    creation_method="deterministic curated catalog",
    rationale_sources=["Security Knowledge Model"],
)


def _path(
    number: int,
    name: str,
    description: str,
    stages: list[str],
    assets: list[str],
    boundary_id: str,
) -> AttackPath:
    path_id = f"AP-{number:03d}"
    return AttackPath(
        attack_path_id=path_id,
        name=name,
        description=description,
        ordered_stages=stages,
        entry_conditions=[f"The conditions of TS-{number:03d} are present"],
        intermediate_conditions=["The relevant security boundary is not fully enforced"],
        attacker_goals=[name.lower()],
        affected_assets=assets,
        security_outcome_ids=[f"OUT-{number:03d}"],
        threat_scenario_ids=[f"TS-{number:03d}"],
        boundary_ids=[boundary_id],
        residual_path_description="The path remains open when its required boundary effect is omitted.",
        lifecycle_status=LifecycleStatus.ACTIVE,
        confidence=Confidence.HIGH,
        provenance=_PROVENANCE,
    )


ATTACK_PATHS = (
    _path(1, "Credential relay and authentication interception", "An attacker intercepts or relays authentication exchanges to impersonate a trusted identity.", ["credential access", "authentication", "lateral movement"], ["identity providers", "network services", "credentials"], "BND-IDENTITY-AUTHENTICATION"),
    _path(2, "Credential extraction from operating-system memory", "An attacker with local execution reads credential secrets or derivatives from protected operating-system processes.", ["execution", "privilege escalation", "credential access"], ["operating-system memory", "credential authority", "administrative credentials"], "BND-CREDENTIAL-MEMORY"),
    _path(3, "Lateral movement over administrative protocols", "An attacker uses an administrative network protocol to move from one system to another.", ["authentication", "lateral movement"], ["managed hosts", "administrative protocols"], "BND-NETWORK-ADMINISTRATION"),
    _path(4, "Abuse of remote-management interfaces", "An attacker reaches or misuses a remote administration interface to control a system.", ["initial access", "authentication", "execution"], ["remote management services", "managed hosts"], "BND-REMOTE-MANAGEMENT"),
    _path(5, "Malicious code and script execution", "Untrusted executable content reaches an execution surface and runs on the system.", ["delivery", "execution"], ["applications", "scripts", "host processes"], "BND-EXECUTION-CONTROL"),
    _path(6, "Malware evasion and protection disablement", "Malware evades behavioral prevention or disables protection so malicious activity can persist.", ["defense evasion", "persistence", "impact"], ["malware protection stack", "host"], "BND-MALWARE-PROTECTION"),
    _path(7, "Unauthorized inbound network access", "Unsolicited or unauthorized network traffic crosses the host boundary and reaches a service.", ["reconnaissance", "initial access"], ["host network boundary", "listening services"], "BND-NETWORK-INBOUND"),
    _path(8, "Privilege elevation through weak consent boundaries", "Code obtains administrative execution through absent, bypassable, or spoofable elevation consent.", ["execution", "privilege escalation"], ["administrative tokens", "elevation interface"], "BND-PRIVILEGE-ELEVATION"),
    _path(9, "Plaintext or weakly protected credential storage", "Reusable credentials or weak derivatives remain recoverable from storage or delegated state.", ["credential access", "collection"], ["credential stores", "delegated credentials", "password derivatives"], "BND-CREDENTIAL-STORAGE"),
    _path(10, "Security-event suppression or loss of forensic evidence", "Relevant security activity is not recorded or retained, preventing detection or investigation.", ["defense evasion", "detection", "investigation"], ["security logs", "audit pipeline"], "BND-MONITORING-EVIDENCE"),
)

ATTACK_PATH_BY_ID = {item.attack_path_id: item for item in ATTACK_PATHS}
