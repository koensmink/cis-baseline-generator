from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .evidence import EvidenceItem, EvidenceType
from .identifiers import BoundaryId, TechniqueId, ThreatScenarioId
from .provenance import CatalogObjectProvenance, Confidence, LifecycleStatus


class ThreatScenario(BaseModel):
    model_config = ConfigDict(frozen=True)

    threat_scenario_id: ThreatScenarioId
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    attacker_position: str = Field(min_length=1)
    preconditions: list[str] = Field(min_length=1)
    targeted_assets: list[str] = Field(min_length=1)
    abused_weakness: str = Field(min_length=1)
    attacker_objective: str = Field(min_length=1)
    immediate_outcome: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    technique_ids: list[TechniqueId] = Field(default_factory=list)
    boundary_ids: list[BoundaryId] = Field(min_length=1)
    lifecycle_status: LifecycleStatus
    confidence: Confidence
    provenance: CatalogObjectProvenance
    evidence: list[EvidenceItem] = Field(default_factory=list)

    @model_validator(mode="after")
    def active_scenario_is_complete(self) -> ThreatScenario:
        if self.lifecycle_status == LifecycleStatus.ACTIVE and not self.evidence:
            raise ValueError("Active ThreatScenario requires evidence")
        return self


_PROVENANCE = CatalogObjectProvenance(
    catalog_authority="cis-pdf2csv security knowledge",
    catalog_version="1.0",
    object_version="1.0",
    creation_method="deterministic curated catalog",
    rationale_sources=["Security Knowledge Model"],
)


def _scenario(
    number: int,
    name: str,
    position: str,
    weakness: str,
    objective: str,
    outcome: str,
    boundary_id: str,
) -> ThreatScenario:
    scenario_id = f"TS-{number:03d}"
    evidence = EvidenceItem(
        evidence_type=EvidenceType.CURATED_SECURITY,
        source="Security Knowledge Model",
        locator=f"initial scenario catalog:{scenario_id}",
        assertion=f"{weakness} enables {objective}",
        collection_method="deterministic catalog definition",
        confidence=Confidence.HIGH,
    )
    return ThreatScenario(
        threat_scenario_id=scenario_id,
        name=name,
        description=f"An attacker {position} exploits {weakness} to {objective}.",
        attacker_position=position,
        preconditions=[weakness],
        targeted_assets=["protected systems and security data"],
        abused_weakness=weakness,
        attacker_objective=objective,
        immediate_outcome=outcome,
        impact=outcome,
        boundary_ids=[boundary_id],
        lifecycle_status=LifecycleStatus.ACTIVE,
        confidence=Confidence.HIGH,
        provenance=_PROVENANCE,
        evidence=[evidence],
    )


THREAT_SCENARIOS = (
    _scenario(1, "Intercepted authentication exchange", "with a network interception position", "an authentication exchange without adequate integrity", "relay a trusted identity", "unauthorized authentication", "BND-IDENTITY-AUTHENTICATION"),
    _scenario(2, "Credential memory extraction", "with local execution", "credential material accessible in operating-system memory", "extract reusable credentials", "credential theft", "BND-CREDENTIAL-MEMORY"),
    _scenario(3, "Administrative lateral movement", "with access to a peer host", "an inadequately restricted administrative protocol", "move to another managed host", "lateral movement", "BND-NETWORK-ADMINISTRATION"),
    _scenario(4, "Remote-management abuse", "with network reachability", "an inadequately protected management interface", "obtain remote administrative execution", "remote system control", "BND-REMOTE-MANAGEMENT"),
    _scenario(5, "Untrusted code execution", "able to deliver active content", "an unrestricted execution surface", "execute malicious code", "unauthorized code execution", "BND-EXECUTION-CONTROL"),
    _scenario(6, "Protection disablement", "with local configuration influence", "a malware protection stack that can be evaded or disabled", "suppress active protection", "persistent malicious execution", "BND-MALWARE-PROTECTION"),
    _scenario(7, "Unauthorized inbound reachability", "with network access", "an open inbound host path", "reach an unauthorized service", "unauthorized network access", "BND-NETWORK-INBOUND"),
    _scenario(8, "Weak elevation consent", "with user-context execution", "an absent or spoofable elevation boundary", "obtain privileged execution", "privilege escalation", "BND-PRIVILEGE-ELEVATION"),
    _scenario(9, "Recoverable credential storage", "with access to stored security material", "plaintext or weakly protected credential storage", "recover reusable credentials", "credential disclosure", "BND-CREDENTIAL-STORAGE"),
    _scenario(10, "Security evidence suppression", "able to affect telemetry", "missing or suppressible security-event evidence", "prevent detection or investigation", "loss of forensic evidence", "BND-MONITORING-EVIDENCE"),
)

THREAT_SCENARIO_BY_ID = {item.threat_scenario_id: item for item in THREAT_SCENARIOS}
