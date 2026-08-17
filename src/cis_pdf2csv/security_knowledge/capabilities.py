from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .identifiers import CapabilityId
from .provenance import CatalogObjectProvenance, LifecycleStatus


class SecurityCapability(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability_id: CapabilityId
    name: str = Field(min_length=1)
    definition: str = Field(min_length=1)
    security_objective: str = Field(min_length=1)
    examples: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    lifecycle_status: LifecycleStatus
    catalog_version: str = Field(min_length=1)
    provenance: CatalogObjectProvenance

    @property
    def description(self) -> str:
        """Deprecated Phase-1 alias for definition."""
        return self.definition


_PROVENANCE = CatalogObjectProvenance(
    catalog_authority="cis-pdf2csv security knowledge",
    catalog_version="1.0",
    object_version="1.0",
    creation_method="authoritative model catalog",
    rationale_sources=["Security Knowledge Model section 5"],
)


def _capability(
    number: int,
    name: str,
    definition: str,
    objective: str,
    examples: list[str],
    exclusions: list[str],
) -> SecurityCapability:
    return SecurityCapability(
        capability_id=f"CAP-{number:02d}",
        name=name,
        definition=definition,
        security_objective=objective,
        examples=examples,
        exclusions=exclusions,
        lifecycle_status=LifecycleStatus.ACTIVE,
        catalog_version="1.0",
        provenance=_PROVENANCE,
    )


CAPABILITIES = (
    _capability(1, "Identity and authentication protection", "Validates identities and resists weak or intercepted authentication.", "Only adequately verified identities cross an access boundary.", ["strong authentication", "legacy credential refusal"], ["account naming", "identity display"]),
    _capability(2, "Credential protection", "Prevents credential material and reusable derivatives from disclosure, extraction, or unsafe retention.", "Reusable authentication material remains confidential.", ["isolated secrets", "non-reversible storage"], ["password cosmetics", "authentication logging alone"]),
    _capability(3, "Privileged execution control", "Mediates and restricts transitions into privileged execution contexts.", "Administrative authority is granted only through an enforced elevation boundary.", ["elevation consent", "privileged-token mediation"], ["general account management", "malware scanning alone"]),
    _capability(4, "Network boundary protection", "Restricts network paths and traffic crossing a protected-system boundary.", "Unauthorized connectivity cannot reach protected assets.", ["default-deny inbound policy", "segmentation"], ["network logging alone", "notifications"]),
    _capability(5, "Secure remote management", "Protects authentication, authorization, and transport for remote administration channels.", "Management interfaces cannot be abused through an inadequately protected channel.", ["protected management transport", "strong remote authentication"], ["session usability", "temporary-folder handling"]),
    _capability(6, "Application and code execution control", "Restricts whether untrusted applications, scripts, and active content may execute.", "Unauthorized code does not obtain an execution path.", ["allowlisting", "script restriction"], ["detection after execution", "inventory alone"]),
    _capability(7, "Malware prevention and response", "Prevents, contains, and responds to malicious software behavior.", "Active protection remains capable of blocking malicious execution and evasion.", ["real-time protection", "behavior monitoring"], ["scan scheduling", "notifications"]),
    _capability(8, "Cryptographic and transport protection", "Provides confidentiality, integrity, and peer authenticity for stored or transmitted information.", "Protected information cannot be read or modified through a weak channel.", ["signing", "sealing", "approved encryption"], ["mere mention of encryption", "audit-only checks"]),
    _capability(9, "Security monitoring and investigation", "Preserves security visibility and evidence needed to detect and investigate harmful activity.", "Material security events remain observable and reconstructable.", ["essential audit source", "tamper-resistant logging"], ["log cosmetics", "redundant telemetry"]),
    _capability(10, "Data protection", "Protects data against unauthorized disclosure, alteration, and loss throughout its lifecycle.", "Data security properties are preserved according to sensitivity and use.", ["storage protection", "integrity enforcement"], ["generic availability tuning"]),
)

CAPABILITY_BY_ID = {item.capability_id: item for item in CAPABILITIES}
