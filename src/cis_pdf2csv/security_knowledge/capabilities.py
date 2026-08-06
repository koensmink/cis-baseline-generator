from __future__ import annotations

from .schema import SecurityCapability

CAPABILITIES = (
    SecurityCapability(capability_id="CAP-01", name="Identity and authentication protection", description="Validates identities and resists weak or intercepted authentication independently of implementation technology."),
    SecurityCapability(capability_id="CAP-02", name="Credential protection", description="Prevents credential material and reusable derivatives from disclosure, extraction, or unsafe retention."),
    SecurityCapability(capability_id="CAP-03", name="Privileged execution control", description="Mediates and restricts transitions into privileged execution contexts."),
    SecurityCapability(capability_id="CAP-04", name="Network boundary protection", description="Restricts network paths and traffic crossing a protected-system boundary."),
    SecurityCapability(capability_id="CAP-05", name="Secure remote management", description="Protects authentication, authorization, and transport for remote administration channels."),
    SecurityCapability(capability_id="CAP-06", name="Application and code execution control", description="Restricts whether untrusted applications, scripts, and active content may execute."),
    SecurityCapability(capability_id="CAP-07", name="Malware prevention and response", description="Prevents, contains, and responds to malicious software behavior."),
    SecurityCapability(capability_id="CAP-08", name="Cryptographic and transport protection", description="Provides confidentiality, integrity, and peer authenticity for stored or transmitted information."),
    SecurityCapability(capability_id="CAP-09", name="Security monitoring and investigation", description="Preserves security visibility and evidence needed to detect and investigate harmful activity."),
    SecurityCapability(capability_id="CAP-10", name="Data protection", description="Protects data against unauthorized disclosure, alteration, and loss throughout its lifecycle."),
)

CAPABILITY_BY_ID = {item.capability_id: item for item in CAPABILITIES}

