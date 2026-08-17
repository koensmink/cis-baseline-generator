from __future__ import annotations

from cis_pdf2csv.schema import ControlRecord

from .base import (
    BenchmarkFamily,
    BenchmarkFamilyAdapter,
    BoundaryCandidate,
    DeploymentScope,
    FamilyApplicabilityStatus,
    NormalizedApplicability,
)


class WindowsServerAdapter(BenchmarkFamilyAdapter):
    family = BenchmarkFamily.MICROSOFT_WINDOWS_SERVER

    def supports(self, control: ControlRecord) -> bool:
        name = control.benchmark_name.lower()
        applicability = (control.applicability or "").lower()
        return "windows server" in name and "e3 level" not in applicability and "e5 level" not in applicability

    def normalize_applicability(self, control: ControlRecord) -> NormalizedApplicability:
        text = f"{control.title} {control.applicability or ''}".lower()
        conditional = any(
            term in text
            for term in ("remote desktop", "rdp", "winrm", "defender", "antivirus", "edr")
        )
        return NormalizedApplicability(
            deployment_scope=(DeploymentScope.CONDITIONAL if conditional else DeploymentScope.TENANT_WIDE),
            applicability_status=(
                FamilyApplicabilityStatus.MANDATORY_WHEN_FEATURE_DEPLOYED
                if conditional
                else FamilyApplicabilityStatus.APPLICABLE
            ),
        )

    def derive_semantic_subjects(self, control: ControlRecord) -> tuple[str, ...]:
        text = _behavior(control)
        subjects = (
            "smb", "ldap", "ntlm", "winrm", "rdp", "windows_firewall", "defender", "uac"
        )
        return tuple(item for item in subjects if item.replace("_", " ") in text)

    def identify_boundary_candidates(self, control: ControlRecord) -> tuple[BoundaryCandidate, ...]:
        title = control.title.lower()
        behavior = _behavior(control)
        rules = (
            ("SEM-PASSWORD-AUTHENTICATION-STRENGTH", "authentication", "password authentication strength", "password must meet complexity requirements", "password"),
            ("SEM-EXTERNAL-IDENTITY-AUTHENTICATION", "authentication", "external identity trust rejection", "consumer microsoft account user authentication", "consumer"),
            ("SEM-EXTERNAL-IDENTITY-AUTHENTICATION", "authentication", "peer online identity trust rejection", "pku2u authentication", "pku2u"),
            ("SEM-WEAK-PLAINTEXT-AUTHENTICATION", "authentication", "Basic authentication rejection", "basic", "basic authentication"),
        )
        return tuple(
            BoundaryCandidate(
                semantic_mapping_id=mapping,
                semantic_domain=domain,
                security_effect=effect,
                evidence=(f"title:{title_term}", f"behavior:{behavior_term}"),
            )
            for mapping, domain, effect, title_term, behavior_term in rules
            if title_term in title and behavior_term in behavior
        )

    def classify_security_role(self, control: ControlRecord) -> str:
        return "product_specific_host_boundary"

    def extract_family_specific_evidence(self, control: ControlRecord) -> tuple[str, ...]:
        return tuple(value for value in (control.description, control.rationale, control.remediation) if value)


def _behavior(control: ControlRecord) -> str:
    return " ".join(
        (value or "").lower()
        for value in (control.description, control.rationale, control.remediation)
    )
