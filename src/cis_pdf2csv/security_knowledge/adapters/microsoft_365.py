from __future__ import annotations

from cis_pdf2csv.schema import ControlRecord

from .base import (
    BenchmarkFamily,
    BenchmarkFamilyAdapter,
    BoundaryCandidate,
    DeploymentScope,
    FamilyApplicabilityStatus,
    LicenseScope,
    NormalizedApplicability,
)

DOMAIN_TERMS: dict[str, tuple[str, ...]] = {
    "authentication": ("authentication", "password", "multifactor", "mfa", "sign-in"),
    "privileged_role_activation": ("role activation", "privileged role", "eligible role"),
    "application_registration_and_consent": ("register applications", "application consent", "admin consent"),
    "external_collaboration_and_guest_trust": ("guest", "external collaboration", "external user"),
    "mail_security": ("dmarc", "dkim", "spf", "anti-phishing", "anti-spam", "mail flow"),
    "auditing_and_retention": ("audit", "retention"),
    "data_protection": ("dlp", "data loss prevention", "sensitivity label"),
    "service_principal_authorization": ("service principal",),
    "meeting_federation_cross_tenant": ("meeting", "federation", "cross-tenant", "external teams"),
}


class Microsoft365Adapter(BenchmarkFamilyAdapter):
    family = BenchmarkFamily.MICROSOFT_365_FOUNDATIONS

    def supports(self, control: ControlRecord) -> bool:
        name = control.benchmark_name.lower()
        applicability = (control.applicability or "").lower()
        return "microsoft 365" in name or (
            ("e3 level" in applicability or "e5 level" in applicability)
            and any(term in _all_behavior(control) for term in ("tenant", "entra", "exchange online", "sharepoint", "teams"))
        )

    def normalize_applicability(self, control: ControlRecord) -> NormalizedApplicability:
        applicability = (control.applicability or "").upper()
        has_e3 = "E3" in applicability
        has_e5 = "E5" in applicability
        license_scope = (
            LicenseScope.E3_OR_E5
            if has_e3 and has_e5
            else LicenseScope.E3
            if has_e3
            else LicenseScope.E5
            if has_e5
            else LicenseScope.UNKNOWN
        )
        text = _all_behavior(control)
        service_terms = ("exchange", "sharepoint", "onedrive", "teams", "power bi")
        feature_terms = ("if enabled", "when deployed", "when configured", "feature is used")
        if any(term in text for term in feature_terms):
            deployment = DeploymentScope.CONDITIONAL
            status = FamilyApplicabilityStatus.MANDATORY_WHEN_FEATURE_DEPLOYED
        elif any(term in text for term in service_terms):
            deployment = DeploymentScope.SERVICE_SPECIFIC
            status = FamilyApplicabilityStatus.APPLICABLE
        elif license_scope != LicenseScope.UNKNOWN:
            deployment = DeploymentScope.TENANT_WIDE
            status = FamilyApplicabilityStatus.APPLICABLE
        else:
            deployment = DeploymentScope.UNKNOWN
            status = FamilyApplicabilityStatus.UNRESOLVED
        return NormalizedApplicability(
            license_scope=license_scope,
            deployment_scope=deployment,
            applicability_status=status,
        )

    def derive_semantic_subjects(self, control: ControlRecord) -> tuple[str, ...]:
        text = _all_behavior(control)
        return tuple(
            domain for domain, terms in DOMAIN_TERMS.items() if any(term in text for term in terms)
        )

    def identify_boundary_candidates(self, control: ControlRecord) -> tuple[BoundaryCandidate, ...]:
        title = control.title.lower()
        behavior = _behavior(control)
        rules = (
            (
                "SEM-WEAK-PLAINTEXT-AUTHENTICATION",
                "authentication",
                "legacy or weak authentication rejected",
                any(
                    term in title
                    for term in (
                        "legacy authentication",
                        "modern authentication",
                        "weak authentication methods",
                        "resourcekey authentication",
                    )
                )
                and any(
                    term in behavior
                    for term in (
                        "legacy authentication",
                        "modern authentication",
                        "weak authentication",
                        "resourcekey",
                    )
                )
                or (
                    "weak authentication methods" in title
                    and "authentication methods" in behavior
                    and ("disable" in behavior or "disabled" in behavior)
                ),
            ),
            (
                "SEM-PASSWORD-AUTHENTICATION-STRENGTH",
                "authentication",
                "password recovery authentication reconfirmed",
                any(term in title for term in ("password", "sspr"))
                and "password" in behavior
                and "authentication" in behavior,
            ),
            (
                "SEM-PRIVILEGED-ROLE-ACTIVATION",
                "privileged_role_activation",
                "privileged activation independently approved",
                "approval is required" in title
                and "privileged" in title
                and "activation" in title
                and "approval" in behavior
                and "activation" in behavior,
            ),
        )
        candidates: list[BoundaryCandidate] = []
        for mapping, domain, effect, matches in rules:
            if matches:
                candidates.append(
                    BoundaryCandidate(
                        semantic_mapping_id=mapping,
                        semantic_domain=domain,
                        security_effect=effect,
                        evidence=(f"domain:{domain}", f"effect:{effect}"),
                    )
                )
        return tuple(candidates)

    def classify_security_role(self, control: ControlRecord) -> str:
        domains = self.derive_semantic_subjects(control)
        return "classification_relevant" if domains else "enrichment_optional"

    def extract_family_specific_evidence(self, control: ControlRecord) -> tuple[str, ...]:
        return tuple(value for value in (control.description, control.rationale, control.remediation) if value)


def _behavior(control: ControlRecord) -> str:
    return " ".join(
        (value or "").lower()
        for value in (control.description, control.rationale, control.remediation)
    )


def _all_behavior(control: ControlRecord) -> str:
    return f"{control.title.lower()} {_behavior(control)}"
