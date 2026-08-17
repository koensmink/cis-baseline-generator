from __future__ import annotations

import re

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
    "authentication": (
        "authentication", "password", "multifactor", "multi-factor", "mfa",
        "sign-in", "reauthentication", "authentication transfer", "device trust",
    ),
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
        managed_device_dependency = _requires_managed_device(text)
        if managed_device_dependency or any(term in text for term in feature_terms):
            deployment = DeploymentScope.CONDITIONAL
            status = FamilyApplicabilityStatus.MANDATORY_WHEN_FEATURE_DEPLOYED
        elif any(term in text for term in ("specific resource", "selected resources", "user action")):
            deployment = DeploymentScope.FEATURE_SPECIFIC
            status = FamilyApplicabilityStatus.APPLICABLE
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
        scope = _evaluation_scope(control)
        risk_adaptive = "risk" in title and "risk" in behavior
        rules: tuple[tuple[str, str, str, tuple[str, ...], str, bool], ...] = (
            (
                "SEM-WEAK-PLAINTEXT-AUTHENTICATION",
                "authentication",
                "legacy or weak authentication rejected",
                ("Basic or plaintext authentication rejected",),
                "standalone_primary_boundary",
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
                ,
            ),
            (
                "SEM-PASSWORD-AUTHENTICATION-STRENGTH",
                "authentication",
                "password recovery authentication reconfirmed",
                ("weak password selection constrained",),
                "boundary_set_core_member",
                any(term in title for term in ("password", "sspr"))
                and "password" in behavior
                and "authentication" in behavior,
            ),
            (
                "SEM-PRIVILEGED-ROLE-ACTIVATION",
                "privileged_role_activation",
                "privileged activation independently approved",
                ("activation independently approved",),
                "boundary_set_core_member",
                "approval is required" in title
                and "privileged" in title
                and "activation" in title
                and "approval" in behavior
                and "activation" in behavior,
            ),
            (
                "SEM-MULTIFACTOR-AUTHENTICATION",
                "authentication",
                "multifactor authentication enforced for the stated access scope",
                (
                    "additional independent authentication factor",
                    "authentication enforcement scope",
                    "authentication bypass resistance",
                ),
                "standalone_primary_boundary",
                _mfa_enforcement(behavior) and not risk_adaptive,
            ),
            (
                "SEM-PHISHING-RESISTANT-AUTHENTICATION",
                "authentication",
                "phishing-resistant authentication enforced",
                (
                    "cryptographic verifier binding",
                    "origin or channel binding",
                    "credential replay and proxy resistance",
                ),
                "standalone_primary_boundary",
                _phishing_resistant_enforcement(behavior),
            ),
            (
                "SEM-AUTHENTICATION-STRENGTH",
                "authentication",
                "minimum authentication strength enforced",
                (
                    "minimum authentication strength selected",
                    "authentication enforcement scope",
                    "weaker authentication methods rejected",
                ),
                "standalone_primary_boundary",
                _authentication_strength_enforcement(behavior),
            ),
            (
                "SEM-AUTHENTICATION-STRENGTH",
                "authentication",
                "selected weak authentication methods disabled",
                ("weaker authentication methods rejected",),
                "supporting_hardening",
                _weak_method_hardening(behavior),
            ),
            (
                "SEM-SESSION-ASSURANCE",
                "authentication",
                "authentication freshness and protected continuation enforced",
                _session_assurance_effects(behavior),
                "boundary_set_core_member",
                _session_assurance(behavior) and not risk_adaptive,
            ),
            (
                "SEM-AUTHENTICATION-SESSION-BINDING",
                "authentication",
                "authenticated state remains bound to its originating context",
                _session_binding_effects(behavior),
                "standalone_primary_boundary",
                _session_binding(behavior),
            ),
            (
                "SEM-MANAGED-DEVICE-AUTHENTICATION-TRUST",
                "authentication",
                "managed-device trust enforced during authentication",
                _managed_device_effects(behavior),
                "boundary_set_core_member",
                _managed_device_trust(behavior),
            ),
        )
        candidates: list[BoundaryCandidate] = []
        for mapping, domain, effect, sub_boundaries, role, matches in rules:
            if matches:
                candidates.append(
                    BoundaryCandidate(
                        semantic_mapping_id=mapping,
                        semantic_domain=domain,
                        security_effect=effect,
                        evidence=(f"domain:{domain}", f"effect:{effect}"),
                        satisfied_sub_boundaries=sub_boundaries,
                        boundary_role=role,
                        non_compensable=True,
                        evaluation_scope=scope,
                        attack_path_ids=_candidate_attack_paths(mapping, behavior),
                    )
                )
        if risk_adaptive:
            if _mfa_enforcement(behavior):
                candidates.append(
                    BoundaryCandidate(
                        semantic_mapping_id="SEM-MULTIFACTOR-AUTHENTICATION",
                        semantic_domain="authentication",
                        security_effect="risk-triggered multifactor challenge",
                        evidence=("domain:authentication", "effect:risk-triggered multifactor challenge"),
                        satisfied_sub_boundaries=("additional independent authentication factor",),
                        boundary_role="risk_adaptive_enhancement",
                        non_compensable=False,
                        evaluation_scope=scope,
                        attack_path_ids=("AP-017",),
                    )
                )
            if _session_assurance(behavior):
                candidates.append(
                    BoundaryCandidate(
                        semantic_mapping_id="SEM-SESSION-ASSURANCE",
                        semantic_domain="authentication",
                        security_effect="risk-triggered revalidation",
                        evidence=("domain:authentication", "effect:risk-triggered revalidation"),
                        satisfied_sub_boundaries=("risk or event driven revalidation",),
                        boundary_role="risk_adaptive_enhancement",
                        non_compensable=False,
                        evaluation_scope=scope,
                        attack_path_ids=("AP-020",),
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
        for value in (
            control.description,
            control.rationale,
            control.remediation,
            control.applicability,
        )
    )


def _all_behavior(control: ControlRecord) -> str:
    return f"{control.title.lower()} {_behavior(control)}"


def _contains_all(text: str, groups: tuple[tuple[str, ...], ...]) -> bool:
    return all(any(_contains_term(text, term) for term in group) for group in groups)


def _contains_term(text: str, term: str) -> bool:
    if " " in term or "-" in term:
        return term in text
    return re.search(rf"\b{re.escape(term)}\b", text) is not None


def _mfa_enforcement(text: str) -> bool:
    enforced = any(
        phrase in text
        for phrase in (
            "require multifactor",
            "requires multifactor",
            "enforce multifactor",
            "multifactor authentication is enabled",
            "multifactor authentication for all",
            "require mfa",
            "enforce mfa",
        )
    )
    return enforced and _contains_all(
        text,
        (("multifactor", "multi-factor", "mfa"), ("second factor", "two separate", "additional form")),
    )


def _phishing_resistant_enforcement(text: str) -> bool:
    return _contains_all(text, (("phishing-resistant", "phishing resistant"), ("require", "requires", "required", "enforce", "enforces", "enforced"), ("fido", "passkey", "certificate-based", "cryptographic")))


def _authentication_strength_enforcement(text: str) -> bool:
    explicit_strength = _contains_all(text, (("authentication strength",), ("require", "requires", "required", "enforce", "enforces", "enforced"), ("block", "reject", "allowed methods", "stronger method")))
    return explicit_strength


def _weak_method_hardening(text: str) -> bool:
    return _contains_all(
        text,
        (
            ("weak authentication methods", "sms", "voice call"),
            ("disable", "disabled"),
            ("phishing", "sim swapping", "intercepted"),
        ),
    )


def _session_assurance(text: str) -> bool:
    return _contains_all(text, (("reauthentication", "sign-in frequency"), ("require", "requires", "required", "enforce", "enforces", "enforced", "every time")))


def _session_assurance_effects(text: str) -> tuple[str, ...]:
    effects = ["reauthentication freshness"]
    if any(term in text for term in ("persistent browser", "session continuation", "never persistent")):
        effects.append("protected session continuation")
    if any(term in text for term in ("risk change", "sign-in risk", "user risk", "context change")):
        effects.append("risk or event driven revalidation")
    return tuple(effects)


def _session_binding(text: str) -> bool:
    return _contains_all(text, (("authentication transfer", "session transfer"), ("block", "prevent"), ("device", "browser", "session")))


def _session_binding_effects(text: str) -> tuple[str, ...]:
    effects = ["authentication transfer prohibited"]
    if any(term in text for term in ("original device", "originating device", "device tokens")):
        effects.append("authenticated state bound to originating context")
    if any(term in text for term in ("token theft", "token replay", "replay attacks")):
        effects.append("session token replay resistance")
    return tuple(effects)


def _managed_device_trust(text: str) -> bool:
    return _contains_all(text, (("managed device", "compliant device", "hybrid joined device"), ("authentication", "sign-in"), ("require", "requires", "required", "enforce", "enforces", "enforced")))


def _managed_device_effects(text: str) -> tuple[str, ...]:
    effects = ["trusted device identity"]
    if any(term in text for term in ("compliance status", "marked as compliant", "device-state", "device state")):
        effects.append("device state assertion")
    if any(term in text for term in ("conditional access", "before authentication", "authentication is permitted", "qualify for authentication")):
        effects.append("device trust policy enforced at authentication")
    return tuple(effects)


def _requires_managed_device(text: str) -> bool:
    return _managed_device_trust(text) and any(
        term in text
        for term in ("enrolled", "enrollment", "compliance polic", "hybrid joined", "device management")
    )


def _evaluation_scope(control: ControlRecord) -> str:
    text = _all_behavior(control)
    if "intune enrollment" in text:
        resource = "application:intune_enrollment"
    elif "all resources" in text or "all cloud apps" in text:
        resource = "tenant:all_resources"
    elif "exchange online" in text:
        resource = "service:exchange_online"
    elif "sharepoint" in text:
        resource = "service:sharepoint"
    elif "streaming and push datasets" in text or "resourcekey" in text:
        resource = "feature:power_bi_streaming_push"
    else:
        resource = "benchmark"
    title = control.title.lower()
    if "administrative roles" in title or "administrative users" in title:
        subject = "administrative_roles"
    elif "user risk" in title:
        subject = "high_user_risk"
    elif "sign-in risk" in title:
        subject = "medium_high_sign_in_risk"
    elif "all users" in title or "all users" in text:
        subject = "all_users"
    else:
        subject = "stated_subjects"
    return f"{resource}|{subject}"


def _candidate_attack_paths(mapping_id: str, behavior: str) -> tuple[str, ...]:
    if mapping_id == "SEM-WEAK-PLAINTEXT-AUTHENTICATION" and "resourcekey" in behavior:
        return ("AP-022",)
    return ()
