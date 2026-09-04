from __future__ import annotations

import pytest

from cis_pdf2csv.mandatory.shadow import assess_controls_shadow
from cis_pdf2csv.parser import detect_benchmark_identity
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.adapters import (
    BenchmarkFamily,
    DeploymentScope,
    FamilyApplicabilityStatus,
    LicenseScope,
    select_adapter,
)
from cis_pdf2csv.security_knowledge.adapters.microsoft_365 import Microsoft365Adapter


def invented_control(**changes: object) -> ControlRecord:
    values: dict[str, object] = {
        "benchmark_name": "Invented Microsoft 365 Foundations Benchmark",
        "benchmark_version": "1.0",
        "benchmark_date": "2026",
        "control_id": "1.2.3",
        "profile": "L1",
        "title": "Configure an invented tenant safeguard",
        "assessment": "Automated",
        "applicability": "E3 Level 1 and E5 Level 1",
        "description": "The invented tenant safeguard enforces the described behavior.",
        "rationale": "The safeguard closes an invented security path.",
        "audit": "Inspect the invented tenant configuration.",
        "remediation": "Configure the invented tenant safeguard.",
        "page_start": 1,
        "page_end": 2,
        "source_pdf_sha256": "a" * 64,
        "block_text_sha256": "b" * 64,
        "extracted_at_utc": "2026-01-01T00:00:00Z",
    }
    values.update(changes)
    return ControlRecord.model_validate(values)


def test_benchmark_identity_detection_is_evidence_based() -> None:
    windows = detect_benchmark_identity(["CIS Microsoft Windows Server 2025 Benchmark"])
    cloud = detect_benchmark_identity(["CIS Microsoft 365 Foundations Benchmark"])
    unknown = detect_benchmark_identity(["Invented CIS Product Benchmark"])
    ambiguous = detect_benchmark_identity(
        [
            "CIS Microsoft Windows Server 2025 Benchmark",
            "CIS Microsoft 365 Foundations Benchmark",
        ]
    )
    assert windows.family == "microsoft-windows-server"
    assert cloud.family == "microsoft-365-foundations"
    assert unknown.family == "unknown" and unknown.finding is None
    assert unknown.benchmark_name == "CIS Product Benchmark"
    assert ambiguous.family == "ambiguous" and ambiguous.finding == "BENCHMARK_FAMILY_AMBIGUOUS"
    assert unknown.benchmark_name != "CIS Microsoft Windows Server Benchmark"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("E3 Level 1", LicenseScope.E3),
        ("E5 Level 1", LicenseScope.E5),
        ("E3 Level 1 and E5 Level 1", LicenseScope.E3_OR_E5),
        ("Unknown subscription", LicenseScope.UNKNOWN),
    ],
)
def test_m365_license_scope(text: str, expected: LicenseScope) -> None:
    applicability = Microsoft365Adapter().normalize_applicability(
        invented_control(applicability=text)
    )
    assert applicability.license_scope == expected


def test_m365_license_scope_does_not_imply_feature_deployment() -> None:
    applicability = Microsoft365Adapter().normalize_applicability(
        invented_control(
            applicability="E5 Level 1",
            description="The safeguard applies when the optional feature is used.",
        )
    )
    assert applicability.deployment_scope == DeploymentScope.CONDITIONAL
    assert (
        applicability.applicability_status
        == FamilyApplicabilityStatus.MANDATORY_WHEN_FEATURE_DEPLOYED
    )


def test_adapter_selection_requires_exactly_one_match() -> None:
    cloud = select_adapter(invented_control())
    ambiguous = select_adapter(
        invented_control(
            benchmark_name="Invented Microsoft 365 Windows Server Benchmark",
            applicability="Unknown subscription",
        )
    )
    unsupported = select_adapter(
        invented_control(
            benchmark_name="Invented Database Benchmark",
            applicability="Unknown subscription",
        )
    )
    assert cloud.family == BenchmarkFamily.MICROSOFT_365_FOUNDATIONS
    assert ambiguous.family == BenchmarkFamily.AMBIGUOUS
    assert unsupported.family == BenchmarkFamily.UNKNOWN


@pytest.mark.parametrize(
    ("description", "domain"),
    [
        ("Tenant authentication resists credential misuse.", "authentication"),
        ("Approval protects privileged role activation.", "privileged_role_activation"),
        ("The admin consent workflow governs application consent.", "application_registration_and_consent"),
        ("External collaboration restricts each guest identity.", "external_collaboration_and_guest_trust"),
        ("DMARC and anti-phishing controls protect mail flow.", "mail_security"),
        ("Audit retention preserves investigation evidence.", "auditing_and_retention"),
        ("DLP and sensitivity labels protect tenant data.", "data_protection"),
        ("Service principal access is explicitly authorized.", "service_principal_authorization"),
        ("Cross-tenant meeting federation is restricted.", "meeting_federation_cross_tenant"),
    ],
)
def test_m365_semantic_domain_recognition(description: str, domain: str) -> None:
    subjects = Microsoft365Adapter().derive_semantic_subjects(
        invented_control(description=description)
    )
    assert domain in subjects


def test_m365_mapping_requires_behavior_not_title_audit_or_references() -> None:
    adapter = Microsoft365Adapter()
    item = invented_control(
        title="Block legacy authentication",
        description="An invented tenant preference.",
        rationale="The preference standardizes configuration.",
        remediation="Configure the preference.",
        audit="Verify that legacy authentication is blocked.",
        references="https://example.test/legacy-authentication",
    )
    assert adapter.identify_boundary_candidates(item) == ()


def test_missing_relevant_mapping_reviews_but_optional_gap_is_non_blocking() -> None:
    relevant = invented_control(
        control_id="2.1",
        title="Require a managed device for authentication",
        description="Tenant authentication requires a managed device trust decision.",
        rationale="Unmanaged devices otherwise reach protected tenant resources.",
        remediation="Require managed-device authentication.",
    )
    optional = invented_control(
        control_id="2.2",
        title="Configure an invented tenant preference",
    )
    result = assess_controls_shadow(reversed([relevant, optional]))
    by_id = {item.control_id: item for item in result.shadow_assessments}
    assert by_id["2.1"].normative_proposal == "Review Required"
    assert by_id["2.1"].normative_boundary_definition_ids == (
        "BND-IDENTITY-MANAGED-DEVICE-TRUST",
    )
    assert "SHADOW-INCOMPLETE-BOUNDARY" in by_id["2.1"].difference_codes
    assert by_id["2.2"].normative_proposal == "Regular Control"
    assert by_id["2.2"].mapping_gap_category == "optional_non_mandatory_enrichment"


@pytest.mark.parametrize(
    ("description", "rationale", "remediation", "mapping_id"),
    [
        (
            "Access requires an additional form of identification.",
            "Two separate factors prevent password-only entry.",
            "Enforce multifactor authentication for every protected resource.",
            "SEM-MULTIFACTOR-AUTHENTICATION",
        ),
        (
            "A phishing-resistant cryptographic authenticator is used.",
            "Verifier and origin binding prevent proxy and replay attacks.",
            "Require a FIDO passkey for the protected service.",
            "SEM-PHISHING-RESISTANT-AUTHENTICATION",
        ),
        (
            "Access policy defines an authentication strength.",
            "Allowed methods must meet the stronger method policy.",
            "Require the authentication strength and reject weaker methods.",
            "SEM-AUTHENTICATION-STRENGTH",
        ),
        (
            "Sign-in frequency limits authenticated session age.",
            "Stolen token use is reduced through reauthentication.",
            "Require periodic reauthentication for continued access.",
            "SEM-SESSION-ASSURANCE",
        ),
        (
            "Authentication transfer can move state to another device.",
            "Binding to the original device prevents token replay.",
            "Block authentication transfer between browser sessions.",
            "SEM-AUTHENTICATION-SESSION-BINDING",
        ),
        (
            "Authentication evaluates managed device compliance status.",
            "Only trusted device identity should reach resources.",
            "Require a compliant device through conditional access at sign-in.",
            "SEM-MANAGED-DEVICE-AUTHENTICATION-TRUST",
        ),
    ],
)
def test_m365_identity_semantic_recognition(
    description: str, rationale: str, remediation: str, mapping_id: str
) -> None:
    candidates = Microsoft365Adapter().identify_boundary_candidates(
        invented_control(
            title="Configure an invented identity safeguard",
            description=description,
            rationale=rationale,
            remediation=remediation,
        )
    )
    assert mapping_id in {item.semantic_mapping_id for item in candidates}


def test_m365_identity_mapping_ignores_title_audit_and_reference_only_evidence() -> None:
    adapter = Microsoft365Adapter()
    item = invented_control(
        title="Require phishing-resistant multifactor authentication and session binding",
        description="An invented preference is documented.",
        rationale="The preference standardizes administration.",
        remediation="Save the invented preference.",
        audit="Verify authentication strength, reauthentication, and managed device trust.",
        references="https://example.test/identity",
    )
    assert adapter.identify_boundary_candidates(item) == ()


def test_m365_device_entitlement_does_not_resolve_managed_device_deployment() -> None:
    item = invented_control(
        applicability="E3 Level 1 and E5 Level 1",
        description="Authentication evaluates managed device compliance status after enrollment.",
        rationale="A trusted device identity is required.",
        remediation="Require a compliant device through conditional access at sign-in.",
    )
    applicability = Microsoft365Adapter().normalize_applicability(item)
    assert applicability.license_scope == LicenseScope.E3_OR_E5
    assert applicability.deployment_scope == DeploymentScope.CONDITIONAL
    assert applicability.applicability_status == FamilyApplicabilityStatus.MANDATORY_WHEN_FEATURE_DEPLOYED


def test_complete_mfa_boundary_can_be_candidate_but_incomplete_session_is_review() -> None:
    complete = invented_control(
        control_id="8.1",
        title="Require an invented access verification safeguard",
        description="Access requires an additional form of identification.",
        rationale="Two separate factors prevent password-only entry and bypass.",
        remediation="Enforce multifactor authentication for every protected resource without exclusions.",
    )
    incomplete = invented_control(
        control_id="8.2",
        title="Require an invented session safeguard",
        description="Sign-in frequency limits authenticated session age.",
        rationale="Stale authentication can permit continued access.",
        remediation="Require periodic reauthentication.",
    )
    result = assess_controls_shadow(reversed([complete, incomplete]))
    by_id = {item.control_id: item for item in result.shadow_assessments}
    assert by_id["8.1"].normative_proposal == "Candidate Mandatory"
    assert by_id["8.2"].normative_proposal == "Review Required"
    assert assess_controls_shadow([complete, incomplete]).model_dump() == result.model_dump()


def test_one_control_maps_atomically_to_two_independent_boundaries() -> None:
    item = invented_control(
        control_id="8.3",
        title="Require an invented authentication and session safeguard",
        description=(
            "Access requires an additional form of identification. Sign-in frequency limits "
            "authenticated session age and the persistent browser session is disabled."
        ),
        rationale=(
            "Two separate factors prevent password-only entry and protected session "
            "continuation prevents stale browser access."
        ),
        remediation=(
            "Enforce multifactor authentication for every protected resource without "
            "exclusions; require periodic reauthentication and never persistent browser sessions."
        ),
    )
    result = assess_controls_shadow([item])
    assessment = result.shadow_assessments[0]
    assert assessment.normative_boundary_definition_ids == (
        "BND-IDENTITY-MULTIFACTOR-AUTHENTICATION",
        "BND-IDENTITY-SESSION-ASSURANCE",
    )
    assert {mapping.boundary_definition_id for mapping in result.mitigation_mappings} == set(
        assessment.normative_boundary_definition_ids
    )
    assert all(len({mapping.boundary_definition_id}) == 1 for mapping in result.mitigation_mappings)
    assert assessment.normative_proposal == "Candidate Mandatory"


def test_complete_second_boundary_survives_incomplete_first_boundary() -> None:
    item = invented_control(
        control_id="8.4",
        title="Require an invented authentication and session safeguard",
        description=(
            "Access requires an additional form of identification. Sign-in frequency limits "
            "authenticated session age."
        ),
        rationale="Two separate factors prevent password-only entry and bypass.",
        remediation=(
            "Enforce multifactor authentication for every protected resource without exclusions "
            "and require periodic reauthentication."
        ),
    )
    assessment = assess_controls_shadow([item]).shadow_assessments[0]
    assert assessment.normative_proposal == "Candidate Mandatory"
    assert "SHADOW-INCOMPLETE-BOUNDARY" in assessment.difference_codes
    assert not any(
        finding.code == "BOUNDARY_EVALUATION_INCOMPLETE"
        for finding in assessment.validation_findings
    )


def test_weak_method_hardening_is_supporting_only() -> None:
    item = invented_control(
        control_id="8.5",
        title="Disable invented weak authentication methods",
        description="SMS and voice call authentication methods are weak.",
        rationale="Phishing can intercept SMS and SIM swapping can redirect it.",
        remediation="Disable SMS and voice call authentication methods.",
    )
    assessment = assess_controls_shadow([item]).shadow_assessments[0]
    assert assessment.normative_proposal == "Regular Control"


def test_equivalent_narrower_alternative_does_not_duplicate_mandatory() -> None:
    tenant = invented_control(
        control_id="8.6",
        title="Block invented legacy authentication for all users",
        description="The tenant rejects legacy authentication exchanges.",
        rationale="Legacy authentication permits replayable credentials.",
        remediation="Block legacy authentication for all users and all resources.",
    )
    service = invented_control(
        control_id="8.7",
        title="Block invented legacy authentication for Exchange Online",
        description="Exchange Online rejects legacy authentication exchanges.",
        rationale="Legacy authentication permits replayable credentials.",
        remediation="Block legacy authentication for Exchange Online users.",
    )
    by_id = {
        item.control_id: item for item in assess_controls_shadow([service, tenant]).shadow_assessments
    }
    assert by_id["8.6"].normative_proposal == "Candidate Mandatory"
    assert by_id["8.7"].normative_proposal == "Regular Control"


def test_session_complementary_effects_do_not_cross_scope() -> None:
    freshness = invented_control(
        control_id="8.8",
        title="Require periodic reauthentication for all users",
        description="Sign-in frequency limits authenticated session age.",
        rationale="Stale authentication permits continued access.",
        remediation="Require periodic reauthentication for all users and all resources.",
    )
    continuation = invented_control(
        control_id="8.9",
        title="Disable persistent browser sessions for administrative users",
        description="The persistent browser session retains authenticated state.",
        rationale="Protected session continuation prevents unattended browser access.",
        remediation="Require reauthentication and set never persistent for administrative users.",
    )
    by_id = {
        item.control_id: item
        for item in assess_controls_shadow([freshness, continuation]).shadow_assessments
    }
    assert by_id["8.8"].normative_proposal == "Review Required"
    assert by_id["8.9"].normative_proposal == "Candidate Mandatory"


def test_mapping_order_is_deterministic_for_multiple_boundaries() -> None:
    first = invented_control(
        control_id="8.10",
        title="Require an invented tenant authentication safeguard",
        description="Access requires an additional form of identification.",
        rationale="Two separate factors prevent password-only entry and bypass.",
        remediation="Enforce multifactor authentication for every protected resource without exclusions.",
    )
    second = invented_control(
        control_id="8.11",
        title="Block invented authentication transfer",
        description="Authentication transfer moves a session to another device.",
        rationale="The original device binding prevents token replay.",
        remediation="Block authentication transfer between browser sessions.",
    )
    assert assess_controls_shadow([first, second]).model_dump() == assess_controls_shadow(
        [second, first]
    ).model_dump()


@pytest.mark.parametrize(
    ("description", "rationale", "remediation", "mapping_id", "boundary_id"),
    [
        (
            "Application registration is restricted to an approved role.",
            "Accountable ownership prevents attacker-controlled application identities.",
            "Restrict application identity creation to an authorized role and require an owner.",
            "SEM-APPLICATION-REGISTRATION-AUTHORIZATION",
            "BND-IDENTITY-APPLICATION-REGISTRATION-AUTHORIZATION",
        ),
        (
            "User consent is restricted and privileged application permissions require admin consent.",
            "Independent administrator approval prevents excessive permission grants.",
            "Block untrusted application consent, require approval, and constrain permission scope to least privilege.",
            "SEM-APPLICATION-CONSENT-AUTHORIZATION",
            "BND-IDENTITY-APPLICATION-CONSENT-AUTHORIZATION",
        ),
        (
            "Each service principal is explicitly authorized with minimum permissions.",
            "A stale app-only permission permits excessive resource access.",
            "Enforce least privilege, approved role assignment, and review and revoke unused authorization.",
            "SEM-SERVICE-PRINCIPAL-AUTHORIZATION",
            "BND-IDENTITY-SERVICE-PRINCIPAL-AUTHORIZATION",
        ),
        (
            "A federated workload identity validates its issuer, subject, and audience.",
            "Claim binding prevents a token from another workload context being accepted.",
            "Restrict and validate the issuer, subject, and audience of each federated identity credential.",
            "SEM-WORKLOAD-IDENTITY-TRUST",
            "BND-IDENTITY-WORKLOAD-IDENTITY-TRUST",
        ),
    ],
)
def test_m365_application_and_workload_identity_complete_boundaries(
    description: str,
    rationale: str,
    remediation: str,
    mapping_id: str,
    boundary_id: str,
) -> None:
    item = invented_control(
        title="Configure an invented application identity safeguard",
        description=description,
        rationale=rationale,
        remediation=remediation,
    )
    candidates = Microsoft365Adapter().identify_boundary_candidates(item)
    assert {candidate.semantic_mapping_id for candidate in candidates} == {mapping_id}
    assessment = assess_controls_shadow([item]).shadow_assessments[0]
    assert assessment.normative_boundary_definition_ids == (boundary_id,)
    assert assessment.normative_proposal == "Candidate Mandatory"


def test_m365_application_consent_incomplete_concept_requires_review() -> None:
    item = invented_control(
        control_id="8.12",
        title="Configure an invented consent safeguard",
        description="Application consent and privileged permissions require admin consent.",
        rationale="Administrator approval prevents an unreviewed permission grant.",
        remediation="Require approval for application permission grants.",
    )
    assessment = assess_controls_shadow([item]).shadow_assessments[0]
    assert assessment.normative_proposal == "Review Required"
    assert "SHADOW-INCOMPLETE-BOUNDARY" in assessment.difference_codes


def test_m365_application_and_workload_mapping_is_not_title_only() -> None:
    item = invented_control(
        title="Restrict application registration, admin consent, service principals, and workload identity",
        description="An invented tenant preference is documented.",
        rationale="The preference standardizes configuration.",
        remediation="Configure the preference.",
        audit="Verify all privileged application permissions are restricted.",
        references="https://example.test/workload-identity",
    )
    assert Microsoft365Adapter().identify_boundary_candidates(item) == ()


def test_m365_application_and_workload_shadow_slice_counts() -> None:
    complete = [
        invented_control(
            control_id="10.1",
            description="Application registration is restricted to an approved role.",
            rationale="Accountable ownership prevents attacker-controlled application identities.",
            remediation="Restrict application identity creation to an authorized role and require an owner.",
        ),
        invented_control(
            control_id="10.2",
            description="User consent is restricted and privileged application permissions require admin consent.",
            rationale="Independent administrator approval prevents excessive permission grants.",
            remediation="Block untrusted application consent, require approval, and constrain permission scope to least privilege.",
        ),
        invented_control(
            control_id="10.3",
            description="Each service principal is explicitly authorized with minimum permissions.",
            rationale="A stale app-only permission permits excessive resource access.",
            remediation="Enforce least privilege, approved role assignment, and review and revoke unused authorization.",
        ),
        invented_control(
            control_id="10.4",
            description="A federated workload identity validates its issuer, subject, and audience.",
            rationale="Claim binding prevents a token from another workload context being accepted.",
            remediation="Restrict and validate the issuer, subject, and audience of each federated identity credential.",
        ),
    ]
    incomplete = invented_control(
        control_id="10.5",
        title="Configure consent for administrative users",
        description="Application consent and privileged permissions require admin consent.",
        rationale="Administrator approval prevents an unreviewed permission grant.",
        remediation="Require approval for application permission grants.",
    )
    title_only = invented_control(
        control_id="10.6",
        title="Restrict application registration, consent, service principals, and workload identity",
    )
    proposals = [
        item.normative_proposal
        for item in assess_controls_shadow([*complete, incomplete, title_only]).shadow_assessments
    ]
    assert proposals.count("Candidate Mandatory") == 4
    assert proposals.count("Review Required") == 1
    assert proposals.count("Regular Control") == 1
