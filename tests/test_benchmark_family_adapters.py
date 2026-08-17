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
    assert unknown.family == "unknown" and unknown.finding == "BENCHMARK_FAMILY_UNSUPPORTED"
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
    assert by_id["2.1"].mapping_gap_category == (
        "qualifying_security_effect_catalog_mapping_missing"
    )
    assert by_id["2.2"].normative_proposal == "Regular Control"
    assert by_id["2.2"].mapping_gap_category == "optional_non_mandatory_enrichment"
