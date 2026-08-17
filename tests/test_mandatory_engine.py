from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any

import pytest

from cis_pdf2csv.mandatory.cli import main as mandatory_main
from cis_pdf2csv.mandatory.criteria import CRITERIA, match_criteria
from cis_pdf2csv.mandatory.exporters import (
    write_assessment_csv,
    write_shadow_comparison,
    write_summary_json,
)
from cis_pdf2csv.mandatory.features import extract_features
from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.mandatory.shadow import (
    assess_controls_shadow,
    compare_shadow_assessments,
)
from cis_pdf2csv.schema import ControlRecord


def control(control_id: str = "1.1", title: str = "Require firewall protection", **changes: Any) -> ControlRecord:
    values: dict[str, Any] = {
        "benchmark_name": "Invented Microsoft Windows Server Benchmark",
        "benchmark_version": "v1.0",
        "benchmark_date": "January 2026",
        "control_id": control_id,
        "profile": "L1",
        "title": title,
        "assessment": "Automated",
        "applicability": "All invented server systems",
        "description": "This invented setting controls firewall enforcement.",
        "rationale": "A firewall blocks untrusted inbound connections at the network boundary.",
        "impact": "Approved traffic must be documented.",
        "audit": "Query the invented firewall state and verify it is enabled.",
        "remediation": "Enable the invented firewall policy.",
        "default_value": "Disabled",
        "references": "Invented reference SEC-1",
        "page_start": 10,
        "page_end": 11,
        "source_pdf_sha256": "a" * 64,
        "block_text_sha256": "b" * 64,
        "extracted_at_utc": "2026-01-01T00:00:00Z",
        "parser_version": "0.4.1",
    }
    values.update(changes)
    return ControlRecord.model_validate(values)


@pytest.mark.parametrize(
    ("code", "phrase"),
    [
        ("MC-CRIT-001", "Disable the legacy SMBv1 mechanism"),
        ("MC-CRIT-002", "Require multi-factor authentication"),
        ("MC-CRIT-003", "Protect privileged access for administrator accounts"),
        ("MC-CRIT-004", "Enable Credential Guard credential protection"),
        ("MC-CRIT-005", "Restrict run as administrator elevated execution"),
        ("MC-CRIT-006", "Deny direct remote desktop access"),
        ("MC-CRIT-007", "Block macro execution and script execution"),
        ("MC-CRIT-008", "Enforce network boundary protection"),
        ("MC-CRIT-009", "Require firewall enforcement"),
        ("MC-CRIT-010", "Require TLS transport protection"),
        ("MC-CRIT-011", "Require code signing"),
        ("MC-CRIT-012", "Require storage encryption"),
        ("MC-CRIT-013", "Enable application sandboxing"),
        ("MC-CRIT-014", "Enforce application control allowlisting"),
        ("MC-CRIT-015", "Enable essential security audit logging"),
        ("MC-CRIT-016", "Enable real-time malware protection"),
    ],
)
def test_every_mandatory_criterion_has_a_stable_match(code: str, phrase: str) -> None:
    assert code in match_criteria(phrase)
    assert code in {criterion.code for criterion in CRITERIA}


def neutral_control(**changes: Any) -> ControlRecord:
    values: dict[str, Any] = {
        "title": "Configure invented preference",
        "description": "An invented preference is configured.",
        "rationale": "The invented preference provides consistent behavior.",
        "impact": "The preference becomes consistent.",
        "audit": "Inspect the invented preference.",
        "remediation": "Configure the invented preference.",
        "default_value": "Unset",
    }
    values.update(changes)
    return control(**values)


def test_https_in_references_cannot_activate_transport_protection() -> None:
    features = extract_features(
        neutral_control(references="See https://standards.example.test/citation")
    )
    assert "https" not in features.criterion_text
    assert "https" in features.supporting_evidence_text
    assert "MC-CRIT-010" not in match_criteria(features.criterion_text)


def test_security_terms_only_in_audit_cannot_activate_a_criterion() -> None:
    features = extract_features(
        neutral_control(audit="Verify TLS transport protection and firewall status.")
    )
    assert "transport protection" not in features.criterion_text
    assert "transport protection" in features.supporting_evidence_text
    assert match_criteria(features.criterion_text) == []


@pytest.mark.parametrize("field", ["title", "rationale", "remediation"])
def test_behavior_fields_can_activate_transport_criterion(field: str) -> None:
    features = extract_features(
        neutral_control(**{field: "Require TLS transport protection."})
    )
    assert "MC-CRIT-010" in match_criteria(features.criterion_text)


@pytest.mark.parametrize(
    ("changes", "failure"),
    [
        ({"control_id": ""}, "ELIG-001"),
        ({"title": ""}, "ELIG-002"),
        ({"profile": "Unknown"}, "ELIG-003"),
        ({"assessment": "Manual", "audit": None}, "ELIG-004"),
        ({"rationale": None}, "ELIG-005"),
        ({"applicability": "Where applicable to invented systems"}, "ELIG-006"),
    ],
)
def test_formal_eligibility_failures_require_review(changes: dict[str, Any], failure: str) -> None:
    assessment = assess_controls([control(**changes)])[0]
    assert assessment.proposal == "Review Required"
    assert failure in (assessment.review_note or "")


@pytest.mark.parametrize(
    ("text", "code", "proposal"),
    [
        ("This is additional defense in depth firewall protection.", "EXCL-001", "Regular Control"),
        ("Hide a firewall notification for user experience.", "EXCL-002", "Regular Control"),
        ("Set the firewall timeout threshold.", "EXCL-003", "Regular Control"),
        ("Firewall behavior is environment dependent.", "EXCL-004", "Regular Control"),
        ("An alternative control provides equivalent protection for this firewall.", "EXCL-005", "Regular Control"),
        ("Firewall rationale without complete evidence.", "EXCL-006", "Review Required"),
        ("Use the firewall where applicable.", "EXCL-007", "Review Required"),
    ],
)
def test_every_exclusion_rule_blocks_candidate(text: str, code: str, proposal: str) -> None:
    changes: dict[str, Any] = {"rationale": text}
    if code == "EXCL-006":
        changes["audit"] = None
    if code == "EXCL-007":
        changes["applicability"] = text
    assessment = assess_controls([control(**changes)])[0]
    assert assessment.proposal == proposal
    assert any(reason.startswith(code) for reason in assessment.exclusion_reasons)


def test_complete_primary_control_is_candidate_mandatory() -> None:
    assessment = assess_controls([control()])[0]
    assert assessment.proposal == "Candidate Mandatory"
    assert assessment.confidence == "High"
    assert assessment.non_compensable_reason
    assert assessment.benchmark_evidence


def test_related_grouping_and_primary_versus_supporting() -> None:
    primary = control("3.2.1", "Require firewall network boundary protection")
    supporting = control(
        "3.2.2",
        "Configure additional firewall reporting",
        description="Supporting firewall reporting enhances the primary boundary.",
        rationale="Additional firewall reporting is defense in depth.",
    )
    results = {item.control_id: item for item in assess_controls([supporting, primary])}
    assert results["3.2.2"].control_id in results["3.2.1"].related_control_ids
    assert results["3.2.1"].relationship == "standalone primary boundary"
    assert results["3.2.2"].relationship == "supporting hardening"
    assert results["3.2.2"].proposal == "Regular Control"


def test_fine_tuning_related_control_is_excluded() -> None:
    items = [
        control("4.1.1", "Require security audit logging"),
        control("4.1.2", "Set security audit log retention period"),
    ]
    result = {item.control_id: item for item in assess_controls(items)}["4.1.2"]
    assert result.relationship == "fine-tuning"
    assert result.proposal == "Regular Control"


def test_candidate_requires_high_confidence() -> None:
    assessment = assess_controls([control(rationale=None)])[0]
    assert assessment.confidence != "High"
    assert assessment.proposal != "Candidate Mandatory"


def test_no_minimum_count_bias() -> None:
    regular = [
        control(str(index), f"Configure invented cosmetic preference {index}", rationale="This preference changes user experience.")
        for index in range(1, 21)
    ]
    assert not [item for item in assess_controls(regular) if item.proposal == "Candidate Mandatory"]


def test_repeatability_is_independent_of_input_order() -> None:
    first = control("2.1", "Require firewall network boundary protection")
    second = control("2.2", "Configure additional firewall reporting")
    forward = [item.model_dump() for item in assess_controls([first, second])]
    reverse = [item.model_dump() for item in assess_controls([second, first])]
    assert forward == reverse


def test_benchmark_sized_analysis_is_fast_and_functionally_stable() -> None:
    # Five seconds is intentionally generous for a 450-control local/CI unit
    # benchmark while still preventing the previous roughly one-minute runtime.
    controls = [
        neutral_control(
            control_id=f"100.{index}.1",
            title=f"token{index:04d}",
            description=f"token{index:04d}",
            rationale=f"token{index:04d}",
            impact=f"token{index:04d}",
            audit=f"token{index:04d}",
            remediation=f"token{index:04d}",
        )
        for index in range(450)
    ]
    controls.extend(
        [
            control("200.1.1", "Require firewall network boundary protection"),
            control(
                "200.1.2",
                "Configure additional firewall reporting",
                description="Supporting firewall reporting enhances the primary boundary.",
                rationale="Additional firewall reporting is defense in depth.",
            ),
        ]
    )

    started = time.perf_counter()
    results = assess_controls(reversed(controls))
    duration = time.perf_counter() - started
    by_id = {item.control_id: item for item in results}

    assert len(results) == 452
    assert duration < 5.0
    assert by_id["200.1.1"].proposal == "Candidate Mandatory"
    assert by_id["200.1.1"].relationship == "standalone primary boundary"
    assert by_id["200.1.2"].proposal == "Regular Control"
    assert by_id["200.1.2"].relationship == "supporting hardening"
    assert all(by_id[f"100.{index}.1"].proposal == "Regular Control" for index in range(450))


def test_windows_server_l1_false_positive_regression_fixture() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "mandatory_windows_server_l1_regression.json"
    cases: list[dict[str, Any]] = json.loads(fixture_path.read_text(encoding="utf-8"))
    controls = [
        neutral_control(
            control_id=case["control_id"],
            title=case["title"],
            description=case["title"],
            rationale=case["rationale"],
            remediation=case["title"],
            applicability=case.get("applicability", "All invented server systems"),
        )
        for case in cases
    ]

    forward = {item.control_id: item for item in assess_controls(controls)}
    reverse = {item.control_id: item for item in assess_controls(reversed(controls))}
    assert [item.model_dump() for item in forward.values()] == [
        item.model_dump() for item in reverse.values()
    ]
    for case in cases:
        assessment = forward[case["control_id"]]
        assert assessment.proposal == case["expected_proposal"]
        assert assessment.relationship == case["expected_relationship"]
        if assessment.proposal == "Candidate Mandatory":
            assert assessment.non_compensable_reason
            assert "If omitted" in assessment.non_compensable_reason
            assert "non-compensable" in assessment.non_compensable_reason


def set_control(control_id: str, title: str) -> ControlRecord:
    return neutral_control(
        control_id=control_id,
        title=title,
        description=f"{title} directly enforces its named security effect.",
        rationale=f"{title} closes a distinct attack path in the minimum effective boundary.",
        remediation=title,
    )


def assert_complete_core_set(
    controls: list[ControlRecord],
    boundary_set_id: str,
) -> dict[str, Any]:
    results = assess_controls(controls)
    assert all(item.proposal == "Candidate Mandatory" for item in results)
    assert all(item.relationship == "boundary-set core member" for item in results)
    assert all(item.boundary_set_id == boundary_set_id for item in results)
    assert all(item.overlap_type in {"none", "complementary"} for item in results)
    for item in results:
        assert item.enforced_sub_boundary
        assert item.attack_path_if_omitted
        assert item.remaining_members_cannot_compensate
        assert item.related_core_member_ids
    return {item.control_id: item.model_dump() for item in results}


def test_complete_and_incomplete_firewall_boundary_sets() -> None:
    enabled = set_control("9.1.1", "Windows Firewall Domain firewall state enabled")
    inbound = set_control("9.1.2", "Windows Firewall Domain inbound connections block by default")
    complete = assert_complete_core_set(
        [enabled, inbound],
        "BS-HOST-FIREWALL-DOMAIN",
    )
    assert complete["9.1.1"]["overlap_type"] == "complementary"

    incomplete = assess_controls([enabled])[0]
    assert incomplete.proposal == "Review Required"
    assert "default_inbound_block" in (incomplete.review_note or "")


def test_smb_version_and_signing_are_complementary_core_members() -> None:
    assert_complete_core_set(
        [
            set_control("18.6.1", "Require minimum supported SMB version"),
            set_control("18.6.2", "Require SMB signing"),
        ],
        "BS-SMB-SECURITY",
    )


def test_ldap_signing_and_encryption_are_complementary_core_members() -> None:
    assert_complete_core_set(
        [
            set_control("2.3.1", "Require LDAP signing"),
            set_control("2.3.2", "Require LDAP encryption"),
        ],
        "BS-LDAP-SECURITY",
    )


def test_ntlm_authentication_and_session_security_form_a_boundary() -> None:
    assert_complete_core_set(
        [
            set_control("2.3.3", "Refuse LM credentials and refuse NTLM credentials"),
            set_control("2.3.4", "Require NTLM minimum session security with 128-bit session encryption"),
        ],
        "BS-NTLM-SESSION",
    )


def test_winrm_encrypted_management_is_mandatory_when_deployed() -> None:
    results = assert_complete_core_set(
        [
            set_control("18.10.1", "Disable WinRM Basic authentication"),
            set_control("18.10.2", "Disable WinRM unencrypted traffic"),
            set_control("18.10.3", "WinRM credential storage is disabled"),
        ],
        "BS-WINRM-SECURITY",
    )
    assert all(item["applicability_mode"] == "mandatory_when_deployed" for item in results.values())


def test_winrm_client_and_service_controls_are_complementary_not_duplicates() -> None:
    controls = [
        set_control("18.10.1", "Disable WinRM Client Basic authentication"),
        set_control("18.10.2", "Disable WinRM Service Basic authentication"),
        set_control("18.10.3", "Disable WinRM Client unencrypted traffic"),
        set_control("18.10.4", "Disable WinRM Service unencrypted traffic"),
    ]
    results = assert_complete_core_set(controls, "BS-WINRM-SECURITY")
    assert all(item["overlap_type"] == "complementary" for item in results.values())


def test_rdp_secure_access_boundary_is_mandatory_when_deployed() -> None:
    results = assert_complete_core_set(
        [
            set_control("18.10.4", "Require Network Level Authentication for RDP connections"),
            set_control("18.10.5", "Require SSL security layer for RDP connections"),
            set_control("18.10.6", "Require RDP high encryption level"),
        ],
        "BS-RDP-SECURITY",
    )
    assert all(item["applicability_mode"] == "mandatory_when_deployed" for item in results.values())


def test_defender_minimum_protection_stack_excludes_supplemental_scans() -> None:
    core = [
        set_control("18.10.7", "Enable real-time malware protection"),
        set_control("18.10.8", "Enable behavior monitoring"),
        set_control("18.10.9", "Enable network protection in block mode"),
        set_control("18.10.10", "Enable EDR in block mode"),
    ]
    results = assert_complete_core_set(core, "BS-MALWARE-PROTECTION")
    assert all(item["applicability_mode"] == "mandatory_when_deployed" for item in results.values())

    scan = assess_controls([neutral_control(title="Schedule Defender removable-drive scans")])[0]
    assert scan.proposal == "Regular Control"
    assert scan.relationship == "supporting hardening"

    oobe = assess_controls(
        [neutral_control(title="Configure real-time protection during OOBE")]
    )[0]
    assert oobe.proposal == "Regular Control"
    assert oobe.relationship == "supporting hardening"


def test_duplicate_effect_requires_review_but_complementary_effect_does_not() -> None:
    results = {
        item.control_id: item
        for item in assess_controls(
            [
                set_control("9.2.1", "Windows Firewall Private firewall state enabled"),
                set_control("9.2.2", "Windows Firewall Private firewall enabled"),
                set_control("9.2.3", "Windows Firewall Private inbound connections block by default"),
            ]
        )
    }
    assert results["9.2.1"].proposal == "Review Required"
    assert results["9.2.2"].proposal == "Review Required"
    assert results["9.2.1"].overlap_type == "duplicate"
    assert results["9.2.3"].proposal == "Candidate Mandatory"
    assert results["9.2.3"].overlap_type == "complementary"


def test_shadow_exact_match_and_complete_complementary_boundary() -> None:
    controls = [
        set_control("90.1", "Windows Firewall Domain firewall state enabled"),
        set_control("90.2", "Windows Firewall Domain inbound connections block by default"),
    ]
    result = assess_controls_shadow(controls)
    assert [item.proposal for item in result.legacy_assessments] == [
        "Candidate Mandatory",
        "Candidate Mandatory",
    ]
    assert all(item.normative_proposal == "Candidate Mandatory" for item in result.shadow_assessments)
    assert all(item.proposals_match and item.cutover_eligible for item in result.shadow_assessments)
    evaluation = result.boundary_evaluations[0]
    assert evaluation.completeness_status == "complete_complementary_core_set"
    assert evaluation.satisfied_sub_boundaries == evaluation.required_sub_boundaries
    assert not evaluation.missing_sub_boundaries

    mappings_by_control = {
        control_id: {
            item.enforced_sub_boundary
            for item in result.mitigation_mappings
            if item.control_id == control_id
        }
        for control_id in ("90.1", "90.2")
    }
    assert mappings_by_control == {
        "90.1": {"stateful firewall enforcement"},
        "90.2": {"default-deny inbound policy"},
    }


def test_shadow_missing_mapping_and_incomplete_boundary_require_review() -> None:
    missing = assess_controls_shadow([control(title="Require firewall protection")])
    item = missing.shadow_assessments[0]
    assert item.normative_proposal == "Review Required"
    assert "SHADOW-MISSING-CATALOG-MAPPING" in item.difference_codes

    incomplete = assess_controls_shadow(
        [set_control("91.1", "Windows Firewall Domain firewall state enabled")]
    )
    item = incomplete.shadow_assessments[0]
    assert item.normative_proposal == "Review Required"
    assert "SHADOW-INCOMPLETE-BOUNDARY" in item.difference_codes


def test_shadow_supporting_control_remains_regular_and_legacy_is_unchanged() -> None:
    controls = [
        control("92.1", "Require firewall network boundary protection"),
        control(
            "92.2",
            "Configure additional firewall reporting",
            description="Supporting firewall reporting enhances the primary boundary.",
            rationale="Additional firewall reporting is defense in depth.",
        ),
    ]
    before = [item.model_dump() for item in assess_controls(controls)]
    shadow = assess_controls_shadow(controls)
    after = [item.model_dump() for item in shadow.legacy_assessments]
    assert after == before
    supporting = next(item for item in shadow.shadow_assessments if item.control_id == "92.2")
    assert supporting.legacy_proposal == supporting.normative_proposal == "Regular Control"


def test_shadow_export_is_deterministic_and_cli_requires_opt_in(tmp_path: Path) -> None:
    controls = [
        set_control("93.1", "Windows Firewall Domain firewall state enabled"),
        set_control("93.2", "Windows Firewall Domain inbound connections block by default"),
    ]
    input_path = tmp_path / "controls.jsonl"
    input_path.write_text("\n".join(item.model_dump_json() for item in controls) + "\n", encoding="utf-8")
    output = tmp_path / "legacy.csv"
    assert mandatory_main([str(input_path), "-o", str(output)]) == 0
    assert not (tmp_path / "legacy-shadow-comparison.json").exists()
    legacy_bytes = output.read_bytes()

    assert mandatory_main([str(input_path), "-o", str(output), "--shadow-normative"]) == 0
    assert output.read_bytes() == legacy_bytes
    first = (tmp_path / "legacy-shadow-comparison.json").read_bytes()
    shadow = assess_controls_shadow(reversed(controls))
    write_shadow_comparison(shadow.shadow_assessments, tmp_path, "legacy")
    assert (tmp_path / "legacy-shadow-comparison.json").read_bytes() == first
    assert (tmp_path / "legacy-shadow-comparison.csv").exists()
    assert (tmp_path / "legacy-shadow-summary.json").exists()
    assert json.loads(first)[0]["normative_status"] == "advisory"


def test_shadow_reports_normative_promotion_demotion_and_confidence_difference() -> None:
    controls = [
        set_control("94.1", "Windows Firewall Domain firewall state enabled"),
        set_control("94.2", "Windows Firewall Domain inbound connections block by default"),
    ]
    legacy = assess_controls(controls)
    promoted_legacy = legacy[0].model_copy(update={"proposal": "Regular Control"})
    promoted = compare_shadow_assessments(controls, [promoted_legacy, legacy[1]])
    first = next(item for item in promoted.shadow_assessments if item.control_id == "94.1")
    assert first.normative_proposal == "Candidate Mandatory"
    assert "SHADOW-NORMATIVE-PROMOTION" in first.difference_codes

    demoted_legacy = legacy[0].model_copy(update={"confidence": "Low"})
    demoted = compare_shadow_assessments(controls, [demoted_legacy, legacy[1]])
    first = next(item for item in demoted.shadow_assessments if item.control_id == "94.1")
    assert first.normative_proposal == "Review Required"
    assert "SHADOW-NORMATIVE-DEMOTION" in first.difference_codes
    assert "SHADOW-CONFIDENCE-DIFFERENCE" in first.difference_codes


@pytest.mark.parametrize(
    "relationship",
    [
        "supporting hardening",
        "fine-tuning",
        "detection-only",
        "information-hiding",
        "operational",
    ],
)
def test_shadow_unresolved_applicability_takes_precedence_over_supporting_role(
    relationship: str,
) -> None:
    record = neutral_control(
        control_id="94.3",
        title="Configure smart card removal behavior",
        applicability="Where smart cards are deployed",
    )
    legacy = assess_controls([record])[0].model_copy(
        update={
            "proposal": "Review Required",
            "relationship": relationship,
            "applicability_mode": "unresolved",
        }
    )
    shadow = compare_shadow_assessments([record], [legacy]).shadow_assessments[0]
    assert shadow.normative_proposal == "Review Required"
    assert "SHADOW-APPLICABILITY-DIFFERENCE" in shadow.difference_codes


def test_shadow_unresolved_applicability_is_advisory_review() -> None:
    controls = [
        set_control("95.1", "Windows Firewall Domain firewall state enabled"),
        set_control("95.2", "Windows Firewall Domain inbound connections block by default"),
    ]
    legacy = assess_controls(controls)
    unresolved = legacy[0].model_copy(update={"applicability_mode": "unresolved"})
    result = compare_shadow_assessments(controls, [unresolved, legacy[1]])
    first = next(item for item in result.shadow_assessments if item.control_id == "95.1")
    assert first.normative_proposal == "Review Required"
    assert "SHADOW-APPLICABILITY-DIFFERENCE" in first.difference_codes


def cloud_control(title: str, **changes: Any) -> ControlRecord:
    return neutral_control(
        benchmark_name="Invented Microsoft 365 Foundations Benchmark",
        benchmark_version="1.0",
        applicability="All licensed tenant users",
        title=title,
        **changes,
    )


def test_cloud_legacy_authentication_reuses_generic_weak_authentication_boundary() -> None:
    item = cloud_control(
        "Block legacy authentication for tenant access",
        description="The tenant rejects legacy authentication exchanges.",
        rationale="Legacy authentication permits replayable credentials without modern verification.",
        remediation="Configure access policy to reject legacy authentication.",
    )
    shadow = assess_controls_shadow([item])
    assessment = shadow.shadow_assessments[0]
    assert assessment.normative_boundary_definition_ids == (
        "BND-IDENTITY-WEAK-AUTHENTICATION",
    )
    assert assessment.attack_path_ids == ("AP-012",)


def test_cloud_privileged_activation_resolves_new_generic_boundary() -> None:
    item = cloud_control(
        "Ensure approval is required for privileged role activation",
        description="Eligible privileged authority remains dormant until activation.",
        rationale="Independent approval prevents unreviewed privileged activation.",
        remediation="Require an approver for each privileged role activation.",
    )
    first = assess_controls_shadow([item])
    second = assess_controls_shadow(reversed([item]))
    assessment = first.shadow_assessments[0]
    assert assessment.normative_boundary_definition_ids == (
        "BND-IDENTITY-PRIVILEGED-ACTIVATION",
    )
    assert assessment.attack_path_ids == ("AP-016",)
    assert first.model_dump() == second.model_dump()


def test_cloud_semantic_mapping_requires_behavior_evidence_not_title_alone() -> None:
    item = cloud_control("Block legacy authentication for tenant access")
    assessment = assess_controls_shadow([item]).shadow_assessments[0]
    assert not assessment.normative_boundary_definition_ids
    assert "SHADOW-MISSING-CATALOG-MAPPING" in assessment.difference_codes


@pytest.mark.parametrize(
    "title",
    [
        "Require SMB signing",
        "Require LDAP signing",
        "Refuse NTLM authentication",
        "Disable WinRM Basic authentication",
        "Require RDP network-level authentication",
        "Enable Windows Firewall",
        "Enable Defender real-time protection",
        "Enable UAC admin approval mode",
    ],
)
def test_windows_host_boundary_rules_do_not_apply_to_explicit_cloud_benchmark(
    title: str,
) -> None:
    item = cloud_control(
        title,
        description="An invented cloud preference with no host protocol behavior.",
    )
    assessment = assess_controls([item])[0]
    assert assessment.boundary_set_id is None


def test_firewall_logging_and_fine_tuning_are_not_core_members() -> None:
    controls = [
        set_control("9.3.1", "Windows Firewall Public logging filename"),
        set_control("9.3.2", "Windows Firewall Public logging size limit"),
        set_control("9.3.3", "Windows Firewall Public display notification"),
        set_control("9.3.4", "Windows Firewall Public logging successful connections"),
    ]
    results = assess_controls(controls)
    assert all(item.proposal == "Regular Control" for item in results)
    assert all(item.boundary_set_id is None for item in results)


def test_boundary_set_results_are_deterministic_across_input_order() -> None:
    controls = [
        set_control("18.6.10", "Require minimum supported SMB version"),
        set_control("18.6.11", "Require SMB signing"),
    ]
    forward = [item.model_dump() for item in assess_controls(controls)]
    reverse = [item.model_dump() for item in assess_controls(reversed(controls))]
    assert forward == reverse


def test_csv_and_json_export(tmp_path: Path) -> None:
    assessments = assess_controls([control()])
    csv_path = tmp_path / "assessment.csv"
    json_path = tmp_path / "summary.json"
    write_assessment_csv(assessments, csv_path)
    write_summary_json(assessments, json_path)
    with csv_path.open(encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    summary = json.loads(json_path.read_text(encoding="utf-8"))
    assert rows[0]["proposal"] == "Candidate Mandatory"
    assert rows[0]["source_framework"] == "cis"
    assert rows[0]["benchmark_family"] == "microsoft-windows-server"
    assert rows[0]["benchmark_name"] == "Invented Microsoft Windows Server Benchmark"
    assert rows[0]["benchmark_version"] == "v1.0"
    assert rows[0]["profile"] == "L1"
    assert summary["proposal_counts"]["Candidate Mandatory"] == 1


def test_composite_identity_separates_same_id_across_families() -> None:
    windows = set_control("1.1.1", "Windows Firewall Domain firewall state enabled")
    cloud = cloud_control(
        "Configure an invented tenant preference",
        control_id="1.1.1",
        description="An invented tenant preference has no host firewall behavior.",
    )
    result = assess_controls_shadow([windows, cloud])
    assert len(result.legacy_assessments) == 2
    assert len({item.source_identity for item in result.legacy_assessments}) == 2
    by_family = {
        item.source_identity.benchmark_family: item
        for item in result.shadow_assessments
    }
    assert by_family["microsoft-windows-server"].normative_boundary_definition_ids == (
        "BND-NETWORK-HOST-FIREWALL",
    )
    assert by_family["microsoft-365-foundations"].normative_boundary_definition_ids == ()
    assert all(
        mapping.source_identity.benchmark_family == "microsoft-windows-server"
        for mapping in result.mitigation_mappings
    )


def test_composite_identity_prevents_cross_version_boundary_completion() -> None:
    version_one = set_control("2.1.1", "Windows Firewall Domain firewall state enabled")
    version_two = set_control(
        "2.1.1", "Windows Firewall Domain inbound connections block by default"
    ).model_copy(update={"benchmark_version": "2.0"})
    result = assess_controls_shadow([version_one, version_two])
    assert len({item.source_identity for item in result.legacy_assessments}) == 2
    assert all(item.proposal == "Review Required" for item in result.legacy_assessments)
    assert all(
        item.normative_proposal == "Review Required"
        for item in result.shadow_assessments
    )
    assert len(result.boundary_evaluations) == 2
    assert {item.benchmark_version for item in result.boundary_evaluations} == {
        "v1.0",
        "2.0",
    }


def test_composite_identity_separates_profiles_and_mixed_order_is_stable() -> None:
    level_one = neutral_control(control_id="3.1.1", profile="L1")
    level_two = neutral_control(control_id="3.1.1", profile="L2")
    cloud = cloud_control("Configure an invented tenant preference", control_id="3.1.1")
    controls = [level_one, level_two, cloud]
    forward = assess_controls_shadow(controls)
    reverse = assess_controls_shadow(reversed(controls))
    assert forward.model_dump() == reverse.model_dump()
    assert len({item.source_identity for item in forward.legacy_assessments}) == 3
