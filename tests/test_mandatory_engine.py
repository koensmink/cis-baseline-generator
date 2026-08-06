from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any

import pytest

from cis_pdf2csv.mandatory.criteria import CRITERIA, match_criteria
from cis_pdf2csv.mandatory.exporters import write_assessment_csv, write_summary_json
from cis_pdf2csv.mandatory.features import extract_features
from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.schema import ControlRecord


def control(control_id: str = "1.1", title: str = "Require firewall protection", **changes: Any) -> ControlRecord:
    values: dict[str, Any] = {
        "benchmark_name": "Invented Security Benchmark",
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
    assert results["3.2.1"].relationship == "primary boundary control"
    assert results["3.2.2"].relationship == "supporting control"
    assert results["3.2.2"].proposal == "Regular Control"


def test_fine_tuning_related_control_is_excluded() -> None:
    items = [
        control("4.1.1", "Require security audit logging"),
        control("4.1.2", "Set security audit log retention period"),
    ]
    result = {item.control_id: item for item in assess_controls(items)}["4.1.2"]
    assert result.relationship == "fine-tuning control"
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
    assert by_id["200.1.1"].relationship == "primary boundary control"
    assert by_id["200.1.2"].proposal == "Regular Control"
    assert by_id["200.1.2"].relationship == "supporting control"
    assert all(by_id[f"100.{index}.1"].proposal == "Regular Control" for index in range(450))


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
    assert summary["proposal_counts"]["Candidate Mandatory"] == 1
