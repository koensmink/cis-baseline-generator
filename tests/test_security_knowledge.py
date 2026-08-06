from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from cis_pdf2csv.mandatory.exporters import write_assessment_csv
from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.attack_paths import ATTACK_PATHS
from cis_pdf2csv.security_knowledge.capabilities import CAPABILITIES
from cis_pdf2csv.security_knowledge.coverage import build_coverage_report
from cis_pdf2csv.security_knowledge.exporters import write_coverage_json


def invented_control(control_id: str, title: str, **changes: Any) -> ControlRecord:
    values: dict[str, Any] = {
        "benchmark_name": "Invented Server Benchmark",
        "benchmark_version": "1.0",
        "benchmark_date": "2026",
        "control_id": control_id,
        "profile": "L1",
        "title": title,
        "assessment": "Automated",
        "applicability": "Invented managed servers",
        "description": f"{title} enforces the described boundary effect.",
        "rationale": f"Without this effect, the attack path described by {title} remains open.",
        "impact": "Incompatible peers cannot cross the protected boundary.",
        "audit": f"Verify that {title} is enforced.",
        "remediation": title,
        "default_value": "Not configured",
        "references": "Invented reference",
        "page_start": 1,
        "page_end": 2,
        "source_pdf_sha256": "a" * 64,
        "block_text_sha256": "b" * 64,
        "extracted_at_utc": "2026-01-01T00:00:00Z",
        "parser_version": "test",
    }
    values.update(changes)
    return ControlRecord.model_validate(values)


def test_stable_capability_and_attack_path_catalogs() -> None:
    assert [item.capability_id for item in CAPABILITIES] == [f"CAP-{index:02d}" for index in range(1, 11)]
    assert [item.attack_path_id for item in ATTACK_PATHS] == [f"AP-{index:03d}" for index in range(1, 11)]


def test_one_control_maps_to_multiple_attack_paths() -> None:
    controls = [
        invented_control("9.1.1", "Windows Firewall Domain firewall state enabled"),
        invented_control("9.1.2", "Windows Firewall Domain inbound connections block by default"),
    ]
    assessments = assess_controls(controls)
    assert all(item.attack_path_ids == ["AP-003", "AP-007"] for item in assessments)
    assert all(item.capability_ids == ["CAP-04"] for item in assessments)


def test_attack_path_has_multiple_complementary_controls() -> None:
    assessments = assess_controls(
        [
            invented_control("2.1.1", "Require LDAP signing"),
            invented_control("2.1.2", "Require LDAP encryption and sealing"),
        ]
    )
    assert all("AP-001" in item.attack_path_ids for item in assessments)
    assert all(item.mitigation_strengths == ["complementary"] for item in assessments)


def test_title_alone_does_not_create_attack_path_mapping() -> None:
    assessment = assess_controls(
        [
            invented_control(
                "7.1",
                "Require firewall enforcement",
                description="An invented preference is configured.",
                rationale="This preference provides consistent behavior.",
                impact="No material impact.",
                remediation="Configure the invented preference.",
            )
        ]
    )[0]
    assert assessment.attack_path_ids == []
    assert assessment.proposal == "Review Required"
    assert "ATTACK_PATH_MAPPING_REQUIRED" in assessment.exclusion_reasons


def test_primary_and_supporting_mitigation_strength() -> None:
    primary = invented_control("5.1", "Require firewall network boundary protection")
    supporting = invented_control(
        "5.2",
        "Configure additional firewall protection",
        rationale="Additional firewall protection is supporting defense in depth.",
    )
    results = {item.control_id: item for item in assess_controls([primary, supporting])}
    assert results["5.1"].mitigation_strengths == ["primary"]
    assert results["5.2"].mitigation_strengths == ["supporting"]
    assert results["5.2"].proposal == "Regular Control"


def test_missing_reliable_mapping_requires_review() -> None:
    assessment = assess_controls(
        [invented_control("6.1", "Require application sandboxing")]
    )[0]
    assert assessment.relationship == "standalone primary boundary"
    assert assessment.proposal == "Review Required"
    assert assessment.review_note == "ATTACK_PATH_MAPPING_REQUIRED"


@pytest.mark.parametrize(
    ("boundary_id", "expected_paths", "controls"),
    [
        ("BS-HOST-FIREWALL-DOMAIN", {"AP-003", "AP-007"}, [("1", "Windows Firewall Domain firewall state enabled"), ("2", "Windows Firewall Domain inbound connections block by default")]),
        ("BS-SMB-SECURITY", {"AP-001", "AP-003"}, [("1", "Require minimum supported SMB version"), ("2", "Require SMB signing")]),
        ("BS-LDAP-SECURITY", {"AP-001"}, [("1", "Require LDAP signing"), ("2", "Require LDAP encryption")]),
        ("BS-NTLM-SESSION", {"AP-001", "AP-009"}, [("1", "Refuse LM and refuse NTLM credentials"), ("2", "Require NTLM minimum session security with 128-bit session encryption")]),
        ("BS-WINRM-SECURITY", {"AP-003", "AP-004"}, [("1", "Disable WinRM Basic authentication"), ("2", "Disable WinRM unencrypted traffic")]),
        ("BS-RDP-SECURITY", {"AP-003", "AP-004"}, [("1", "Require Network Level Authentication for RDP"), ("2", "Require RDP TLS security layer"), ("3", "Require RDP high encryption level")]),
        ("BS-MALWARE-PROTECTION", {"AP-005", "AP-006"}, [("1", "Enable real-time malware protection"), ("2", "Enable behavior monitoring"), ("3", "Enable network protection in block mode")]),
        ("BS-PRIVILEGED-CREDENTIALS", {"AP-002", "AP-009"}, [("1", "Do not store passwords using reversible encryption")]),
    ],
)
def test_windows_boundary_sets_receive_expected_paths(
    boundary_id: str,
    expected_paths: set[str],
    controls: list[tuple[str, str]],
) -> None:
    assessments = assess_controls(
        [invented_control(f"8.{control_id}", title) for control_id, title in controls]
    )
    assert all(item.boundary_set_id == boundary_id for item in assessments)
    assert expected_paths == {path for item in assessments for path in item.attack_path_ids}


def test_repeatability_and_coverage_report(tmp_path: Path) -> None:
    controls = [
        invented_control("9.1", "Windows Firewall Public firewall state enabled"),
        invented_control("9.2", "Windows Firewall Public inbound connections block by default"),
    ]
    forward = assess_controls(controls)
    reverse = assess_controls(reversed(controls))
    assert [item.model_dump() for item in forward] == [item.model_dump() for item in reverse]

    report = build_coverage_report(forward)
    candidate_counts = report["candidate_mandatory_controls_per_attack_path"]
    assert isinstance(candidate_counts, dict)
    assert candidate_counts["AP-007"] == ["9.1", "9.2"]
    assert report["security_capabilities_represented"] == ["CAP-04"]
    output = tmp_path / "coverage.json"
    write_coverage_json(forward, output)
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_mandatory_csv_remains_backward_compatible_and_adds_mapping_columns(
    tmp_path: Path,
) -> None:
    assessments = assess_controls(
        [
            invented_control("10.1", "Windows Firewall Private firewall state enabled"),
            invented_control("10.2", "Windows Firewall Private inbound connections block by default"),
        ]
    )
    output = tmp_path / "mandatory.csv"
    write_assessment_csv(assessments, output)
    with output.open(encoding="utf-8-sig") as handle:
        row = next(csv.DictReader(handle))
    assert row["control_id"] == "10.1"
    assert row["proposal"] == "Candidate Mandatory"
    assert row["attack_path_ids"] == "AP-003;AP-007"
    assert row["attack_path_names"]
    assert row["attack_stages"]
    assert row["mitigation_strengths"] == "complementary"
