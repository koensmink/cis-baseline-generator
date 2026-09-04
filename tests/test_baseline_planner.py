from __future__ import annotations

import json
from pathlib import Path

from cis_pdf2csv.baseline_planner.cli import main
from cis_pdf2csv.baseline_planner.engine import build_plan
from cis_pdf2csv.baseline_planner.models import (
    DeploymentReadiness,
    SecurityCategory,
)
from cis_pdf2csv.schema import ControlRecord


def control(**changes: object) -> ControlRecord:
    values: dict[str, object] = {
        "benchmark_name": "CIS Invented Product Benchmark",
        "benchmark_version": "v1.0.0",
        "benchmark_date": "2026",
        "control_id": "1.1.1",
        "profile": "L1",
        "title": "Ensure security event logging is enabled",
        "assessment": "Automated",
        "applicability": "Level 1",
        "description": "Security events are recorded for monitoring.",
        "rationale": "Logging supports detection and investigation.",
        "impact": "Additional log storage is required.",
        "audit": "Verify logging is enabled.",
        "remediation": "Enable security event logging.",
        "page_start": 1,
        "page_end": 2,
        "source_pdf_sha256": "a" * 64,
        "block_text_sha256": "b" * 64,
        "extracted_at_utc": "2026-01-01T00:00:00Z",
    }
    values.update(changes)
    return ControlRecord.model_validate(values)


def test_plan_enriches_control_with_explainable_wave() -> None:
    item = build_plan([control()]).controls[0]

    assert item.security_category == SecurityCategory.AUDIT_LOGGING
    assert item.work_package == "Security Logging and Monitoring"
    assert "undetected malicious activity" in item.risk_statement
    assert item.prevents
    assert item.priority_score > 0
    assert item.recommended_wave == 1
    assert item.execution_phase == "1"
    assert item.wave_rationale
    assert item.evidence_sources == (
        "cis_control",
        "mandatory_engine",
        "intune_verifier",
    )


def test_unknown_family_planning_remains_fail_closed() -> None:
    item = build_plan([control()]).controls[0]

    assert item.intune_mapping_status == "manual_review"
    assert item.deployment_readiness == DeploymentReadiness.NEEDS_VALIDATION


def test_plan_is_input_order_independent() -> None:
    first = control(control_id="2.1", title="Ensure the firewall is enabled")
    second = control(control_id="1.1", title="Ensure audit logging is enabled")

    forward = build_plan([first, second])
    reverse = build_plan([second, first])

    assert forward.model_dump() == reverse.model_dump()
    assert [item.control_id for item in forward.controls] == ["1.1", "2.1"]


def test_specific_account_policy_rule_wins_over_generic_identity_rule() -> None:
    item = build_plan([control(title="Ensure minimum password length is configured")]).controls[0]

    assert item.security_category == SecurityCategory.ACCOUNT_POLICY
    assert item.work_package == "Account Policy"


def test_narrative_technology_reference_does_not_override_control_subject() -> None:
    item = build_plan(
        [
            control(
                title="Ensure installation of matching device drivers is prevented",
                rationale="This supports computers protected by BitLocker encryption.",
                remediation="Enable the device installation restriction.",
            )
        ]
    ).controls[0]

    assert item.security_category == SecurityCategory.SYSTEM_HARDENING
    assert "Wave 0: Recovery-key escrow and recovery test" not in item.dependencies


def test_impact_dimensions_do_not_treat_every_block_setting_as_high_impact() -> None:
    item = build_plan([control(title="Ensure firewall blocks unsolicited inbound traffic")]).controls[0]

    assert item.operational_impact.value == "Medium"
    assert item.user_impact.value == "Low"


def test_large_wave_is_split_into_bounded_execution_phases() -> None:
    controls = [control(control_id=f"2.{index}", title="Ensure firewall is enabled") for index in range(5)]
    plan = build_plan(controls, max_phase_size=2)

    assert {item.execution_phase for item in plan.controls} == {"3A", "3B", "3C"}
    assert max(phase.control_count for phase in plan.implementation_phases) == 2
    assert len(plan.work_packages) == 1
    assert [phase.title for phase in plan.implementation_phases] == [
        "Wave 3 / Network and Firewall Hardening (part 1/3)",
        "Wave 3 / Network and Firewall Hardening (part 2/3)",
        "Wave 3 / Network and Firewall Hardening (part 3/3)",
    ]


def test_execution_phase_does_not_mix_work_packages() -> None:
    plan = build_plan(
        [
            control(control_id="1.1", title="Ensure audit logging is enabled"),
            control(control_id="2.1", title="Ensure minimum password length is configured"),
            control(control_id="3.1", title="Ensure Defender antivirus is enabled"),
        ]
    )

    assert all(len(phase.work_packages) == 1 for phase in plan.implementation_phases)


def test_known_control_dependencies_are_explicit() -> None:
    bitlocker = build_plan([control(title="Ensure BitLocker recovery key is escrowed")]).controls[0]
    ntlm = build_plan([control(title="Ensure NTLM authentication is blocked")]).controls[0]

    assert "Wave 0: Recovery-key escrow and recovery test" in bitlocker.dependencies
    assert "Wave 0: NTLM usage inventory" in ntlm.dependencies


def test_cli_writes_customer_planning_artifacts(tmp_path: Path) -> None:
    input_path = tmp_path / "controls.jsonl"
    input_path.write_text(
        "\n".join(
            (
                control().model_dump_json(),
                control(
                    control_id="2.1.1",
                    title="Ensure remote desktop access is disabled",
                    impact="This may interrupt remote administration.",
                ).model_dump_json(),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "plan"

    assert main([str(input_path), "-o", str(output)]) == 0

    expected = {
        "enriched-controls.csv",
        "enriched-controls.jsonl",
        "manual-review.csv",
        "implementation-phases.csv",
        "plan-summary.json",
        "wave-00-prerequisites.csv",
        "waves.csv",
        "work-packages.csv",
    }
    assert expected <= {path.name for path in output.iterdir()}
    summary = json.loads((output / "plan-summary.json").read_text(encoding="utf-8"))
    assert summary["controls"] == 2
    assert sum(summary["waves"].values()) == 2
    assert summary["prerequisites"] == 9
