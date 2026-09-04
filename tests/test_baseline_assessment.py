from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cis_pdf2csv.baseline_assessment.cli import main
from cis_pdf2csv.baseline_assessment.engine import assess_baseline
from cis_pdf2csv.baseline_assessment.models import (
    AssessmentStatus,
    ExceptionDecision,
    ExceptionRecord,
    ValueComparison,
)
from cis_pdf2csv.environment_scan.models import (
    CollectionStatus,
    CurrentStateSnapshot,
    EnvironmentSource,
    ObservationScope,
    ObservedPolicy,
    ObservedSetting,
    ScanProvenance,
)
from cis_pdf2csv.schema import ControlRecord

SETTING_ID = "local_fixture.windows_server_2025.defender.antivirus_enabled"


def control(
    *,
    control_id: str = "1.1",
    title: str = "(L1) Ensure Microsoft Defender Antivirus is Enabled",
    assessment: str = "Automated",
    benchmark_name: str = "CIS Microsoft Windows Server 2025 Benchmark",
) -> ControlRecord:
    return ControlRecord(
        benchmark_name=benchmark_name,
        benchmark_version="1.0",
        benchmark_date="2026-01-01",
        control_id=control_id,
        profile="L1",
        title=title,
        assessment=assessment,
        default_value="Disabled",
        page_start=1,
        page_end=2,
        source_pdf_sha256="a" * 64,
        block_text_sha256="b" * 64,
        extracted_at_utc="2026-01-01T00:00:00Z",
    )


def snapshot(
    *values: str,
    status: CollectionStatus = CollectionStatus.COMPLETE,
) -> CurrentStateSnapshot:
    policies = tuple(
        ObservedPolicy(
            policy_id=f"policy-{index}",
            name=f"Policy {index}",
            policy_type="endpoint_security_antivirus",
            settings=(
                ObservedSetting(
                    identity=SETTING_ID,
                    display_name="Microsoft Defender Antivirus",
                    value=value,
                    policy_id=f"policy-{index}",
                    policy_name=f"Policy {index}",
                    source_path=f"policies/{index}",
                ),
            ),
        )
        for index, value in enumerate(values, start=1)
    )
    return CurrentStateSnapshot(
        status=status,
        scopes=(ObservationScope.DECLARED_CONFIGURATION,),
        provenance=ScanProvenance(
            source=EnvironmentSource.INTUNE,
            collected_at_utc="2026-01-01T00:00:00Z",
            collector_version="test",
        ),
        policies=policies,
        policy_count=len(policies),
        setting_count=len(values),
        asset_count=0,
        collection_errors=("collection incomplete",)
        if status == CollectionStatus.PARTIAL
        else (),
    )


def assess(item: ControlRecord, state: CurrentStateSnapshot):
    return assess_baseline(
        [item],
        state,
        current_state_sha256="c" * 64,
        at_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ).controls[0]


@pytest.mark.parametrize(
    ("observed", "expected_status", "expected_comparison"),
    [
        ("true", AssessmentStatus.DECLARED_COMPLIANT, ValueComparison.MATCH),
        ("false", AssessmentStatus.DECLARED_NON_COMPLIANT, ValueComparison.MISMATCH),
    ],
)
def test_verified_mapping_compares_declared_value(
    observed: str,
    expected_status: AssessmentStatus,
    expected_comparison: ValueComparison,
) -> None:
    result = assess(control(), snapshot(observed))

    assert result.status == expected_status
    assert result.comparison == expected_comparison
    assert result.desired_value == "True"
    assert "EFFECTIVE_STATE_NOT_OBSERVED" in result.reason_codes


def test_conflicting_declared_values_are_not_called_compliant() -> None:
    result = assess(control(), snapshot("true", "false"))

    assert result.status == AssessmentStatus.POTENTIAL_CONFLICT
    assert result.comparison == ValueComparison.UNKNOWN
    assert result.policy_ids == ("policy-1", "policy-2")


def test_unknown_family_is_fail_closed() -> None:
    result = assess(
        control(benchmark_name="CIS Example Appliance Benchmark"), snapshot("true")
    )

    assert result.status == AssessmentStatus.NOT_MEASURABLE
    assert result.mapping_status != "verified"
    assert "MAPPING_NOT_VERIFIED" in result.reason_codes


def test_manual_control_requires_evidence() -> None:
    result = assess(control(assessment="Manual"), snapshot("true"))

    assert result.status == AssessmentStatus.MANUAL_EVIDENCE_REQUIRED
    assert "CIS_MANUAL_ASSESSMENT" in result.reason_codes


def test_active_exception_is_auditable() -> None:
    exception = ExceptionRecord(
        control_id="1.1",
        decision=ExceptionDecision.EXCEPTION_ACTIVE,
        rationale="Approved compensating control",
        approved_by="Security Board",
        expires_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    result = assess_baseline(
        [control()],
        snapshot("false"),
        current_state_sha256="c" * 64,
        exceptions=(exception,),
        at_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ).controls[0]

    assert result.status == AssessmentStatus.EXCEPTION_ACTIVE
    assert result.exception == exception
    assert result.reason_codes == ("APPROVED_EXCEPTION",)


def test_expired_exception_does_not_hide_non_compliance() -> None:
    exception = ExceptionRecord(
        control_id="1.1",
        decision=ExceptionDecision.EXCEPTION_ACTIVE,
        rationale="Old exception",
        approved_by="Security Board",
        expires_at=datetime(2025, 12, 31, tzinfo=timezone.utc),
    )
    result = assess_baseline(
        [control()],
        snapshot("false"),
        current_state_sha256="c" * 64,
        exceptions=(exception,),
        at_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ).controls[0]

    assert result.status == AssessmentStatus.DECLARED_NON_COMPLIANT
    assert "EXCEPTION_EXPIRED" in result.reason_codes


def test_cli_writes_outputs_and_returns_two_for_partial_snapshot(
    tmp_path: Path,
) -> None:
    controls_path = tmp_path / "controls.jsonl"
    controls_path.write_text(control().model_dump_json() + "\n", encoding="utf-8")
    state_path = tmp_path / "current-state.json"
    state_path.write_text(
        snapshot("false", status=CollectionStatus.PARTIAL).model_dump_json(indent=2),
        encoding="utf-8",
    )
    output = tmp_path / "assessment"

    exit_code = main(
        [
            str(controls_path),
            "--current-state",
            str(state_path),
            "--at-time",
            "2026-01-01T00:00:00Z",
            "-o",
            str(output),
        ]
    )

    assert exit_code == 2
    assert (output / "assessment.csv").exists()
    assert (output / "assessment.jsonl").exists()
    assert (output / "action-required.csv").exists()
    summary = json.loads((output / "assessment-summary.json").read_text())
    assert summary["current_state_status"] == "partial"
    assert summary["status_counts"] == {"declared_non_compliant": 1}


def test_assessment_order_is_deterministic() -> None:
    controls = [
        control(control_id="2.1", title="Unknown recommendation"),
        control(control_id="1.1"),
    ]
    first = assess_baseline(
        controls,
        snapshot("true"),
        current_state_sha256="c" * 64,
        at_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    second = assess_baseline(
        list(reversed(controls)),
        snapshot("true"),
        current_state_sha256="c" * 64,
        at_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert first.controls == second.controls


def test_action_queue_is_written_even_when_no_action_is_required(
    tmp_path: Path,
) -> None:
    controls_path = tmp_path / "controls.jsonl"
    controls_path.write_text(control().model_dump_json() + "\n", encoding="utf-8")
    state_path = tmp_path / "current-state.json"
    state_path.write_text(snapshot("true").model_dump_json(), encoding="utf-8")
    output = tmp_path / "assessment"

    exit_code = main(
        [
            str(controls_path),
            "--current-state",
            str(state_path),
            "--at-time",
            "2026-01-01T00:00:00Z",
            "-o",
            str(output),
        ]
    )

    assert exit_code == 0
    assert len((output / "action-required.csv").read_text().splitlines()) == 1
