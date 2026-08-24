from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cis_pdf2csv.mandatory.pipeline import assess_controls as production_assess_controls
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.provenance import Confidence, LifecycleStatus
from cis_pdf2csv.security_knowledge.threat_intelligence import cli as threat_cli
from cis_pdf2csv.security_knowledge.threat_intelligence.cli import main
from cis_pdf2csv.security_knowledge.threat_intelligence.exporters import (
    THREAT_OVERLAY_CSV_FIELDS,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.schema import (
    ThreatApplicabilityScope,
    ThreatContext,
    ThreatContextProvenance,
    ThreatSeverity,
    ThreatSourceType,
)

AT_TIME = "2026-08-24T12:00:00+00:00"


def control(control_id: str, title: str, *, family: str = "windows") -> ControlRecord:
    benchmark = (
        "Invented Microsoft Windows Server Benchmark"
        if family == "windows"
        else "Invented Microsoft 365 Benchmark"
    )
    return ControlRecord(
        benchmark_name=benchmark,
        benchmark_version="synthetic-v1",
        benchmark_date="August 2026",
        control_id=control_id,
        profile="L1",
        title=title,
        assessment="Automated",
        applicability="All invented systems",
        description=f"{title} directly enforces its named security effect.",
        rationale=f"{title} closes an invented attack path in the effective boundary.",
        impact="Synthetic traffic follows the stated policy.",
        audit="Inspect the invented configuration.",
        remediation=title,
        default_value="Disabled",
        references="Synthetic reference",
        page_start=1,
        page_end=1,
        source_pdf_sha256="a" * 64,
        block_text_sha256=("b" if family == "windows" else "c") * 64,
        extracted_at_utc="2026-08-01T00:00:00Z",
        parser_version="test",
    )


def firewall_controls() -> tuple[ControlRecord, ControlRecord]:
    return (
        control("1.1", "Windows Firewall Domain firewall state enabled"),
        control("1.2", "Windows Firewall Domain inbound connections block by default"),
    )


def context(
    context_id: str = "THRCTX-SYNTH-CLI-FIREWALL",
    *,
    confidence: Confidence = Confidence.HIGH,
    lifecycle: LifecycleStatus = LifecycleStatus.ACTIVE,
    valid_from: str = "2026-08-23T12:00:00Z",
    valid_until: str = "2026-08-25T12:00:00Z",
) -> ThreatContext:
    return ThreatContext.model_validate(
        {
            "threat_context_id": context_id,
            "title": "Synthetic inbound path activity",
            "description": "Invented activity concerns an inbound synthetic service path.",
            "source_type": ThreatSourceType.ANALYST,
            "source_name": "Synthetic test authority",
            "source_reference": f"SYNTH-{context_id}",
            "valid_from": valid_from,
            "valid_until": valid_until,
            "confidence": confidence,
            "severity": ThreatSeverity.HIGH,
            "lifecycle_status": lifecycle,
            "attack_path_ids": ["AP-007"],
            "targeted_asset_classes": ["synthetic services"],
            "affected_technology_families": ["synthetic servers"],
            "applicability_scope": ThreatApplicabilityScope.TECHNOLOGY_FAMILY,
            "provenance": ThreatContextProvenance(
                authority="Synthetic test authority",
                creation_method="invented CLI fixture",
                model_version="1.0",
                object_version="1",
            ),
        }
    )


def write_inputs(
    directory: Path,
    *,
    controls: tuple[ControlRecord, ...] | None = None,
    contexts: tuple[ThreatContext, ...] | None = None,
) -> tuple[Path, tuple[Path, ...]]:
    controls_path = directory / "controls.jsonl"
    controls_path.write_text(
        "".join(
            item.model_dump_json() + "\n"
            for item in (controls if controls is not None else firewall_controls())
        ),
        encoding="utf-8",
    )
    threat_paths: list[Path] = []
    for index, item in enumerate(contexts or (context(),), start=1):
        path = directory / f"threat-{index}.json"
        path.write_text(item.model_dump_json(), encoding="utf-8")
        threat_paths.append(path)
    return controls_path, tuple(threat_paths)


def args(controls: Path, threats: tuple[Path, ...], output: Path) -> list[str]:
    values = [str(controls)]
    for threat in threats:
        values.extend(("--threat-context", str(threat)))
    values.extend(("--at-time", AT_TIME, "-o", str(output)))
    return values


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def test_help_works(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "--threat-context" in capsys.readouterr().out


def test_active_analysis_writes_all_artifacts_and_real_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    controls, threats = write_inputs(tmp_path)
    output = tmp_path / "threat-overlay.csv"
    assert main(args(controls, threats, output)) == 0
    expected = {
        output,
        tmp_path / "threat-overlay-high.csv",
        tmp_path / "threat-overlay-review.csv",
        tmp_path / "threat-overlay.json",
        tmp_path / "threat-overlay-summary.json",
    }
    assert all(path.is_file() for path in expected)
    rows = read_csv(output)
    assert rows
    assert list(rows[0]) == THREAT_OVERLAY_CSV_FIELDS
    assert all(
        row["threat_relevance"] in {"High", "Critical"}
        for row in read_csv(tmp_path / "threat-overlay-high.csv")
    )
    assert all(
        row["advisory_action"] == "review"
        for row in read_csv(tmp_path / "threat-overlay-review.csv")
    )
    summary = json.loads((tmp_path / "threat-overlay-summary.json").read_text())
    assert summary["priority_summary"]["total_projected_controls"] == len(rows)
    rendered = capsys.readouterr().out
    assert "cis-threat-analyze summary" in rendered
    assert "Projected controls" in rendered
    assert str(len(rows)) in rendered


def test_repeated_runs_and_input_order_are_byte_deterministic(tmp_path: Path) -> None:
    first_dir, second_dir = tmp_path / "first", tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    controls = firewall_controls()
    first_inputs = write_inputs(first_dir, controls=controls)
    second_inputs = write_inputs(second_dir, controls=tuple(reversed(controls)))
    first_output = first_dir / "overlay.csv"
    second_output = second_dir / "overlay.csv"
    assert main(args(*first_inputs, first_output)) == 0
    assert main(args(*second_inputs, second_output)) == 0
    for suffix in (".csv", "-high.csv", "-review.csv", ".json", "-summary.json"):
        assert (first_dir / f"overlay{suffix}").read_bytes() == (
            second_dir / f"overlay{suffix}"
        ).read_bytes()


def test_regular_base_remains_regular_when_cli_relevance_is_high(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls, threats = write_inputs(tmp_path)

    def regular_assessments(records):  # type: ignore[no-untyped-def]
        return [
            item.model_copy(update={"proposal": "Regular Control"})
            for item in production_assess_controls(records)
        ]

    monkeypatch.setattr(threat_cli, "assess_controls", regular_assessments)
    output = tmp_path / "regular.csv"
    assert main(args(controls, threats, output)) == 0
    rows = read_csv(output)
    assert rows
    assert all(row["base_proposal"] == "Regular Control" for row in rows)
    assert any(row["threat_relevance"] == "High" for row in rows)
    assert all("Candidate Mandatory" not in row["base_proposal"] for row in rows)


def test_candidate_and_review_base_proposals_are_preserved(tmp_path: Path) -> None:
    candidate_dir, review_dir = tmp_path / "candidate", tmp_path / "review"
    candidate_dir.mkdir()
    review_dir.mkdir()
    candidate_inputs = write_inputs(candidate_dir)
    review_inputs = write_inputs(
        review_dir,
        controls=(firewall_controls()[0],),
    )
    candidate_output = candidate_dir / "overlay.csv"
    review_output = review_dir / "overlay.csv"
    assert main(args(*candidate_inputs, candidate_output)) == 0
    assert main(args(*review_inputs, review_output)) == 0
    assert {row["base_proposal"] for row in read_csv(candidate_output)} == {
        "Candidate Mandatory"
    }
    assert {row["base_proposal"] for row in read_csv(review_output)} == {
        "Review Required"
    }


def test_review_export_contains_review_capped_controls_only(tmp_path: Path) -> None:
    controls, threats = write_inputs(
        tmp_path, contexts=(context(confidence=Confidence.MEDIUM),)
    )
    output = tmp_path / "review-capped.csv"
    assert main(args(controls, threats, output)) == 0
    full = read_csv(output)
    review = read_csv(tmp_path / "review-capped-review.csv")
    assert review
    assert len(review) == len(full)
    assert all(row["advisory_action"] == "review" for row in review)
    assert all(row["threat_relevance"] == "Elevated" for row in review)


def test_inactive_context_succeeds_with_empty_overlay(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inactive = context(
        lifecycle=LifecycleStatus.DEPRECATED,
        valid_from="2026-08-20T00:00:00Z",
        valid_until="2026-08-21T00:00:00Z",
    )
    controls, threats = write_inputs(tmp_path, contexts=(inactive,))
    output = tmp_path / "inactive.csv"
    assert main(args(controls, threats, output)) == 0
    assert read_csv(output) == []
    summary = json.loads((tmp_path / "inactive-summary.json").read_text())
    assert summary["priority_summary"]["total_projected_controls"] == 0
    assert summary["threat_resolutions"][0]["status"] == "inactive"
    assert "No active projected controls were found" in capsys.readouterr().out


def test_multiple_contexts_preserve_all_drivers(tmp_path: Path) -> None:
    contexts = (
        context("THRCTX-SYNTH-CLI-A"),
        context("THRCTX-SYNTH-CLI-B", confidence=Confidence.MEDIUM),
    )
    controls, threats = write_inputs(tmp_path, contexts=contexts)
    output = tmp_path / "multiple.csv"
    assert main(args(controls, threats, output)) == 0
    payload = json.loads((tmp_path / "multiple.json").read_text())
    assert payload
    assert all(
        item["threat_context_ids"] == ["THRCTX-SYNTH-CLI-A", "THRCTX-SYNTH-CLI-B"]
        for item in payload
    )
    assert all(len(item["drivers"]) == 2 for item in payload)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["missing.jsonl", "-o", "out.csv"], "--threat-context"),
        (
            [
                "missing.jsonl",
                "--threat-context",
                "missing-threat.json",
                "-o",
                "out.csv",
            ],
            "input file not found",
        ),
    ],
)
def test_missing_inputs_error_cleanly(
    argv: list[str], expected: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert expected in captured.err
    assert "Traceback" not in captured.out + captured.err


def test_missing_threat_file_and_invalid_output_directory_error_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    controls, threats = write_inputs(tmp_path)
    with pytest.raises(SystemExit) as missing:
        main(args(controls, (tmp_path / "missing.json",), tmp_path / "out.csv"))
    assert missing.value.code == 2
    assert "threat context file not found" in capsys.readouterr().err
    with pytest.raises(SystemExit) as output_error:
        main(args(controls, threats, tmp_path / "absent" / "out.csv"))
    assert output_error.value.code == 2
    assert "output directory does not exist" in capsys.readouterr().err


def test_malformed_context_and_blocking_validation_error_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    controls, _ = write_inputs(tmp_path)
    malformed = tmp_path / "malformed.json"
    malformed.write_text("not-json", encoding="utf-8")
    with pytest.raises(SystemExit) as malformed_error:
        main(args(controls, (malformed,), tmp_path / "malformed.csv"))
    assert malformed_error.value.code == 2
    assert "Invalid ThreatContext" in capsys.readouterr().err

    blocked = tmp_path / "blocked.json"
    blocked.write_text(
        context()
        .model_copy(
            update={
                "valid_from": datetime(2026, 8, 25, tzinfo=timezone.utc),
                "valid_until": datetime(2026, 8, 24, tzinfo=timezone.utc),
            }
        )
        .model_dump_json(),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as blocked_error:
        main(args(controls, (blocked,), tmp_path / "blocked.csv"))
    assert blocked_error.value.code == 2
    assert "Blocking ThreatContext validation" in capsys.readouterr().err


def test_malformed_controls_report_line_number_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    controls, threats = write_inputs(tmp_path)
    controls.write_text("{}\nnot-json\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(args(controls, threats, tmp_path / "bad.csv"))
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "line 1" in captured.err
    assert "Traceback" not in captured.out + captured.err


def test_duplicate_control_ids_across_families_remain_isolated(tmp_path: Path) -> None:
    windows = firewall_controls()[0].model_copy(update={"control_id": "7.1"})
    m365 = control(
        "7.1",
        "Configure an invented tenant preference",
        family="m365",
    )
    controls, threats = write_inputs(tmp_path, controls=(windows, m365))
    output = tmp_path / "mixed.csv"
    assert main(args(controls, threats, output)) == 0
    rows = read_csv(output)
    identities = [row["source_identity"] for row in rows]
    assert len(identities) == len(set(identities))
    assert all(row["benchmark_family"] == "microsoft-windows-server" for row in rows)


def test_cli_only_orchestrates_phase_apis() -> None:
    source = Path(threat_cli.__file__).read_text()
    assert "resolve_threat_context(" in source
    assert "project_threat_resolutions(" in source
    assert "prioritize_threat_projections(" in source
    assert "ThreatRelevance" not in source
    assert "Candidate Mandatory" not in source
