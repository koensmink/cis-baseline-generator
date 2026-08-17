from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import fitz
from cis_pdf2csv.cli import main as parser_main
from cis_pdf2csv.parser import (
    UnsupportedBenchmarkIdentityError,
    parse_controls,
)


def _write_pdf(path: Path, pages: list[list[str]]) -> None:
    document = fitz.open()
    for lines in pages:
        page = document.new_page()
        y = 72
        for line in lines:
            page.insert_text((72, y), line, fontsize=10)
            y += 14
        
    document.save(str(path))
    document.close()


def _windows_pages(control_id: str = "1.2.3") -> list[list[str]]:
    return [
        [
            "CIS Microsoft Windows Server 2025 Benchmark",
            "v9.8.7 - 17 August 2026",
        ],
        [
            f"{control_id} Ensure the invented recommendation",
            "is enabled (Automated)",
            "Profile Applicability",
            "Level 1 - Member Server",
            "Description",
            "Invented description line one",
            "continues on the next line.",
            "Rationale Statement",
            "Invented rationale.",
            "Impact Statement",
            "Invented impact.",
            "Audit Procedure",
            "Run invented audit command.",
        ],
        [
            "Confirm the invented result.",
            "Remediation Procedure",
            "Apply invented remediation.",
            "Default Value",
            "Invented default.",
            "References",
            "INVENTED-REF-1",
            "2.4.6 Configure the invented advanced option (Manual)",
            "Profile Applicability",
            "Level 2 - Member Server",
            "Description",
            "Invented advanced description.",
            "Rationale",
            "Invented advanced rationale.",
            "Impact",
            "Invented advanced impact.",
            "Audit",
            "Run invented advanced audit.",
            "Remediation",
            "Apply invented advanced remediation.",
            "Default Value",
            "Invented advanced default.",
            "References",
            "INVENTED-REF-2",
        ],
    ]


def _m365_pages() -> list[list[str]]:
    return [
        [
            "CIS Microsoft 365 Foundations Benchmark",
            "v7.6.5 - 17 August 2026",
        ],
        [
            "3.2.1 Ensure invented tenant authentication is enabled (Automated)",
            "Profile Applicability",
            "E3 Level 1",
            "Description",
            "Invented tenant description.",
            "Rationale",
            "Invented tenant rationale.",
            "Impact",
            "Invented tenant impact.",
            "Audit",
            "Run invented tenant audit.",
            "Remediation",
            "Apply invented tenant remediation.",
            "Default Value",
            "Invented tenant default.",
            "References",
            "INVENTED-M365-REF",
        ],
    ]


def test_parse_synthetic_pdf_end_to_end(tmp_path: Path) -> None:
    pdf = tmp_path / "invented-windows.pdf"
    _write_pdf(pdf, _windows_pages())

    controls = parse_controls(str(pdf))

    assert len(controls) == 2
    first = controls[0]
    assert first["benchmark_name"] == "CIS Microsoft Windows Server 2025 Benchmark"
    assert first["benchmark_version"] == "v9.8.7"
    assert first["benchmark_date"] == "17 August 2026"
    assert first["control_id"] == "1.2.3"
    assert first["title"] == "Ensure the invented recommendation is enabled"
    assert first["assessment"] == "Automated"
    assert first["profile"] == "L1"
    assert first["applicability"] == "Level 1 - Member Server"
    assert first["description"] == "Invented description line one continues on the next line."
    assert first["rationale"] == "Invented rationale."
    assert first["impact"] == "Invented impact."
    assert first["audit"] == "Run invented audit command. Confirm the invented result."
    assert first["remediation"] == "Apply invented remediation."
    assert first["default_value"] == "Invented default."
    assert first["references"] == "INVENTED-REF-1"
    assert first["page_start"] == 2
    assert first["page_end"] == 3
    assert first["source_pdf_sha256"] == hashlib.sha256(pdf.read_bytes()).hexdigest()
    assert len(first["block_text_sha256"]) == 64
    assert first["block_text_sha256"] == parse_controls(str(pdf))[0]["block_text_sha256"]

    second = controls[1]
    assert second["control_id"] == "2.4.6"
    assert second["assessment"] == "Manual"
    assert second["profile"] == "L2"
    assert second["page_start"] == second["page_end"] == 3


def test_parser_profile_filter_is_deterministic(tmp_path: Path) -> None:
    pdf = tmp_path / "invented-profiles.pdf"
    _write_pdf(pdf, _windows_pages())
    assert [item["control_id"] for item in parse_controls(str(pdf), "L1")] == ["1.2.3"]
    assert [item["control_id"] for item in parse_controls(str(pdf), "l2")] == ["2.4.6"]


@pytest.mark.parametrize(
    ("metadata", "finding"),
    [
        (["Invented Unsupported Benchmark", "v1.0.0 - 17 August 2026"], "BENCHMARK_FAMILY_UNSUPPORTED"),
        (
            [
                "CIS Microsoft Windows Server 2025 Benchmark",
                "CIS Microsoft 365 Foundations Benchmark",
                "v1.0.0 - 17 August 2026",
            ],
            "BENCHMARK_FAMILY_AMBIGUOUS",
        ),
    ],
)
def test_parser_rejects_unsupported_or_ambiguous_identity(
    tmp_path: Path,
    metadata: list[str],
    finding: str,
) -> None:
    pdf = tmp_path / f"{finding}.pdf"
    _write_pdf(pdf, [metadata, *_windows_pages()[1:]])
    with pytest.raises(UnsupportedBenchmarkIdentityError, match=finding):
        parse_controls(str(pdf))


def test_parser_cli_reports_unsupported_identity_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pdf = tmp_path / "unsupported.pdf"
    output = tmp_path / "output.jsonl"
    _write_pdf(pdf, [["Invented Unsupported Benchmark"], *_windows_pages()[1:]])
    assert parser_main([str(pdf), "-o", str(output)]) == 2
    captured = capsys.readouterr()
    assert "BENCHMARK_FAMILY_UNSUPPORTED" in captured.out
    assert "Traceback" not in captured.out + captured.err
    assert not output.exists()


def test_multiple_pdf_output_order_is_input_order_independent(tmp_path: Path) -> None:
    windows_pdf = tmp_path / "windows.pdf"
    m365_pdf = tmp_path / "m365.pdf"
    _write_pdf(windows_pdf, _windows_pages("9.9.9"))
    _write_pdf(m365_pdf, _m365_pages())
    forward = tmp_path / "forward.jsonl"
    reverse = tmp_path / "reverse.jsonl"

    assert parser_main([str(windows_pdf), str(m365_pdf), "-o", str(forward)]) == 0
    assert parser_main([str(m365_pdf), str(windows_pdf), "-o", str(reverse)]) == 0

    def stable_rows(path: Path) -> list[tuple[str, str, str]]:
        return [
            (row["benchmark_name"], row["benchmark_version"], row["control_id"])
            for row in (json.loads(line) for line in path.read_text().splitlines())
        ]

    assert stable_rows(forward) == stable_rows(reverse)
    assert stable_rows(forward) == sorted(stable_rows(forward))
