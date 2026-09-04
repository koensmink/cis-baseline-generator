from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import fitz
from cis_pdf2csv.cli import main as parser_main
from cis_pdf2csv.intune_mapper.models import MappingInputControl
from cis_pdf2csv.intune_mapper.resolver import resolve_control
from cis_pdf2csv.parser import (
    CISStructureError,
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
    "benchmark_title",
    [
        "CIS Microsoft Windows 11 Enterprise Benchmark",
        "CIS Microsoft IIS 10 Benchmark",
        "CIS Microsoft SQL Server 2022 Benchmark",
    ],
)
def test_unknown_benchmark_family_parses_with_generic_identity(
    tmp_path: Path,
    benchmark_title: str,
) -> None:
    pdf = tmp_path / "generic.pdf"
    _write_pdf(
        pdf,
        [[benchmark_title, "v1.2.3 - 17 August 2026"], *_windows_pages()[1:]],
    )

    controls = parse_controls(str(pdf))

    assert len(controls) == 2
    assert {item["benchmark_name"] for item in controls} == {benchmark_title}
    assert {item["benchmark_version"] for item in controls} == {"v1.2.3"}


def test_generically_parsed_family_remains_fail_closed_for_intune(tmp_path: Path) -> None:
    pdf = tmp_path / "windows-11.pdf"
    _write_pdf(
        pdf,
        [
            [
                "CIS Microsoft Windows 11 Enterprise Benchmark",
                "v1.2.3 - 17 August 2026",
            ],
            *_windows_pages()[1:],
        ],
    )
    parsed = parse_controls(str(pdf))[0]

    mapping, conflict = resolve_control(MappingInputControl.model_validate(parsed))

    assert conflict is None
    assert mapping.benchmark_family == "unknown"
    assert mapping.reason_code == "UNSUPPORTED_BENCHMARK_FAMILY"
    assert mapping.implementation_type == "manual_review"


def test_parser_cli_reports_non_cis_structure_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pdf = tmp_path / "not-cis.pdf"
    output = tmp_path / "output.jsonl"
    _write_pdf(pdf, [["Invented Product Manual"], *_windows_pages()[1:]])
    assert parser_main([str(pdf), "-o", str(output)]) == 2
    captured = capsys.readouterr()
    assert "CIS_STRUCTURE_NOT_DETECTED" in captured.out
    assert "Traceback" not in captured.out + captured.err
    assert not output.exists()


def test_malformed_cis_document_fails_structural_validation(tmp_path: Path) -> None:
    pdf = tmp_path / "malformed.pdf"
    _write_pdf(
        pdf,
        [
            ["CIS Invented Product Benchmark", "v1.0.0 - 17 August 2026"],
            ["Introduction", "No recommendations here."],
        ],
    )

    with pytest.raises(CISStructureError, match="CIS_STRUCTURE_NOT_DETECTED"):
        parse_controls(str(pdf))


def test_toc_entries_and_appendix_content_are_not_controls(tmp_path: Path) -> None:
    pdf = tmp_path / "structured-boundaries.pdf"
    _write_pdf(
        pdf,
        [
            [
                "CIS Invented Product Benchmark",
                "v1.0.0 - 17 August 2026",
                "Table of Contents",
                "9.9.9 Ensure the final recommendation (Automated) .......... 42",
            ],
            *_windows_pages()[1:],
            [
                "Appendix: Summary Table",
                "0.0 Explicitly Not Mapped",
                "9.9.9 Ensure the final recommendation (Automated)",
                "Profile Applicability",
                "Level 1",
                "Audit",
                "Appendix audit text.",
            ],
        ],
    )

    controls = parse_controls(str(pdf))

    assert [item["control_id"] for item in controls] == ["1.2.3", "2.4.6"]
    assert "Appendix" not in (controls[-1]["references"] or "")


def test_duplicate_real_control_ids_fail_integrity_validation(tmp_path: Path) -> None:
    pages = _windows_pages()
    pages.append(
        [
            "2.4.6 A duplicate recommendation (Automated)",
            "Profile Applicability",
            "Level 1 - Member Server",
            "Description",
            "Duplicate description.",
            "Audit",
            "Duplicate audit.",
            "Remediation",
            "Duplicate remediation.",
        ]
    )
    pdf = tmp_path / "duplicate.pdf"
    _write_pdf(pdf, pages)

    with pytest.raises(CISStructureError, match="CONTROL_BOUNDARIES_AMBIGUOUS"):
        parse_controls(str(pdf))


def test_version_like_rationale_text_does_not_split_control(tmp_path: Path) -> None:
    pages = _windows_pages()
    pages[1].insert(
        pages[1].index("Impact Statement"),
        "15.0 Sequoia, it is now disabled by default but should be enabled.",
    )
    pdf = tmp_path / "version-in-rationale.pdf"
    _write_pdf(pdf, pages)

    controls = parse_controls(str(pdf))

    assert [item["control_id"] for item in controls] == ["1.2.3", "2.4.6"]
    assert "15.0 Sequoia" in (controls[0]["rationale"] or "")


def test_bitlocker_profile_header_is_a_control_boundary(tmp_path: Path) -> None:
    pages = _windows_pages()
    pages.extend(
        [
            [
                "0.0 Explicitly Not Mapped",
                "18.9.7.1.3 (BL) Ensure the invented BitLocker setting is set to 'True' (checked) (Automated)",
                "Profile Applicability",
                "Level 1 (L1) + BitLocker (BL)",
                "Level 2 (L2) + BitLocker (BL)",
                "Description",
                "Invented BitLocker description.",
                "Audit",
                "Run the invented BitLocker audit.",
                "Remediation",
                "Apply the invented BitLocker remediation.",
            ]
        ]
    )
    pdf = tmp_path / "bitlocker-profile.pdf"
    _write_pdf(pdf, pages)

    controls = parse_controls(str(pdf))

    assert [item["control_id"] for item in controls] == [
        "1.2.3",
        "2.4.6",
        "18.9.7.1.3",
    ]
    assert controls[-1]["profile"] == "BL"
    assert controls[-1]["assessment"] == "Automated"
    assert all(item["control_id"] != "0.0" for item in controls)


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
