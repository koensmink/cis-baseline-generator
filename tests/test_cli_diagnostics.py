from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from cis_pdf2csv.cli import main as parser_main
from cis_pdf2csv.intune_mapper.cli import main as intune_main
from cis_pdf2csv.mandatory.cli import main as mandatory_main


def test_parser_cli_reports_missing_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing.pdf"
    assert parser_main([str(missing), "-o", str(tmp_path / "output.jsonl")]) == 2
    captured = capsys.readouterr()
    assert "Input file not found" in captured.out
    assert "Traceback" not in captured.out + captured.err


@pytest.mark.parametrize("entrypoint", [mandatory_main, intune_main])
def test_jsonl_clis_report_malformed_input_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    entrypoint: Callable[[list[str] | None], int],
) -> None:
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text('{"not": "complete"}\nnot-json\n', encoding="utf-8")
    output = tmp_path / ("mandatory.csv" if entrypoint is mandatory_main else "intune")
    with pytest.raises(SystemExit) as exc:
        entrypoint([str(malformed), "-o", str(output)])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "line 1" in captured.err
    assert "Traceback" not in captured.out + captured.err
