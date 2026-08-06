from __future__ import annotations

import json
from pathlib import Path

from cis_pdf2csv.mandatory.schema import MandatoryAssessment

from .coverage import build_coverage_report


def write_coverage_json(assessments: list[MandatoryAssessment], path: Path) -> None:
    path.write_text(
        json.dumps(build_coverage_report(assessments), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
