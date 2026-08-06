from __future__ import annotations

from collections.abc import Iterable

from cis_pdf2csv.schema import ControlRecord

from .comparison import compare_controls
from .criteria import match_criteria
from .families import classify_family
from .features import extract_features
from .schema import MandatoryAssessment
from .shortlist import build_assessment


def assess_controls(records: Iterable[ControlRecord]) -> list[MandatoryAssessment]:
    """Assess controls deterministically; input order cannot change results."""
    controls = sorted(
        records,
        key=lambda item: (item.benchmark_name, item.benchmark_version, item.profile, item.control_id),
    )
    features = [extract_features(control) for control in controls]
    comparisons = compare_controls(controls, features)
    return [
        build_assessment(
            control,
            feature,
            comparison,
            classify_family(feature.criterion_text),
            match_criteria(feature.criterion_text),
        )
        for control, feature, comparison in zip(controls, features, comparisons)
    ]
