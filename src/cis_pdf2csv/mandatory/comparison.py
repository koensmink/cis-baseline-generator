from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from cis_pdf2csv.schema import ControlRecord

from .features import ControlFeatures
from .schema import Relationship

MAX_RATIONALE_COMPARISON_LENGTH = 512
MIN_RATIONALE_TITLE_SIMILARITY = 0.15
MIN_RATIONALE_SUBJECT_OVERLAP = 0.20


@dataclass(frozen=True)
class ComparisonResult:
    related_control_ids: tuple[str, ...]
    relationship: Relationship
    ambiguous: bool = False


def _parent_id(control_id: str) -> str:
    parts = control_id.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else control_id


def _normalize(value: str | None) -> str:
    return " ".join((value or "").lower().split())


def _compatible_applicability(left: str, right: str) -> bool:
    return not left or not right or left == right


def compare_controls(controls: list[ControlRecord], features: list[ControlFeatures]) -> list[ComparisonResult]:
    count = len(controls)
    benchmark_keys = [(item.benchmark_name, item.benchmark_version) for item in controls]
    profiles = [_normalize(item.profile) for item in controls]
    applicability = [_normalize(item.applicability) for item in controls]
    hierarchy = [_parent_id(item.control_id) for item in controls]
    titles = [_normalize(item.title) for item in controls]
    rationales = [
        _normalize(item.rationale)[:MAX_RATIONALE_COMPARISON_LENGTH]
        for item in controls
    ]
    subjects = [item.subjects for item in features]
    related: list[set[str]] = [set() for _ in controls]
    duplicates = [False] * count

    # Each unordered pair is considered exactly once. Similarity work happens
    # only after benchmark, scope, hierarchy and subject gates have passed.
    for left_index in range(count):
        for right_index in range(left_index + 1, count):
            if benchmark_keys[left_index] != benchmark_keys[right_index]:
                continue
            if profiles[left_index] != profiles[right_index]:
                continue
            if not _compatible_applicability(applicability[left_index], applicability[right_index]):
                continue

            hierarchical = hierarchy[left_index] == hierarchy[right_index]
            shared_subjects = subjects[left_index] & subjects[right_index]
            shared_subject_count = len(shared_subjects)
            if not hierarchical and shared_subject_count < 2:
                continue

            title_similarity = SequenceMatcher(
                None,
                titles[left_index],
                titles[right_index],
            ).ratio()
            is_related = hierarchical or title_similarity >= 0.35

            # Rationale comparison is a bounded fallback for subject-plausible
            # pairs whose titles alone are not similar enough.
            all_subjects = subjects[left_index] | subjects[right_index]
            subject_overlap = shared_subject_count / len(all_subjects) if all_subjects else 0.0
            if (
                not is_related
                and title_similarity >= MIN_RATIONALE_TITLE_SIMILARITY
                and subject_overlap >= MIN_RATIONALE_SUBJECT_OVERLAP
            ):
                rationale_similarity = SequenceMatcher(
                    None,
                    rationales[left_index],
                    rationales[right_index],
                ).ratio()
                is_related = rationale_similarity >= 0.35

            if not is_related:
                continue

            related[left_index].add(controls[right_index].control_id)
            related[right_index].add(controls[left_index].control_id)
            if title_similarity >= 0.9:
                duplicates[left_index] = True
                duplicates[right_index] = True

    results: list[ComparisonResult] = []
    for index, _control in enumerate(controls):
        text = features[index].criterion_text
        if duplicates[index]:
            relationship: Relationship = "duplicate or overlapping control"
        elif any(marker in text for marker in ("timeout", "threshold", "log size", "retention period", "frequency", "duration")):
            relationship = "fine-tuning control"
        elif related[index] and any(marker in text for marker in ("additional", "supporting", "supplemental", "enhance", "prerequisite")):
            relationship = "supporting control"
        elif any(marker in text for marker in ("monitor", "alert", "report", "detect only", "detection only")):
            relationship = "detection-only control"
        elif any(marker in text for marker in ("block", "deny", "disable", "prevent", "prohibit", "require", "enforce")):
            relationship = "primary boundary control"
        elif related[index]:
            relationship = "supporting control"
        else:
            relationship = "independent control"

        results.append(ComparisonResult(tuple(sorted(related[index])), relationship))
    return results
