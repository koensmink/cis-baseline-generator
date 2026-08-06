from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from cis_pdf2csv.schema import ControlRecord

from .boundary_sets import BoundaryContext
from .features import ControlFeatures
from .schema import Relationship

MAX_RATIONALE_COMPARISON_LENGTH = 512
MIN_RATIONALE_TITLE_SIMILARITY = 0.15
MIN_RATIONALE_SUBJECT_OVERLAP = 0.20
AUDIT_MARKERS = ("audit ", "auditing ")
PREREQUISITE_MARKERS = ("prerequisite", "required for enforcement", "required for protection to function")
INFORMATION_HIDING_MARKERS = (
    "display", "hide", "visibility", "notification", "rename administrator",
    "rename the built-in administrator", "account details", "sign-in information",
)
OPERATIONAL_MARKERS = (
    "temporary folder", "temp folder", "auto-restart", "shutdown behavior",
    "session usability", "lifecycle", "scan schedule", "scheduled scan",
)
MALWARE_SUPPORTING_MARKERS = (
    "scan removable", "removable-drive scan", "quick scan", "scan excluded", "exclusions are visible",
    "visibility of exclusions", "scan scheduling", "notification behavior", "during oobe",
)
SUPPORTING_HARDENING_MARKERS = (
    "behavior of the elevation prompt", "detect application installations",
    "only elevate uiaccess", "enumerate administrator accounts",
)
PRIMARY_OVERRIDE_MARKERS = (
    "real-time protection", "behavior monitoring", "edr in block mode",
    "network protection in block mode", "admin approval mode enabled",
    "run all administrators in admin approval mode",
)
PRIMARY_ACTION_MARKERS = (
    " block", "block ", " deny", "deny ", " disable", "disabled", " disallow",
    " refuse", "restrict anonymous", " require", "required", " enforce",
    "do not store", "not stored", "do not send", "admin approval mode enabled",
)
BOUNDARY_SUBJECT_MARKERS = (
    "authentication", "credential", "password", "privileged", "admin approval",
    "user account control", "remote access", "remote desktop", "rdp", "winrm",
    "remote shell", "redirection", "firewall", "network protection", "encryption",
    "unencrypted", "plaintext", "signing", "sandbox", "application control",
    "real-time protection", "behavior monitoring", "edr", "malware protection",
    "ntlm", "lan manager", "smbv1", "legacy protocol", "unsafe mechanism",
)


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


def compare_controls(
    controls: list[ControlRecord],
    features: list[ControlFeatures],
    boundary_contexts: list[BoundaryContext],
) -> list[ComparisonResult]:
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

    results: list[ComparisonResult] = []
    for index, control in enumerate(controls):
        text = _normalize(control.title)
        supporting = (
            any(marker in text for marker in MALWARE_SUPPORTING_MARKERS)
            or any(marker in text for marker in SUPPORTING_HARDENING_MARKERS)
            or (
                bool(related[index])
                and any(
                    marker in text
                    for marker in ("additional", "supporting", "supplemental", "enhance", "prerequisite")
                )
            )
        )
        boundary = boundary_contexts[index].membership
        if boundary and boundary.standalone:
            relationship: Relationship = "standalone primary boundary"
        elif boundary:
            relationship = "boundary-set core member"
        elif any(marker in text for marker in PREREQUISITE_MARKERS):
            relationship = "prerequisite"
        elif any(marker in text for marker in ("timeout", "threshold", "log size", "retention period", "frequency", "duration")):
            relationship = "fine-tuning"
        elif any(marker in text for marker in AUDIT_MARKERS):
            if (
                any(marker in text for marker in ("essential", "sole source"))
                and any(marker in text for marker in ("privilege escalation", "credential theft", "malware execution", "security state", "system integrity", "account compromise"))
            ):
                relationship = "standalone primary boundary"
            else:
                relationship = "detection-only"
        elif any(marker in text for marker in INFORMATION_HIDING_MARKERS):
            relationship = "information-hiding"
        elif any(marker in text for marker in OPERATIONAL_MARKERS):
            relationship = "operational"
        elif supporting:
            relationship = "supporting hardening"
        elif any(marker in text for marker in PRIMARY_OVERRIDE_MARKERS):
            relationship = "standalone primary boundary"
        elif any(marker in text for marker in ("monitor", "alert", "report", "detect only", "detection only")):
            relationship = "detection-only"
        elif (
            any(marker in f" {text}" for marker in PRIMARY_ACTION_MARKERS)
            and any(marker in text for marker in BOUNDARY_SUBJECT_MARKERS)
        ):
            relationship = "standalone primary boundary"
        elif related[index]:
            relationship = "supporting hardening"
        else:
            relationship = "operational"

        results.append(ComparisonResult(tuple(sorted(related[index])), relationship))
    return results
