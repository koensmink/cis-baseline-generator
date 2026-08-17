from __future__ import annotations

from cis_pdf2csv.mandatory.schema import MandatoryAssessment
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.source_identity import index_controls_by_source_identity

from .attack_paths import ATTACK_PATH_BY_ID
from .mapping import map_control


def enrich_assessments(
    controls: list[ControlRecord],
    assessments: list[MandatoryAssessment],
) -> list[MandatoryAssessment]:
    controls_by_identity = index_controls_by_source_identity(controls)
    enriched = []
    for assessment in assessments:
        if assessment.source_identity is None:
            raise ValueError("MandatoryAssessment is missing composite source identity")
        mappings = map_control(controls_by_identity[assessment.source_identity], assessment)
        reliable = any(
            item.confidence == "High"
            and item.mitigation_strength in {"primary", "complementary"}
            for item in mappings
        )
        proposal = assessment.proposal
        review_note = assessment.review_note
        exclusions = list(assessment.exclusion_reasons)
        if proposal == "Candidate Mandatory" and not reliable:
            proposal = "Review Required"
            marker = "ATTACK_PATH_MAPPING_REQUIRED"
            if marker not in exclusions:
                exclusions.append(marker)
            review_note = marker
        enriched.append(
            assessment.model_copy(
                update={
                    "proposal": proposal,
                    "review_note": review_note,
                    "exclusion_reasons": exclusions,
                    "capability_ids": sorted({item.capability_id for item in mappings}),
                    "attack_path_ids": sorted({item.attack_path_id for item in mappings}),
                    "attack_path_names": sorted(
                        {ATTACK_PATH_BY_ID[item.attack_path_id].name for item in mappings}
                    ),
                    "attack_stages": sorted({item.attack_stage for item in mappings}),
                    "mitigation_roles": sorted({item.mitigation_role for item in mappings}),
                    "mitigation_strengths": sorted(
                        {item.mitigation_strength for item in mappings}
                    ),
                    "mapping_confidences": sorted({item.confidence for item in mappings}),
                    "attack_path_rationale": " ".join(item.rationale for item in mappings) or None,
                    "attack_path_mappings": mappings,
                }
            )
        )
    return enriched
