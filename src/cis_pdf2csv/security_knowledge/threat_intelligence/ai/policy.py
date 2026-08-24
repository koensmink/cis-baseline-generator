from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AIInterpretationPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = "AI-THREAT-AUTHORITY"
    policy_version: str = "1.0"
    source_grounded_only: bool = True
    allow_external_model_knowledge: bool = False
    allowed_assertions: tuple[str, ...] = (
        "summarize_advisory",
        "candidate_technologies",
        "candidate_threat_scenarios",
        "candidate_techniques",
        "candidate_attack_paths",
        "source_dates_and_references",
        "explicit_activity_state",
        "confidence_and_severity",
        "uncertainty",
    )
    prohibited_output_fields: tuple[str, ...] = (
        "advisory_action",
        "base_proposal",
        "boundary_ids",
        "boundary_completeness",
        "candidate_mandatory",
        "cis_control_id",
        "cis_control_ids",
        "control_id",
        "control_ids",
        "customer_vulnerability_status",
        "mandatory_criterion_id",
        "mandatory_criterion_ids",
        "mandatory_status",
        "proposal",
        "proposed_boundary_ids",
        "proposed_outcome_ids",
        "outcome_ids",
        "threat_relevance",
    )
    material_assertion_types: tuple[str, ...] = (
        "activity_state",
        "affected_technology_family",
        "attack_path_id",
        "technique_id",
        "threat_scenario_id",
    )


DEFAULT_AI_INTERPRETATION_POLICY = AIInterpretationPolicy()

__all__ = ["DEFAULT_AI_INTERPRETATION_POLICY", "AIInterpretationPolicy"]
