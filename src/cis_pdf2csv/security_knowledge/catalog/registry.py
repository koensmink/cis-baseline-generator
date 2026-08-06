from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from .validation import ValidationFinding

LifecycleStatus = Literal["draft", "active", "deprecated", "superseded"]
Confidence = Literal["High", "Medium", "Low"]

ID_PATTERNS = {
    "capability": re.compile(r"CAP-[0-9]{2,3}"),
    "boundary": re.compile(r"BND-[A-Z0-9]+(?:-[A-Z0-9]+)*"),
    "boundary_set": re.compile(r"BS-[A-Z0-9]+(?:-[A-Z0-9]+)*"),
    "threat": re.compile(r"TS-[0-9]{3,}"),
    "technique": re.compile(r"TEC-[0-9]{3,}"),
    "path": re.compile(r"AP-[0-9]{3,}"),
    "outcome": re.compile(r"OUT-[0-9]{3,}"),
}


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class CatalogProvenance(FrozenModel):
    authority: str
    method: str
    catalog_version: str
    reviewed_by: str
    reviewed_at: str


class CuratedEvidence(FrozenModel):
    source: str
    locator: str
    assertion: str
    confidence: Confidence = "High"


class SecurityCapability(FrozenModel):
    capability_id: str
    name: str
    definition: str
    security_objective: str
    included_security_effects: tuple[str, ...]
    excluded_effects: tuple[str, ...]
    examples: tuple[str, ...]
    lifecycle_status: LifecycleStatus = "active"
    provenance: CatalogProvenance


class BoundaryDefinition(FrozenModel):
    boundary_id: str
    name: str
    description: str
    protected_security_surface: str
    technology_scope: tuple[str, ...]
    assets: tuple[str, ...]
    required_security_effects: tuple[str, ...]
    related_capability_ids: tuple[str, ...]
    known_exclusions: tuple[str, ...]
    lifecycle_status: LifecycleStatus = "active"
    provenance: CatalogProvenance


class BoundarySetDefinition(FrozenModel):
    boundary_set_id: str
    boundary_definition_id: str
    name: str
    description: str
    required_sub_boundaries: tuple[str, ...]
    minimum_effective_roles: tuple[str, ...]
    completeness_rules: tuple[str, ...]
    alternatives: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    optional_supporting_effects: tuple[str, ...] = ()
    compensation_rules: tuple[str, ...] = ()
    applicability_expectations: tuple[str, ...] = ()
    lifecycle_status: LifecycleStatus = "active"
    provenance: CatalogProvenance


class ExternalMapping(FrozenModel):
    framework: Literal["mitre-attack", "cwe"]
    external_id: str
    external_url: str | None = None
    mapping_type: str
    confidence: Confidence
    provenance: CatalogProvenance


class AttackTechnique(FrozenModel):
    technique_id: str
    name: str
    description: str
    attack_stage: str
    affected_technologies: tuple[str, ...]
    prerequisites: tuple[str, ...]
    external_mappings: tuple[ExternalMapping, ...] = ()
    lifecycle_status: LifecycleStatus = "active"
    confidence: Confidence = "High"
    provenance: CatalogProvenance


class ThreatScenario(FrozenModel):
    threat_scenario_id: str
    name: str
    description: str
    attacker_position: str
    preconditions: tuple[str, ...]
    targeted_assets: tuple[str, ...]
    abused_weakness: str
    attacker_action: str
    attacker_objective: str
    immediate_outcome: str
    technical_impact: str
    boundary_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    evidence: tuple[CuratedEvidence, ...]
    lifecycle_status: LifecycleStatus = "active"
    confidence: Confidence = "High"
    provenance: CatalogProvenance


class SecurityOutcome(FrozenModel):
    outcome_id: str
    name: str
    description: str
    technical_impact: str
    lifecycle_status: LifecycleStatus = "active"
    provenance: CatalogProvenance


class AttackPath(FrozenModel):
    attack_path_id: str
    name: str
    description: str
    ordered_stages: tuple[str, ...]
    entry_conditions: tuple[str, ...]
    intermediate_conditions: tuple[str, ...]
    attacker_goals: tuple[str, ...]
    affected_assets: tuple[str, ...]
    security_outcome_ids: tuple[str, ...]
    threat_scenario_ids: tuple[str, ...]
    technique_ids: tuple[str, ...] = ()
    boundary_ids: tuple[str, ...] = ()
    residual_path_description: str
    lifecycle_status: LifecycleStatus = "active"
    confidence: Confidence = "High"
    provenance: CatalogProvenance
    successor_ids: tuple[str, ...] = ()


class LegacyKnowledgeMigration(FrozenModel):
    legacy_boundary_set_id: str
    normative_boundary_set_id: str
    normative_boundary_definition_id: str
    capability_ids: tuple[str, ...]
    attack_path_ids: tuple[str, ...]
    migration_status: Literal["mapped", "deprecated", "superseded"] = "mapped"
    notes: str
    superseded_by: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityKnowledgeCatalog:
    catalog_id: str
    catalog_version: str
    ontology_version: str
    lifecycle_status: LifecycleStatus
    capabilities: tuple[SecurityCapability, ...]
    boundary_definitions: tuple[BoundaryDefinition, ...]
    boundary_set_definitions: tuple[BoundarySetDefinition, ...]
    threat_scenarios: tuple[ThreatScenario, ...]
    attack_techniques: tuple[AttackTechnique, ...]
    attack_paths: tuple[AttackPath, ...]
    security_outcomes: tuple[SecurityOutcome, ...]
    migration_map: tuple[LegacyKnowledgeMigration, ...]
    provenance: CatalogProvenance

    def __post_init__(self) -> None:
        groups = (
            ("capability_id", self.capabilities),
            ("boundary_id", self.boundary_definitions),
            ("boundary_set_id", self.boundary_set_definitions),
            ("threat_scenario_id", self.threat_scenarios),
            ("technique_id", self.attack_techniques),
            ("attack_path_id", self.attack_paths),
            ("outcome_id", self.security_outcomes),
        )
        for field, objects in groups:
            values = [getattr(item, field) for item in objects]
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate {field}")

    def _get(self, field: str, value: str, objects: tuple[FrozenModel, ...]) -> FrozenModel:
        for item in objects:
            if getattr(item, field) == value:
                return item
        raise KeyError(value)

    def get_capability(self, value: str) -> SecurityCapability:
        return cast(SecurityCapability, self._get("capability_id", value, self.capabilities))

    def get_boundary(self, value: str) -> BoundaryDefinition:
        return cast(BoundaryDefinition, self._get("boundary_id", value, self.boundary_definitions))

    def get_boundary_set(self, value: str) -> BoundarySetDefinition:
        return cast(BoundarySetDefinition, self._get("boundary_set_id", value, self.boundary_set_definitions))

    def get_threat_scenario(self, value: str) -> ThreatScenario:
        return cast(ThreatScenario, self._get("threat_scenario_id", value, self.threat_scenarios))

    def get_technique(self, value: str) -> AttackTechnique:
        return cast(AttackTechnique, self._get("technique_id", value, self.attack_techniques))

    def get_attack_path(self, value: str) -> AttackPath:
        return cast(AttackPath, self._get("attack_path_id", value, self.attack_paths))

    def get_security_outcome(self, value: str) -> SecurityOutcome:
        return cast(SecurityOutcome, self._get("outcome_id", value, self.security_outcomes))

    def validate(self) -> tuple[ValidationFinding, ...]:
        from .validation import validate_catalog

        return tuple(validate_catalog(self))

    def model_dump(self, *, mode: str = "python") -> dict[str, object]:
        return {
            "catalog_id": self.catalog_id,
            "catalog_version": self.catalog_version,
            "ontology_version": self.ontology_version,
            "lifecycle_status": self.lifecycle_status,
            "capabilities": [item.model_dump(mode=mode) for item in self.capabilities],
            "boundary_definitions": [item.model_dump(mode=mode) for item in self.boundary_definitions],
            "boundary_set_definitions": [item.model_dump(mode=mode) for item in self.boundary_set_definitions],
            "threat_scenarios": [item.model_dump(mode=mode) for item in self.threat_scenarios],
            "attack_techniques": [item.model_dump(mode=mode) for item in self.attack_techniques],
            "attack_paths": [item.model_dump(mode=mode) for item in self.attack_paths],
            "security_outcomes": [item.model_dump(mode=mode) for item in self.security_outcomes],
            "migration_map": [item.model_dump(mode=mode) for item in self.migration_map],
            "provenance": self.provenance.model_dump(mode=mode),
        }

    def to_deterministic_json(self) -> str:
        payload = self.model_dump(mode="json")
        payload["validation_summary"] = _validation_summary(self.validate())
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def _validation_summary(findings: tuple[object, ...]) -> dict[str, int]:
    severities = [getattr(item, "severity", "error") for item in findings]
    return {"errors": severities.count("error"), "warnings": severities.count("warning")}
