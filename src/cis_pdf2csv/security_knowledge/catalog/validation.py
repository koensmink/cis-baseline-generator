from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .registry import ID_PATTERNS, SecurityKnowledgeCatalog


class ValidationFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    code: str
    severity: Literal["error", "warning"]
    object_type: str
    object_id: str
    message: str
    required_action: str


def _error(code: str, kind: str, identifier: str, message: str) -> ValidationFinding:
    return ValidationFinding(code=code, severity="error", object_type=kind, object_id=identifier, message=message, required_action="Correct the catalog object before activation.")


def validate_catalog(catalog: SecurityKnowledgeCatalog) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    collections = (
        ("capability", "capability_id", catalog.capabilities),
        ("boundary", "boundary_id", catalog.boundary_definitions),
        ("boundary_set", "boundary_set_id", catalog.boundary_set_definitions),
        ("threat", "threat_scenario_id", catalog.threat_scenarios),
        ("technique", "technique_id", catalog.attack_techniques),
        ("path", "attack_path_id", catalog.attack_paths),
        ("outcome", "outcome_id", catalog.security_outcomes),
    )
    active: dict[str, set[str]] = {}
    for kind, field, objects in collections:
        active[kind] = {getattr(item, field) for item in objects if item.lifecycle_status == "active"}
        for item in objects:
            identifier = getattr(item, field)
            if ID_PATTERNS[kind].fullmatch(identifier) is None:
                findings.append(_error("INVALID_IDENTIFIER", kind, identifier, "Identifier does not match its normative grammar."))
            if not item.provenance.authority or not item.provenance.method:
                findings.append(_error("MISSING_PROVENANCE", kind, identifier, "Catalog provenance is incomplete."))

    for boundary in catalog.boundary_definitions:
        for identifier in boundary.related_capability_ids:
            if identifier not in active["capability"]:
                findings.append(_error("INACTIVE_CAPABILITY_REFERENCE", "boundary", boundary.boundary_id, identifier))
    for boundary_set in catalog.boundary_set_definitions:
        if boundary_set.boundary_definition_id not in active["boundary"]:
            findings.append(_error("UNRESOLVED_BOUNDARY_REFERENCE", "boundary_set", boundary_set.boundary_set_id, boundary_set.boundary_definition_id))
        if not boundary_set.required_sub_boundaries or not boundary_set.completeness_rules:
            findings.append(_error("INCOMPLETE_BOUNDARY_SET_DEFINITION", "boundary_set", boundary_set.boundary_set_id, "Required effects and completeness rules are mandatory."))
    for threat in catalog.threat_scenarios:
        semantics = (threat.attacker_position, threat.abused_weakness, threat.attacker_action, threat.attacker_objective, threat.immediate_outcome, threat.technical_impact)
        if threat.lifecycle_status == "active" and (not all(semantics) or not threat.preconditions or not threat.targeted_assets or not threat.evidence):
            findings.append(_error("INCOMPLETE_THREAT_SCENARIO", "threat", threat.threat_scenario_id, "Active threat semantics and curated evidence are required."))
        for identifier in threat.boundary_ids:
            if identifier not in active["boundary"]:
                findings.append(_error("INACTIVE_BOUNDARY_REFERENCE", "threat", threat.threat_scenario_id, identifier))
        for identifier in threat.technique_ids:
            if identifier not in active["technique"]:
                findings.append(_error("INACTIVE_TECHNIQUE_REFERENCE", "threat", threat.threat_scenario_id, identifier))
    for technique in catalog.attack_techniques:
        for mapping in technique.external_mappings:
            valid = (mapping.framework == "mitre-attack" and re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", mapping.external_id)) or (mapping.framework == "cwe" and re.fullmatch(r"CWE-[1-9][0-9]*", mapping.external_id))
            if not valid:
                findings.append(_error("INVALID_EXTERNAL_MAPPING", "technique", technique.technique_id, mapping.external_id))
    for path in catalog.attack_paths:
        if path.lifecycle_status == "active" and not path.threat_scenario_ids:
            findings.append(_error("ACTIVE_PATH_WITHOUT_SCENARIO", "path", path.attack_path_id, "Active paths require an active threat scenario."))
        if path.lifecycle_status == "active" and not path.security_outcome_ids:
            findings.append(_error("ACTIVE_PATH_WITHOUT_OUTCOME", "path", path.attack_path_id, "Active paths require an active outcome."))
        if path.attack_path_id == "AP-010" and path.lifecycle_status == "active" and (not path.threat_scenario_ids or not path.security_outcome_ids):
            findings.append(_error("AP010_ACTIVE_EMPTY", "path", path.attack_path_id, "AP-010 cannot be active and empty."))
        for identifier in path.threat_scenario_ids:
            if identifier not in active["threat"]:
                findings.append(_error("INACTIVE_THREAT_REFERENCE", "path", path.attack_path_id, identifier))
        for identifier in path.security_outcome_ids:
            if identifier not in active["outcome"]:
                findings.append(_error("INACTIVE_OUTCOME_REFERENCE", "path", path.attack_path_id, identifier))
        for identifier in path.technique_ids:
            if identifier not in active["technique"]:
                findings.append(_error("INACTIVE_TECHNIQUE_REFERENCE", "path", path.attack_path_id, identifier))
        for identifier in path.boundary_ids:
            if identifier not in active["boundary"]:
                findings.append(_error("INACTIVE_BOUNDARY_REFERENCE", "path", path.attack_path_id, identifier))
    legacy_ids = {item.legacy_boundary_set_id for item in catalog.migration_map}
    required_legacy = {"BS-HOST-FIREWALL-DOMAIN", "BS-HOST-FIREWALL-PRIVATE", "BS-HOST-FIREWALL-PUBLIC", "BS-SMB-SECURITY", "BS-LDAP-SECURITY", "BS-NTLM-SESSION", "BS-WINRM-SECURITY", "BS-RDP-SECURITY", "BS-MALWARE-PROTECTION", "BS-PRIVILEGED-CREDENTIALS"}
    for identifier in sorted(required_legacy - legacy_ids):
        findings.append(_error("MISSING_LEGACY_MIGRATION", "migration", identifier, "Current Phase-1 boundary set is not mapped."))
    for migration in catalog.migration_map:
        if migration.normative_boundary_set_id not in active["boundary_set"] or migration.normative_boundary_definition_id not in active["boundary"]:
            findings.append(_error("UNRESOLVED_MIGRATION", "migration", migration.legacy_boundary_set_id, "Normative migration target is unresolved."))
        for identifier in migration.capability_ids:
            if identifier not in active["capability"]:
                findings.append(_error("UNRESOLVED_MIGRATION_CAPABILITY", "migration", migration.legacy_boundary_set_id, identifier))
        for identifier in migration.attack_path_ids:
            if identifier not in active["path"]:
                findings.append(_error("UNRESOLVED_MIGRATION_PATH", "migration", migration.legacy_boundary_set_id, identifier))

    generic_objects = (
        *catalog.capabilities,
        *catalog.boundary_definitions,
        *catalog.boundary_set_definitions,
        *catalog.threat_scenarios,
        *catalog.attack_techniques,
        *catalog.attack_paths,
        *catalog.security_outcomes,
    )
    forbidden_keys = {"control_id", "source_recommendation_id", "mitigation_mapping_ids"}
    for generic_item in generic_objects:
        present = forbidden_keys & set(generic_item.model_dump())
        if present:
            findings.append(_error("SOURCE_CONTENT_IN_CATALOG", type(generic_item).__name__, repr(generic_item), f"Forbidden source or reverse-mapping fields: {sorted(present)}"))
    return sorted(findings, key=lambda item: (item.severity, item.code, item.object_type, item.object_id))
