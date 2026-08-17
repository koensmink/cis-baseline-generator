from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace

import pytest

from cis_pdf2csv.mandatory.schema import MandatoryAssessment
from cis_pdf2csv.mandatory.shadow import compare_shadow_assessments
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.catalog import (
    SECURITY_KNOWLEDGE_CATALOG,
    build_catalog,
)
from cis_pdf2csv.security_knowledge.catalog.registry import (
    ExternalMapping,
    SecurityKnowledgeCatalog,
)
from cis_pdf2csv.security_knowledge.compatibility import adapt_phase1_assessments


def assessment(control_id: str, proposal: str, boundary_set_id: str | None = None) -> MandatoryAssessment:
    return MandatoryAssessment.model_validate(
        {
            "control_id": control_id,
            "proposal": proposal,
            "control_family": "MC-04 Logging and auditing",
            "boundary_set_id": boundary_set_id,
            "relationship": "boundary-set core member" if boundary_set_id else "operational",
            "rationale": "Invented deterministic assessment rationale.",
            "confidence": "High" if proposal == "Candidate Mandatory" else "Medium",
        }
    )


def finding_codes(catalog: SecurityKnowledgeCatalog) -> set[str]:
    return {item.code for item in catalog.validate()}


def test_authoritative_catalog_builds_with_zero_errors() -> None:
    catalog = build_catalog()
    assert catalog.validate() == ()
    assert (len(catalog.capabilities), len(catalog.boundary_definitions), len(catalog.boundary_set_definitions)) == (10, 13, 9)
    assert (len(catalog.threat_scenarios), len(catalog.attack_techniques), len(catalog.attack_paths), len(catalog.security_outcomes)) == (18, 12, 13, 14)


def test_catalog_serialization_is_deterministic_and_round_trips() -> None:
    first = SECURITY_KNOWLEDGE_CATALOG.to_deterministic_json()
    second = build_catalog().to_deterministic_json()
    assert first == second
    assert json.loads(first)["validation_summary"] == {"errors": 0, "warnings": 0}


def test_duplicate_identifiers_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate capability_id"):
        replace(
            SECURITY_KNOWLEDGE_CATALOG,
            capabilities=SECURITY_KNOWLEDGE_CATALOG.capabilities
            + (SECURITY_KNOWLEDGE_CATALOG.capabilities[0],),
        )


def test_unresolved_and_inactive_references_are_rejected() -> None:
    boundary_set = SECURITY_KNOWLEDGE_CATALOG.boundary_set_definitions[0].model_copy(update={"boundary_definition_id": "BND-NETWORK-MISSING"})
    invalid = replace(SECURITY_KNOWLEDGE_CATALOG, boundary_set_definitions=(boundary_set,) + SECURITY_KNOWLEDGE_CATALOG.boundary_set_definitions[1:])
    assert "UNRESOLVED_BOUNDARY_REFERENCE" in finding_codes(invalid)
    capability = SECURITY_KNOWLEDGE_CATALOG.capabilities[3].model_copy(update={"lifecycle_status": "deprecated"})
    inactive = replace(SECURITY_KNOWLEDGE_CATALOG, capabilities=SECURITY_KNOWLEDGE_CATALOG.capabilities[:3] + (capability,) + SECURITY_KNOWLEDGE_CATALOG.capabilities[4:])
    assert "INACTIVE_CAPABILITY_REFERENCE" in finding_codes(inactive)


def test_active_path_requires_scenario_and_outcome_and_ap010_is_not_empty() -> None:
    path = SECURITY_KNOWLEDGE_CATALOG.attack_paths[9].model_copy(update={"threat_scenario_ids": (), "security_outcome_ids": ()})
    catalog = replace(SECURITY_KNOWLEDGE_CATALOG, attack_paths=SECURITY_KNOWLEDGE_CATALOG.attack_paths[:9] + (path,) + SECURITY_KNOWLEDGE_CATALOG.attack_paths[10:])
    assert {"ACTIVE_PATH_WITHOUT_SCENARIO", "ACTIVE_PATH_WITHOUT_OUTCOME", "AP010_ACTIVE_EMPTY"} <= finding_codes(catalog)


def test_normative_relationships_are_complete() -> None:
    catalog = SECURITY_KNOWLEDGE_CATALOG
    assert all(item.related_capability_ids for item in catalog.boundary_definitions)
    assert all(item.required_sub_boundaries and item.completeness_rules for item in catalog.boundary_set_definitions)
    assert all(item.technique_ids for item in catalog.threat_scenarios)
    assert all(item.security_outcome_ids for item in catalog.attack_paths)


def test_legacy_migration_covers_current_windows_boundary_sets() -> None:
    identifiers = {item.legacy_boundary_set_id for item in SECURITY_KNOWLEDGE_CATALOG.migration_map}
    assert {"BS-HOST-FIREWALL-DOMAIN", "BS-HOST-FIREWALL-PRIVATE", "BS-HOST-FIREWALL-PUBLIC", "BS-SMB-SECURITY", "BS-LDAP-SECURITY", "BS-NTLM-SESSION", "BS-WINRM-SECURITY", "BS-RDP-SECURITY", "BS-MALWARE-PROTECTION", "BS-PRIVILEGED-CREDENTIALS"} <= identifiers


def test_external_mapping_syntax_supports_mitre_and_cwe() -> None:
    provenance = SECURITY_KNOWLEDGE_CATALOG.provenance
    ExternalMapping(framework="mitre-attack", external_id="T1557.001", mapping_type="related", confidence="High", provenance=provenance)
    ExternalMapping(framework="cwe", external_id="CWE-319", mapping_type="weakness", confidence="High", provenance=provenance)
    technique = SECURITY_KNOWLEDGE_CATALOG.attack_techniques[0]
    bad = technique.model_copy(update={"external_mappings": (ExternalMapping(framework="cwe", external_id="319", mapping_type="weakness", confidence="High", provenance=provenance),)})
    catalog = replace(SECURITY_KNOWLEDGE_CATALOG, attack_techniques=(bad,) + SECURITY_KNOWLEDGE_CATALOG.attack_techniques[1:])
    assert "INVALID_EXTERNAL_MAPPING" in finding_codes(catalog)


def test_generic_catalog_does_not_embed_source_control_ids() -> None:
    for collection in (SECURITY_KNOWLEDGE_CATALOG.capabilities, SECURITY_KNOWLEDGE_CATALOG.boundary_definitions, SECURITY_KNOWLEDGE_CATALOG.boundary_set_definitions, SECURITY_KNOWLEDGE_CATALOG.threat_scenarios, SECURITY_KNOWLEDGE_CATALOG.attack_techniques, SECURITY_KNOWLEDGE_CATALOG.attack_paths, SECURITY_KNOWLEDGE_CATALOG.security_outcomes):
        assert "source_recommendation_id" not in json.dumps([item.model_dump(mode="json") for item in collection])


def test_adapter_enriches_27_candidates_without_changing_phase1_counts() -> None:
    legacy_ids = [item.legacy_boundary_set_id for item in SECURITY_KNOWLEDGE_CATALOG.migration_map]
    candidates = [assessment(f"C-{index:03d}", "Candidate Mandatory", legacy_ids[index % len(legacy_ids)]) for index in range(27)]
    all_assessments = candidates + [assessment(f"V-{index:03d}", "Review Required") for index in range(5)] + [assessment(f"R-{index:03d}", "Regular Control") for index in range(275)]
    result = adapt_phase1_assessments(all_assessments)
    assert len(result.resolutions) == 27
    assert result.findings == ()
    assert result.proposal_overrides == {}
    assert all(item.threat_scenario_ids and item.security_outcome_ids for item in result.resolutions)
    assert Counter(item.proposal for item in all_assessments) == {"Candidate Mandatory": 27, "Review Required": 5, "Regular Control": 275}


def test_shadow_validation_block_prevents_candidate_decision() -> None:
    catalog = SECURITY_KNOWLEDGE_CATALOG
    capability = catalog.capabilities[3].model_copy(update={"lifecycle_status": "deprecated"})
    invalid = replace(
        catalog,
        capabilities=catalog.capabilities[:3] + (capability,) + catalog.capabilities[4:],
    )
    record = ControlRecord.model_validate(
        {
            "benchmark_name": "Invented Benchmark",
            "benchmark_version": "1",
            "benchmark_date": "2026",
            "control_id": "S-001",
            "profile": "L1",
            "title": "Invented network boundary effect",
            "assessment": "Automated",
            "applicability": "All invented systems",
            "description": "Invented description.",
            "rationale": "Invented rationale.",
            "audit": "Invented audit.",
            "remediation": "Invented remediation.",
            "page_start": 1,
            "page_end": 1,
            "source_pdf_sha256": "a" * 64,
            "block_text_sha256": "b" * 64,
            "extracted_at_utc": "2026-01-01T00:00:00Z",
        }
    )
    legacy = assessment("S-001", "Candidate Mandatory", "BS-HOST-FIREWALL-DOMAIN")
    legacy = legacy.model_copy(
        update={
            "relationship": "standalone primary boundary",
            "confidence": "High",
            "applicability_mode": "universal",
        }
    )
    result = compare_shadow_assessments([record], [legacy], catalog=invalid)
    shadow = result.shadow_assessments[0]
    assert shadow.normative_proposal == "Review Required"
    assert "SHADOW-VALIDATION-BLOCKED" in shadow.difference_codes
    assert not shadow.cutover_eligible
