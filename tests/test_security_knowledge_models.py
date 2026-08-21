from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.attack_paths import ATTACK_PATHS, AttackPath
from cis_pdf2csv.security_knowledge.boundaries import (
    ApplicabilityMode,
    BoundaryDefinition,
    BoundaryEvaluation,
    BoundarySetDefinition,
    CompletenessStatus,
    DecisionScope,
    DeploymentState,
)
from cis_pdf2csv.security_knowledge.capabilities import CAPABILITIES
from cis_pdf2csv.security_knowledge.coverage import evaluate_mapping_coverage
from cis_pdf2csv.security_knowledge.evidence import EvidenceItem, EvidenceType
from cis_pdf2csv.security_knowledge.identifiers import (
    AttackPathId,
    BoundaryEvaluationId,
    BoundaryId,
    BoundarySetId,
    CapabilityId,
    MandatoryDecisionId,
    MappingId,
    OutcomeId,
    RiskId,
    TechniqueId,
    ThreatContextId,
    ThreatScenarioId,
    validate_identifier,
)
from cis_pdf2csv.security_knowledge.mitigation import (
    BoundaryRole,
    CompensatingControlEvaluation,
    EquivalenceType,
    MitigationMapping,
    MitigationRole,
    MitigationStrength,
)
from cis_pdf2csv.security_knowledge.phase1_mapping_adapter import (
    adapt_phase1_assessments_to_mappings,
)
from cis_pdf2csv.security_knowledge.provenance import (
    CatalogObjectProvenance,
    Confidence,
    DecisionProvenance,
    LifecycleStatus,
    MappingEvidenceProvenance,
    ReviewProvenance,
    SourceExtractionProvenance,
)
from cis_pdf2csv.security_knowledge.schema import MandatoryDecision, Proposal
from cis_pdf2csv.security_knowledge.threats import THREAT_SCENARIOS
from cis_pdf2csv.security_knowledge.validation import (
    DecisionEffect,
    KnowledgeCatalog,
    validate_attack_path,
    validate_boundary_evaluation,
    validate_compensation,
    validate_duplicate_effects,
    validate_mandatory_decision,
    validate_mapping,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def catalog_provenance() -> CatalogObjectProvenance:
    return CatalogObjectProvenance(
        catalog_authority="Invented catalog authority",
        catalog_version="1.0",
        object_version="1.0",
        creation_method="invented deterministic test",
    )


def evidence() -> EvidenceItem:
    return EvidenceItem(
        evidence_type=EvidenceType.SOURCE_CONTROL,
        source="Invented benchmark|1.0|L1|1.1",
        locator="pages 1-2",
        assertion="The invented setting enforces the stated boundary.",
        collection_method="synthetic fixture",
        confidence=Confidence.HIGH,
        timestamp=NOW,
    )


def boundary(status: LifecycleStatus = LifecycleStatus.ACTIVE) -> BoundaryDefinition:
    return BoundaryDefinition(
        boundary_id="BND-IDENTITY-AUTHENTICATION",
        name="Invented authentication boundary",
        description="Protects an invented authentication exchange.",
        technology_scope=["generic authentication protocols"],
        related_capability_ids=["CAP-01"],
        lifecycle_status=status,
        catalog_version="1.0",
        provenance=catalog_provenance(),
    )


def boundary_set() -> BoundarySetDefinition:
    return BoundarySetDefinition(
        boundary_set_id="BS-IDENTITY-AUTHENTICATION",
        boundary_definition_id="BND-IDENTITY-AUTHENTICATION",
        name="Invented authentication minimum set",
        description="Requires integrity and identity validation.",
        required_sub_boundaries=["message integrity", "identity validation"],
        minimum_effective_roles=["boundary_set_core_member"],
        completeness_rules=["both invented effects are selected"],
        lifecycle_status=LifecycleStatus.ACTIVE,
        catalog_version="1.0",
        provenance=catalog_provenance(),
    )


def mapping(
    *,
    mapping_id: str = "MAP-100",
    boundary_role: BoundaryRole = BoundaryRole.BOUNDARY_SET_CORE_MEMBER,
    strength: MitigationStrength = MitigationStrength.COMPLEMENTARY,
    role: MitigationRole = MitigationRole.PREVENT,
) -> MitigationMapping:
    return MitigationMapping(
        mapping_id=mapping_id,
        source_recommendation_id="Invented framework|Invented benchmark|1.0|L1|1.1",
        capability_id="CAP-01",
        boundary_definition_id="BND-IDENTITY-AUTHENTICATION",
        boundary_set_definition_id="BS-IDENTITY-AUTHENTICATION",
        threat_scenario_id="TS-001",
        attack_path_id="AP-001",
        attack_stage="authentication",
        boundary_role=boundary_role,
        mitigation_role=role,
        mitigation_strength=strength,
        enforced_sub_boundary="invented message integrity",
        attack_path_if_omitted="An invented relay path remains open.",
        evidence=[evidence()],
        confidence=Confidence.HIGH,
        applicability_mode=ApplicabilityMode.MANDATORY_WHEN_DEPLOYED,
        lifecycle_status=LifecycleStatus.ACTIVE,
        rule_version="1.0",
        ontology_version="1.0",
        provenance=MappingEvidenceProvenance(
            source_fields_used=["description", "rationale", "remediation"],
            evidence_reference_ids=["E-1"],
            mapping_method="invented deterministic rule",
            rule_version="1.0",
            ontology_version="1.0",
        ),
    )


def evaluation(
    status: CompletenessStatus = CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET,
    scope: DecisionScope = DecisionScope.BENCHMARK,
    deployment: DeploymentState = DeploymentState.NOT_EVALUATED,
) -> BoundaryEvaluation:
    return BoundaryEvaluation(
        evaluation_id="BEV-IDENTITY-TEST",
        boundary_definition_id="BND-IDENTITY-AUTHENTICATION",
        boundary_set_definition_id="BS-IDENTITY-AUTHENTICATION",
        decision_scope=scope,
        benchmark_profile="L1",
        applicability_mode=ApplicabilityMode.MANDATORY_WHEN_DEPLOYED,
        deployment_state=deployment,
        selected_control_ids=["1.1", "1.2"],
        selected_alternatives=[],
        completeness_status=status,
        residual_path="No residual path remains when both invented effects are active.",
        confidence=Confidence.HIGH,
        evidence=[evidence()],
    )


def decision(
    *,
    proposal: Proposal = Proposal.CANDIDATE,
    scope: DecisionScope = DecisionScope.BENCHMARK,
    deployment: DeploymentState = DeploymentState.NOT_EVALUATED,
    reviews: list[ReviewProvenance] | None = None,
) -> MandatoryDecision:
    return MandatoryDecision(
        decision_id="MD-100",
        source_recommendation_id="Invented framework|Invented benchmark|1.0|L1|1.1",
        proposal=proposal,
        mitigation_mapping_ids=["MAP-100"],
        boundary_evaluation_ids=["BEV-IDENTITY-TEST"],
        decision_scope=scope,
        applicability_mode=ApplicabilityMode.MANDATORY_WHEN_DEPLOYED,
        deployment_state=deployment,
        confidence=Confidence.HIGH,
        rationale="The invented complementary control closes a required sub-boundary.",
        evidence=[evidence()],
        review_provenance=reviews or [],
        decision_provenance=DecisionProvenance(
            source_revision="source-1",
            mapping_revisions=["MAP-100@1"],
            boundary_evaluation_revisions=["BEV-IDENTITY-TEST@1"],
            rule_version="1.0",
            catalog_version="1.0",
            ontology_version="1.0",
            decision_timestamp=NOW,
            source_extraction_confidence=Confidence.HIGH,
        ),
        lifecycle_status=LifecycleStatus.ACTIVE,
    )


def catalog(boundary_object: BoundaryDefinition | None = None) -> KnowledgeCatalog:
    return KnowledgeCatalog(
        capabilities={"CAP-01": CAPABILITIES[0]},
        boundaries={"BND-IDENTITY-AUTHENTICATION": boundary_object or boundary()},
        boundary_sets={"BS-IDENTITY-AUTHENTICATION": boundary_set()},
        threats={"TS-001": THREAT_SCENARIOS[0]},
        attack_paths={"AP-001": ATTACK_PATHS[0]},
    )


@pytest.mark.parametrize(
    ("identifier_type", "valid"),
    [
        (CapabilityId, "CAP-01"),
        (CapabilityId, "CAP-100"),
        (BoundaryId, "BND-IDENTITY-AUTH"),
        (BoundarySetId, "BS-IDENTITY-AUTH"),
        (BoundaryEvaluationId, "BEV-IDENTITY-AUTH"),
        (ThreatScenarioId, "TS-001"),
        (TechniqueId, "TEC-1000"),
        (AttackPathId, "AP-001"),
        (OutcomeId, "OUT-001"),
        (RiskId, "RISK-001"),
        (MappingId, "MAP-001"),
        (MandatoryDecisionId, "MD-001"),
        (ThreatContextId, "THRCTX-INVENTED-001"),
    ],
)
def test_every_identifier_grammar(identifier_type: Any, valid: str) -> None:
    assert TypeAdapter(identifier_type).validate_python(valid) == valid
    for invalid in (valid.lower(), f" {valid}", valid.replace("-", "_"), f"{valid}-"):
        with pytest.raises(ValidationError):
            TypeAdapter(identifier_type).validate_python(invalid)


def test_unknown_identifier_prefix_is_rejected() -> None:
    with pytest.raises(ValueError):
        validate_identifier("UNKNOWN-001")


def test_catalog_and_source_provenance_are_separate() -> None:
    source = SourceExtractionProvenance(
        source_framework="Invented framework",
        benchmark_identity="Invented benchmark",
        benchmark_version="1.0",
        source_hash="a" * 64,
        block_hash="b" * 64,
        page_range="1-2",
        parser_version="test",
        extraction_method="synthetic",
        extracted_at=NOW,
        confidence=Confidence.HIGH,
    )
    catalog_item = catalog_provenance()
    assert source.source_hash
    assert not hasattr(catalog_item, "source_hash")


def test_atomic_mapping_has_three_separate_role_dimensions() -> None:
    item = mapping()
    assert item.boundary_role == BoundaryRole.BOUNDARY_SET_CORE_MEMBER
    assert item.mitigation_role == MitigationRole.PREVENT
    assert item.mitigation_strength == MitigationStrength.COMPLEMENTARY
    assert "attack_path_ids" not in type(item).model_fields


def test_active_attack_path_requires_scenario_and_active_reference() -> None:
    with pytest.raises(ValidationError):
        AttackPath.model_validate({**ATTACK_PATHS[0].model_dump(), "threat_scenario_ids": []})
    unresolved = ATTACK_PATHS[0].model_copy(update={"threat_scenario_ids": ["TS-999"]})
    findings = validate_attack_path(unresolved, {})
    assert findings[0].decision_effect == DecisionEffect.INVALID_OBJECT


def test_active_and_deprecated_reference_validation() -> None:
    item = mapping()
    active_findings = validate_mapping(item, catalog())
    assert active_findings == []
    deprecated_catalog = catalog(boundary(LifecycleStatus.DEPRECATED))
    assert any(
        finding.code == "SKV-INACTIVE-REFERENCE"
        for finding in validate_mapping(item, deprecated_catalog)
    )
    assert validate_mapping(item, deprecated_catalog, historical_evaluation=True) == []


def test_benchmark_conditional_candidate_is_valid() -> None:
    item = decision()
    findings = validate_mandatory_decision(
        item,
        {"MAP-100": mapping()},
        {"BEV-IDENTITY-TEST": evaluation()},
        catalog(),
    )
    assert findings == []


def test_environment_candidate_requires_deployed_state() -> None:
    item = decision(scope=DecisionScope.ENVIRONMENT, deployment=DeploymentState.UNKNOWN)
    findings = validate_mandatory_decision(
        item,
        {"MAP-100": mapping()},
        {"BEV-IDENTITY-TEST": evaluation(scope=DecisionScope.ENVIRONMENT, deployment=DeploymentState.UNKNOWN)},
        catalog(),
    )
    assert {finding.code for finding in findings} == {
        "SKV-APPLICABILITY",
        "SKV-ENVIRONMENT-DEPLOYMENT",
    }


def test_environment_deployed_candidate_is_valid() -> None:
    item = decision(scope=DecisionScope.ENVIRONMENT, deployment=DeploymentState.DEPLOYED)
    findings = validate_mandatory_decision(
        item,
        {"MAP-100": mapping()},
        {"BEV-IDENTITY-TEST": evaluation(scope=DecisionScope.ENVIRONMENT, deployment=DeploymentState.DEPLOYED)},
        catalog(),
    )
    assert findings == []


def test_unresolved_applicability_requires_review() -> None:
    item = decision().model_copy(update={"applicability_mode": ApplicabilityMode.UNRESOLVED})
    findings = validate_mandatory_decision(
        item,
        {"MAP-100": mapping()},
        {"BEV-IDENTITY-TEST": evaluation()},
        catalog(),
    )
    assert any(finding.code == "SKV-APPLICABILITY" for finding in findings)


def test_definitive_mandatory_requires_human_review() -> None:
    with pytest.raises(ValidationError):
        decision(proposal=Proposal.DEFINITIVE)
    approved = ReviewProvenance(
        reviewer="Invented human reviewer",
        review_authority="Security architecture board",
        reviewed_at=NOW,
        disposition="approved",
        reviewed_object_revision="MD-100@1",
    )
    assert decision(proposal=Proposal.DEFINITIVE, reviews=[approved]).proposal == Proposal.DEFINITIVE


def test_complementary_supporting_and_detection_coverage() -> None:
    complementary = evaluate_mapping_coverage(
        [mapping()],
        {"BND-IDENTITY-AUTHENTICATION": CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET},
    )
    assert complementary["AP-001"] == CompletenessStatus.COMPLETE_COMPLEMENTARY_CORE_SET

    supporting_mapping = mapping(
        boundary_role=BoundaryRole.SUPPORTING_HARDENING,
        strength=MitigationStrength.SUPPORTING,
    )
    assert evaluate_mapping_coverage([supporting_mapping], {})["AP-001"] == CompletenessStatus.SUPPORTING_ONLY
    detection_mapping = mapping(
        boundary_role=BoundaryRole.DETECTION_ONLY,
        strength=MitigationStrength.SUPPORTING,
        role=MitigationRole.DETECT,
    )
    assert evaluate_mapping_coverage([detection_mapping], {})["AP-001"] == CompletenessStatus.DETECTION_ONLY


def test_supporting_control_cannot_be_full_compensation() -> None:
    supporting_mapping = mapping(
        boundary_role=BoundaryRole.SUPPORTING_HARDENING,
        strength=MitigationStrength.SUPPORTING,
    )
    compensation = CompensatingControlEvaluation(
        evaluation_id="COMP-TEST-1",
        source_mapping_id="MAP-100",
        candidate_compensating_control_id="Invented|1.0|L1|1.2",
        replaced_security_effect="invented message integrity",
        protected_scope="invented systems",
        equivalence_type=EquivalenceType.FULL,
        applicability_mode=ApplicabilityMode.UNIVERSAL,
        evidence=[evidence()],
        confidence=Confidence.HIGH,
        residual_attack_path="No path claimed by the proposed compensation.",
        reviewer="Invented reviewer",
        status=LifecycleStatus.ACTIVE,
    )
    assert validate_compensation(compensation, supporting_mapping)[0].code == "SKV-INVALID-COMPENSATION"


def test_duplicate_effect_and_incomplete_boundary_findings_are_deterministic() -> None:
    duplicate = mapping(mapping_id="MAP-101").model_copy(
        update={"source_recommendation_id": "Invented framework|Invented benchmark|1.0|L1|1.2"}
    )
    primary = mapping(
        boundary_role=BoundaryRole.STANDALONE_PRIMARY_BOUNDARY,
        strength=MitigationStrength.PRIMARY,
    )
    duplicate = duplicate.model_copy(
        update={
            "boundary_role": BoundaryRole.STANDALONE_PRIMARY_BOUNDARY,
            "mitigation_strength": MitigationStrength.PRIMARY,
        }
    )
    forward = validate_duplicate_effects([primary, duplicate])
    reverse = validate_duplicate_effects([duplicate, primary])
    assert sorted(item.model_dump_json() for item in forward) == sorted(
        item.model_dump_json() for item in reverse
    )
    gap = validate_boundary_evaluation(
        evaluation(CompletenessStatus.INCOMPLETE_BOUNDARY)
    )
    assert gap[0].decision_effect == DecisionEffect.COVERAGE_GAP


def test_audit_only_mapping_evidence_is_rejected() -> None:
    item = mapping().model_copy(
        update={
            "provenance": MappingEvidenceProvenance(
                source_fields_used=["audit", "references"],
                evidence_reference_ids=["E-1"],
                mapping_method="invented rule",
                rule_version="1.0",
                ontology_version="1.0",
            )
        }
    )
    findings = validate_mapping(item, catalog())
    assert any(finding.code == "SKV-AUDIT-REFERENCE-ONLY" for finding in findings)


def invented_control(control_id: str, title: str) -> ControlRecord:
    values: dict[str, Any] = {
        "benchmark_name": "Invented Microsoft Windows Server Benchmark",
        "benchmark_version": "1.0",
        "benchmark_date": "2026",
        "control_id": control_id,
        "profile": "L1",
        "title": title,
        "assessment": "Automated",
        "applicability": "Invented servers",
        "description": f"{title} directly enforces the invented network boundary.",
        "rationale": f"Without {title}, an invented inbound path remains open.",
        "impact": "Unapproved traffic is rejected.",
        "audit": f"Verify {title}.",
        "remediation": title,
        "default_value": "Not configured",
        "references": "Invented reference",
        "page_start": 1,
        "page_end": 2,
        "source_pdf_sha256": "a" * 64,
        "block_text_sha256": "b" * 64,
        "extracted_at_utc": "2026-01-01T00:00:00Z",
        "parser_version": "test",
    }
    return ControlRecord.model_validate(values)


def test_phase1_compatibility_adapter_is_deterministic_and_non_mutating() -> None:
    controls = [
        invented_control("9.1", "Windows Firewall Domain firewall state enabled"),
        invented_control("9.2", "Windows Firewall Domain inbound connections block by default"),
    ]
    assessments = assess_controls(controls)
    original = [item.model_dump() for item in assessments]
    forward = adapt_phase1_assessments_to_mappings(controls, assessments)
    reverse = adapt_phase1_assessments_to_mappings(list(reversed(controls)), list(reversed(assessments)))
    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")
    assert [item.model_dump() for item in assessments] == original
    assert all(item.boundary_role == BoundaryRole.BOUNDARY_SET_CORE_MEMBER for item in forward.mappings)
    assert all(value == Proposal.CANDIDATE for value in forward.proposal_by_control_id.values())
