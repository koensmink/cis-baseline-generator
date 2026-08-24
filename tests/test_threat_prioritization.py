from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.mandatory.schema import (
    MandatoryAssessment,
    OverlapType,
    Relationship,
)
from cis_pdf2csv.mandatory.schema import (
    Proposal as MandatoryProposal,
)
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.boundaries import ApplicabilityMode
from cis_pdf2csv.security_knowledge.catalog import SECURITY_KNOWLEDGE_CATALOG
from cis_pdf2csv.security_knowledge.evidence import EvidenceItem, EvidenceType
from cis_pdf2csv.security_knowledge.mitigation import (
    BoundaryRole,
    MitigationMapping,
    MitigationRole,
    MitigationStrength,
)
from cis_pdf2csv.security_knowledge.phase1_mapping_adapter import (
    adapt_phase1_assessments_to_mappings,
)
from cis_pdf2csv.security_knowledge.provenance import Confidence, LifecycleStatus
from cis_pdf2csv.security_knowledge.schema import Proposal
from cis_pdf2csv.security_knowledge.threat_intelligence import (
    AdvisoryAction,
    ResolutionStatus,
    ThreatApplicabilityScope,
    ThreatContext,
    ThreatContextProvenance,
    ThreatRelevance,
    ThreatSeverity,
    ThreatSourceType,
    prioritize_threat_projections,
    project_threat_resolutions,
    resolve_threat_context,
    summarize_threat_priority,
)
from cis_pdf2csv.source_identity import SourceIdentity

NOW = datetime(2026, 8, 24, 12, tzinfo=timezone.utc)


def identity(
    control_id: str,
    *,
    family: str = "microsoft_365",
    version: str = "synthetic-v1",
    profile: str = "L1",
) -> SourceIdentity:
    return SourceIdentity(
        benchmark_family=family,
        benchmark_name="Invented security benchmark",
        benchmark_version=version,
        benchmark_profile=profile,
        control_id=control_id,
    )


def assessment(
    source: SourceIdentity,
    *,
    proposal: MandatoryProposal = "Regular Control",
    relationship: Relationship = "standalone primary boundary",
    overlap: OverlapType = "none",
    related: tuple[str, ...] = (),
) -> MandatoryAssessment:
    return MandatoryAssessment(
        control_id=source.control_id,
        source_identity=source,
        title=f"Synthetic control {source.control_id}",
        proposal=proposal,
        control_family="synthetic identity",
        relationship=relationship,
        overlap_type=overlap,
        related_control_ids=list(related),
        rationale="Synthetic assessment rationale.",
        confidence="High",
    )


def mapping(
    source: SourceIdentity,
    number: int,
    *,
    role: BoundaryRole = BoundaryRole.STANDALONE_PRIMARY_BOUNDARY,
    mitigation_role: MitigationRole = MitigationRole.PROTECT,
    strength: MitigationStrength = MitigationStrength.PRIMARY,
    confidence: Confidence = Confidence.HIGH,
    applicability: ApplicabilityMode = ApplicabilityMode.UNIVERSAL,
    effect: str = "bind session state to its originating context",
    attack_path_id: str = "AP-019",
    boundary_id: str = "BND-IDENTITY-AUTHENTICATION-SESSION-BINDING",
    technique_id: str = "TEC-016",
) -> MitigationMapping:
    return MitigationMapping(
        mapping_id=f"MAP-{number:03d}",
        source_recommendation_id=source.serialize(),
        capability_id="CAP-02",
        boundary_definition_id=boundary_id,
        attack_path_id=attack_path_id,
        attack_stage="session replay",
        boundary_role=role,
        mitigation_role=mitigation_role,
        mitigation_strength=strength,
        technique_ids=[technique_id],
        enforced_sub_boundary=effect,
        attack_path_if_omitted="Session replay remains possible.",
        evidence=[
            EvidenceItem(
                evidence_type=EvidenceType.SOURCE_CONTROL,
                source=source.serialize(),
                locator="synthetic fixture",
                assertion="The invented control enforces the stated session effect.",
                collection_method="synthetic deterministic fixture",
                confidence=confidence,
            )
        ],
        confidence=confidence,
        applicability_mode=applicability,
        lifecycle_status=LifecycleStatus.ACTIVE,
        rule_version="phase3-test",
        ontology_version="1.0",
    )


def context(
    context_id: str = "THRCTX-SYNTH-SESSION-REPLAY",
    *,
    confidence: Confidence = Confidence.HIGH,
    valid_from: datetime | None = None,
    attack_path_id: str = "AP-019",
) -> ThreatContext:
    return ThreatContext(
        threat_context_id=context_id,
        title="Synthetic session-token replay",
        description="Invented activity reuses synthetic authenticated state.",
        source_type=ThreatSourceType.ANALYST,
        source_name="Synthetic test authority",
        source_reference=f"SYNTH-{context_id}",
        valid_from=valid_from or NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
        confidence=confidence,
        severity=ThreatSeverity.HIGH,
        lifecycle_status=LifecycleStatus.ACTIVE,
        attack_path_ids=(attack_path_id,),
        targeted_asset_classes=("synthetic sessions",),
        affected_technology_families=("synthetic identity",),
        applicability_scope=ThreatApplicabilityScope.TECHNOLOGY_FAMILY,
        provenance=ThreatContextProvenance(
            authority="Synthetic test authority",
            creation_method="invented fixture",
            model_version="1.0",
            object_version="1",
        ),
    )


def resolution(item: ThreatContext | None = None):  # type: ignore[no-untyped-def]
    return resolve_threat_context(
        item or context(), SECURITY_KNOWLEDGE_CATALOG, at_time=NOW
    )


def overlay(
    resolutions,  # type: ignore[no-untyped-def]
    mappings: tuple[MitigationMapping, ...],
    assessments: tuple[MandatoryAssessment, ...],
):  # type: ignore[no-untyped-def]
    projected = project_threat_resolutions(resolutions, mappings, assessments)
    return projected, prioritize_threat_projections(projected.projections)


def test_no_threats_and_inactive_threats_have_no_overlay() -> None:
    source = identity("A.1")
    assert overlay((), (mapping(source, 1),), (assessment(source),))[1] == ()
    inactive = resolution(context(valid_from=NOW + timedelta(hours=1)))
    assert inactive.status == ResolutionStatus.INACTIVE
    assert overlay((inactive,), (mapping(source, 1),), (assessment(source),))[1] == ()


def test_direct_preventive_mapping_is_high_and_regular_base_is_immutable() -> None:
    source = identity("A.2")
    base = assessment(source, proposal="Regular Control")
    projected, results = overlay((resolution(),), (mapping(source, 2),), (base,))
    assert projected.projections[0].base_proposal == Proposal.REGULAR
    assert results[0].threat_relevance == ThreatRelevance.HIGH
    assert results[0].advisory_action == AdvisoryAction.PRIORITIZE
    assert results[0].base_proposal == Proposal.REGULAR
    assert "Base proposal remains Regular Control" in results[0].rationale


def test_medium_confidence_and_partial_resolution_cap_at_elevated() -> None:
    source = identity("A.3")
    medium = resolution(context(confidence=Confidence.MEDIUM))
    partial = resolution().model_copy(
        update={"status": ResolutionStatus.PARTIALLY_RESOLVED}
    )
    for item in (medium, partial):
        result = overlay((item,), (mapping(source, 3),), (assessment(source),))[1][0]
        assert result.threat_relevance == ThreatRelevance.ELEVATED
        assert result.advisory_action == AdvisoryAction.REVIEW


def test_unresolved_applicability_and_conditional_deployment_are_review_capped() -> (
    None
):
    source = identity("A.4")
    unresolved = resolution().model_copy(
        update={"applicability_scope": ThreatApplicabilityScope.UNRESOLVED}
    )
    result = overlay(
        (unresolved,),
        (mapping(source, 4, applicability=ApplicabilityMode.MANDATORY_WHEN_DEPLOYED),),
        (assessment(source),),
    )[1][0]
    assert result.threat_relevance == ThreatRelevance.ELEVATED
    assert result.advisory_action == AdvisoryAction.REVIEW
    assert any("deployment is not inferred" in item.message for item in result.findings)


def test_privileged_role_abuse_respects_applicability_and_confidence_caps() -> None:
    source = identity("PRIV.1")
    privileged = resolution(
        context(
            "THRCTX-SYNTH-PRIVILEGE-ACTIVATION",
            confidence=Confidence.MEDIUM,
            attack_path_id="AP-016",
        )
    )
    result = overlay(
        (privileged,),
        (
            mapping(
                source,
                5,
                applicability=ApplicabilityMode.MANDATORY_WHEN_DEPLOYED,
                attack_path_id="AP-016",
                boundary_id="BND-IDENTITY-PRIVILEGED-ACTIVATION",
                technique_id="TEC-007",
                effect="independently approve privileged role activation",
            ),
        ),
        (assessment(source),),
    )[1][0]
    assert result.threat_relevance == ThreatRelevance.ELEVATED
    assert result.priority_confidence == Confidence.MEDIUM
    assert result.advisory_action == AdvisoryAction.REVIEW


@pytest.mark.parametrize(
    ("role", "strength"),
    [
        (BoundaryRole.BOUNDARY_SET_CORE_MEMBER, MitigationStrength.COMPLEMENTARY),
        (BoundaryRole.PREREQUISITE, MitigationStrength.PRIMARY),
    ],
)
def test_core_and_prerequisite_mitigations_can_reach_high(
    role: BoundaryRole, strength: MitigationStrength
) -> None:
    source = identity(f"A.{role.value}")
    result = overlay(
        (resolution(),),
        (mapping(source, 10, role=role, strength=strength),),
        (assessment(source),),
    )[1][0]
    assert result.threat_relevance == ThreatRelevance.HIGH


def test_primary_outranks_supporting_and_detection_is_capped() -> None:
    primary = identity("B.1")
    supporting = identity("B.2")
    detection = identity("D.1")
    results = overlay(
        (resolution(),),
        (
            mapping(primary, 20),
            mapping(
                supporting,
                21,
                role=BoundaryRole.SUPPORTING_HARDENING,
                strength=MitigationStrength.SUPPORTING,
            ),
            mapping(
                detection,
                22,
                role=BoundaryRole.DETECTION_ONLY,
                mitigation_role=MitigationRole.DETECT,
                strength=MitigationStrength.SUPPORTING,
            ),
        ),
        tuple(assessment(item) for item in (primary, supporting, detection)),
    )[1]
    by_id = {item.control_id: item for item in results}
    assert by_id["B.1"].threat_relevance == ThreatRelevance.HIGH
    assert by_id["B.2"].threat_relevance == ThreatRelevance.ELEVATED
    assert by_id["D.1"].threat_relevance == ThreatRelevance.ELEVATED


@pytest.mark.parametrize(
    "role",
    [
        BoundaryRole.FINE_TUNING,
        BoundaryRole.INFORMATION_HIDING,
        BoundaryRole.OPERATIONAL,
    ],
)
def test_tuning_and_operational_roles_remain_normal(role: BoundaryRole) -> None:
    source = identity(f"N.{role.value}")
    result = overlay(
        (resolution(),),
        (
            mapping(
                source,
                30,
                role=role,
                strength=MitigationStrength.SUPPORTING,
            ),
        ),
        (assessment(source),),
    )[1][0]
    assert result.threat_relevance == ThreatRelevance.NORMAL
    assert result.advisory_action == AdvisoryAction.NONE


def test_multiple_threats_preserve_drivers_and_highest_valid_relevance() -> None:
    source = identity("M.1")
    high = resolution(context("THRCTX-SYNTH-A"))
    medium = resolution(context("THRCTX-SYNTH-B", confidence=Confidence.MEDIUM))
    result = overlay((medium, high), (mapping(source, 40),), (assessment(source),))[1][
        0
    ]
    assert result.threat_relevance == ThreatRelevance.HIGH
    assert result.threat_context_ids == ("THRCTX-SYNTH-A", "THRCTX-SYNTH-B")
    assert len(result.drivers) == 2
    assert {item.relevance for item in result.drivers} == {
        ThreatRelevance.HIGH,
        ThreatRelevance.ELEVATED,
    }


def test_incomplete_driver_does_not_invalidate_complete_driver() -> None:
    source = identity("M.2")
    complete = resolution(context("THRCTX-SYNTH-COMPLETE"))
    incomplete = resolution(context("THRCTX-SYNTH-PARTIAL")).model_copy(
        update={"status": ResolutionStatus.PARTIALLY_RESOLVED}
    )
    result = overlay(
        (incomplete, complete), (mapping(source, 41),), (assessment(source),)
    )[1][0]
    assert result.threat_relevance == ThreatRelevance.HIGH


def test_broader_primary_outranks_narrower_supporting_equivalent() -> None:
    broad = identity("E.1")
    narrow = identity("E.2")
    weak_auth = resolution(
        context(
            "THRCTX-SYNTH-WEAK-AUTHENTICATION",
            attack_path_id="AP-022",
        )
    )
    results = overlay(
        (weak_auth,),
        (
            mapping(
                broad,
                50,
                attack_path_id="AP-022",
                boundary_id="BND-IDENTITY-WEAK-AUTHENTICATION",
                technique_id="TEC-011",
                effect="reject weak authentication across the benchmark scope",
            ),
            mapping(
                narrow,
                51,
                role=BoundaryRole.SUPPORTING_HARDENING,
                strength=MitigationStrength.SUPPORTING,
                attack_path_id="AP-022",
                boundary_id="BND-IDENTITY-WEAK-AUTHENTICATION",
                technique_id="TEC-011",
                effect="reject weak authentication for a narrower service",
            ),
        ),
        (
            assessment(broad),
            assessment(
                narrow,
                relationship="supporting hardening",
                overlap="alternative",
                related=("E.1",),
            ),
        ),
    )[1]
    by_id = {item.control_id: item for item in results}
    assert by_id["E.1"].threat_relevance == ThreatRelevance.HIGH
    assert by_id["E.2"].threat_relevance == ThreatRelevance.ELEVATED


def test_ambiguous_duplicate_primary_effects_require_review() -> None:
    first, second = identity("E.3"), identity("E.4")
    results = overlay(
        (resolution(),),
        (mapping(first, 52), mapping(second, 53)),
        (assessment(first), assessment(second)),
    )[1]
    assert all(item.threat_relevance == ThreatRelevance.ELEVATED for item in results)
    assert all(item.advisory_action == AdvisoryAction.REVIEW for item in results)
    assert all(
        "THREAT_PRIORITY_AMBIGUOUS_EQUIVALENCE"
        in {finding.code for finding in item.findings}
        for item in results
    )


@pytest.mark.parametrize(
    "proposal",
    ["Candidate Mandatory", "Review Required", "Regular Control"],
)
def test_every_base_proposal_remains_enum_identical(
    proposal: MandatoryProposal,
) -> None:
    source = identity(f"P.{proposal[0]}")
    base = assessment(source, proposal=proposal)
    result = overlay((resolution(),), (mapping(source, 60),), (base,))[1][0]
    assert result.base_proposal == Proposal(proposal)
    assert result.model_dump(mode="json")["base_proposal"] == proposal


def test_determinism_input_order_and_source_identity_isolation() -> None:
    first = identity("1.1", family="windows_server", version="2025", profile="L1")
    second = identity("1.1", family="microsoft_365", version="4", profile="E3 L1")
    mappings = (mapping(first, 70), mapping(second, 71))
    assessments = (assessment(first), assessment(second))
    a = overlay((resolution(),), mappings, assessments)[1]
    b = overlay(
        (resolution(),), tuple(reversed(mappings)), tuple(reversed(assessments))
    )[1]
    assert len(a) == 2
    assert a == b
    assert [item.to_deterministic_json() for item in a] == [
        item.to_deterministic_json() for item in b
    ]
    assert a[0].source_identity != a[1].source_identity


def test_confidence_propagation_and_summary() -> None:
    high, low = identity("S.1"), identity("S.2")
    results = overlay(
        (resolution(),),
        (
            mapping(high, 80),
            mapping(
                low,
                81,
                confidence=Confidence.MEDIUM,
                effect="enforce a separate synthetic session restriction",
            ),
        ),
        (assessment(high), assessment(low)),
    )[1]
    by_id = {item.control_id: item for item in results}
    assert by_id["S.1"].priority_confidence == Confidence.HIGH
    assert by_id["S.2"].priority_confidence == Confidence.MEDIUM
    summary = summarize_threat_priority(results)
    assert summary.total_projected_controls == 2
    assert summary.high == 1
    assert summary.elevated == 1
    assert summary.critical == 0
    assert summary.unique_threat_contexts == 1
    assert summary.controls_by_base_proposal == (("Regular Control", 2),)
    assert summary.to_deterministic_json() == summary.to_deterministic_json()


def test_catalog_is_unmodified_and_mandatory_does_not_import_phase3() -> None:
    before = SECURITY_KNOWLEDGE_CATALOG.to_deterministic_json()
    source = identity("Z.1")
    _ = overlay((resolution(),), (mapping(source, 90),), (assessment(source),))
    assert SECURITY_KNOWLEDGE_CATALOG.to_deterministic_json() == before
    mandatory_dir = Path(__file__).parents[1] / "src" / "cis_pdf2csv" / "mandatory"
    assert all(
        "threat_intelligence" not in path.read_text()
        and "prioritization" not in path.read_text()
        and "ThreatRelevance" not in path.read_text()
        for path in mandatory_dir.glob("*.py")
    )


def test_unresolved_boundary_supporting_mapping_starts_and_stays_normal() -> None:
    source = identity("PRECISION.1")
    explicit_technique = context().model_copy(
        update={"attack_path_ids": (), "technique_ids": ("TEC-003",)}
    )
    item = resolution(explicit_technique)
    projected, results = overlay(
        (item,),
        (
            mapping(
                source,
                100,
                role=BoundaryRole.SUPPORTING_HARDENING,
                strength=MitigationStrength.SUPPORTING,
                attack_path_id="AP-004",
                boundary_id="BND-REMOTE-MANAGEMENT",
                technique_id="TEC-002",
            ),
        ),
        (assessment(source),),
    )
    projection = projected.projections[0]
    assert projection.context_technique_ids == ("TEC-003",)
    assert projection.derived_technique_ids == ("TEC-002", "TEC-004")
    assert projection.causal_bases == ()
    assert results[0].threat_relevance == ThreatRelevance.NORMAL
    assert "THREAT_PROJECTION_BOUNDARY_NOT_RESOLVED" in {
        finding.code for finding in results[0].findings
    }
    assert "THREAT_PRIORITY_CAUSAL_BASIS_REQUIRED" in {
        finding.code for finding in results[0].findings
    }


def test_exact_explicit_technique_mapping_is_a_causal_basis_without_fabrication() -> (
    None
):
    source = identity("PRECISION.2")
    item = resolution(
        context().model_copy(
            update={"attack_path_ids": (), "technique_ids": ("TEC-003",)}
        )
    )
    projected, results = overlay(
        (item,),
        (
            mapping(
                source,
                101,
                role=BoundaryRole.SUPPORTING_HARDENING,
                strength=MitigationStrength.SUPPORTING,
                attack_path_id="AP-004",
                boundary_id="BND-REMOTE-MANAGEMENT",
                technique_id="TEC-003",
            ),
        ),
        (assessment(source),),
    )
    assert [basis.value for basis in projected.projections[0].causal_bases] == [
        "explicit_context_technique"
    ]
    assert results[0].threat_relevance == ThreatRelevance.ELEVATED
    assert results[0].context_technique_ids == ("TEC-003",)
    assert results[0].derived_technique_ids == ("TEC-002", "TEC-004")


def test_valid_and_weak_paths_are_independent_in_aggregate_rationale() -> None:
    source = identity("PRECISION.3")
    item = resolution(
        context().model_copy(
            update={"attack_path_ids": (), "technique_ids": ("TEC-003",)}
        )
    )
    _, results = overlay(
        (item,),
        (
            mapping(
                source,
                102,
                attack_path_id="AP-003",
                boundary_id="BND-NETWORK-SMB-SESSION",
                technique_id="TEC-003",
            ),
            mapping(
                source,
                103,
                role=BoundaryRole.SUPPORTING_HARDENING,
                strength=MitigationStrength.SUPPORTING,
                attack_path_id="AP-004",
                boundary_id="BND-REMOTE-MANAGEMENT",
                technique_id="TEC-002",
            ),
        ),
        (assessment(source),),
    )
    result = results[0]
    by_mapping = {driver.mapping_id: driver for driver in result.drivers}
    assert by_mapping["MAP-102"].relevance == ThreatRelevance.HIGH
    assert by_mapping["MAP-103"].relevance == ThreatRelevance.NORMAL
    assert result.threat_relevance == ThreatRelevance.HIGH
    assert result.rationale.startswith(
        f"Aggregate High relevance is determined by {item.threat_context_id}@1|MAP-102."
    )


def test_windows_remote_service_smoke_precision_regression() -> None:
    controls_path = Path(__file__).parents[1] / "controls-windows-server-2025-l1.jsonl"
    controls = [
        ControlRecord.model_validate_json(line)
        for line in controls_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assessments = assess_controls(controls)
    mappings = adapt_phase1_assessments_to_mappings(controls, assessments).mappings
    smoke_context = ThreatContext(
        threat_context_id="THRCTX-SYNTH-REMOTE-SERVICE-PRECISION",
        title="Synthetic remote-service activity",
        description="Invented remote-service targeting for deterministic testing.",
        source_type=ThreatSourceType.ANALYST,
        source_name="Synthetic test authority",
        source_reference="SYNTH-REMOTE-SERVICE-PRECISION",
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
        confidence=Confidence.LOW,
        severity=ThreatSeverity.MEDIUM,
        lifecycle_status=LifecycleStatus.ACTIVE,
        threat_scenario_ids=("TS-101",),
        technique_ids=("TEC-003",),
        affected_technology_families=("Windows",),
        applicability_scope=ThreatApplicabilityScope.TECHNOLOGY_FAMILY,
        provenance=ThreatContextProvenance(
            authority="Synthetic test authority",
            creation_method="invented approved fixture",
            model_version="1.0",
            object_version="1",
        ),
    )
    resolved = resolve_threat_context(
        smoke_context, SECURITY_KNOWLEDGE_CATALOG, at_time=NOW
    )
    projected = project_threat_resolutions(
        (resolved,), mappings, assessments, catalog=SECURITY_KNOWLEDGE_CATALOG
    )
    results = prioritize_threat_projections(projected.projections)
    by_id = {item.control_id: item for item in results}

    strong = {
        "18.10.57.3.9.4",
        "2.2.6",
        "18.10.89.1.1",
        "18.10.89.1.2",
        "2.3.8.1",
        "2.3.9.2",
        "9.2.1",
        "9.2.2",
    }
    weak = {
        "18.10.57.3.3.3",
        "18.7.7",
        "2.3.10.7",
        "2.3.10.8",
        "9.2.4",
        "9.2.5",
    }
    assert all(
        by_id[control_id].threat_relevance == ThreatRelevance.ELEVATED
        for control_id in strong
    )
    assert all(
        by_id[control_id].threat_relevance == ThreatRelevance.NORMAL
        for control_id in weak
    )
    assert by_id["18.10.57.3.9.4"].context_technique_ids == ("TEC-003",)
    assert by_id["18.10.57.3.9.4"].derived_technique_ids == (
        "TEC-002",
        "TEC-004",
    )
    assert by_id["9.2.4"].context_technique_ids == ()
    assert by_id["9.2.4"].derived_technique_ids == ("TEC-004",)
    firewall = by_id["9.2.1"]
    firewall_by_path = {
        driver.attack_path_ids[0]: driver for driver in firewall.drivers
    }
    assert firewall_by_path["AP-003"].relevance == ThreatRelevance.NORMAL
    assert firewall_by_path["AP-007"].relevance == ThreatRelevance.ELEVATED
    assert firewall_by_path["AP-007"].context_scenario_ids == ("TS-101",)
    assert firewall_by_path["AP-007"].derived_technique_ids == ("TEC-004",)
    assert firewall.rationale.startswith(
        "Aggregate Elevated relevance is determined by "
        f"{firewall_by_path['AP-007'].driver_id}."
    )
    summary = summarize_threat_priority(results)
    assert summary.total_projected_controls == 35
    assert (summary.normal, summary.elevated, summary.high, summary.critical) == (
        16,
        19,
        0,
        0,
    )
    assert summary.review_capped_controls == 19
