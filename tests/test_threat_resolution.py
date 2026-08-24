from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cis_pdf2csv.security_knowledge.catalog import SECURITY_KNOWLEDGE_CATALOG
from cis_pdf2csv.security_knowledge.catalog.registry import AttackTechnique
from cis_pdf2csv.security_knowledge.provenance import Confidence, LifecycleStatus
from cis_pdf2csv.security_knowledge.threat_intelligence import (
    ResolutionStatus,
    ThreatApplicabilityScope,
    ThreatContext,
    ThreatContextProvenance,
    ThreatSeverity,
    ThreatSourceType,
    build_resolution_coverage_report,
    resolve_threat_context,
)

NOW = datetime(2026, 8, 21, 12, tzinfo=timezone.utc)


def context(**updates: object) -> ThreatContext:
    values: dict[str, object] = {
        "threat_context_id": "THRCTX-SYNTH-RESOLUTION",
        "title": "Synthetic credential and session replay activity",
        "description": "Invented activity for deterministic resolver tests.",
        "source_type": ThreatSourceType.ANALYST,
        "source_name": "Synthetic test authority",
        "source_reference": "SYNTH-RESOLUTION-001",
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "confidence": Confidence.HIGH,
        "severity": ThreatSeverity.MEDIUM,
        "lifecycle_status": LifecycleStatus.ACTIVE,
        "threat_scenario_ids": (),
        "technique_ids": (),
        "attack_path_ids": (),
        "targeted_asset_classes": ("identity tokens",),
        "affected_technology_families": ("synthetic identity service",),
        "applicability_scope": ThreatApplicabilityScope.TECHNOLOGY_FAMILY,
        "provenance": ThreatContextProvenance(
            authority="Synthetic test authority",
            creation_method="invented fixture",
            model_version="1.0",
            object_version="7",
        ),
    }
    values.update(updates)
    return ThreatContext.model_validate(values)


def resolve(
    item: ThreatContext,
    *,
    catalog=SECURITY_KNOWLEDGE_CATALOG,
    historical_mode: bool = False,
):  # type: ignore[no-untyped-def]
    return resolve_threat_context(
        item, catalog, at_time=NOW, historical_mode=historical_mode
    )


def test_explicit_active_attack_path_has_full_resolution() -> None:
    result = resolve(context(attack_path_ids=("AP-019",)))
    assert result.status == ResolutionStatus.RESOLVED
    assert [item.object_id for item in result.attack_paths] == ["AP-019"]
    assert [item.object_id for item in result.threat_scenarios] == ["TS-126"]
    assert [item.object_id for item in result.techniques] == ["TEC-016"]
    assert [item.object_id for item in result.boundaries] == [
        "BND-IDENTITY-AUTHENTICATION-SESSION-BINDING"
    ]
    assert [item.object_id for item in result.outcomes] == [
        "OUT-002",
        "OUT-009",
        "OUT-012",
    ]
    assert result.threat_context_revision == "7"


def test_explicit_technique_preserves_multiple_matching_paths() -> None:
    result = resolve(context(technique_ids=("TEC-016",)))
    assert result.status == ResolutionStatus.RESOLVED
    assert [item.object_id for item in result.attack_paths] == [
        "AP-018",
        "AP-019",
        "AP-020",
    ]
    assert len(result.resolution_paths) == 3


def test_explicit_threat_scenario_resolves_path() -> None:
    result = resolve(context(threat_scenario_ids=("TS-122",)))
    assert result.status == ResolutionStatus.RESOLVED
    assert [item.object_id for item in result.attack_paths] == ["AP-016"]


def test_technique_only_without_path_is_partially_resolved() -> None:
    technique = AttackTechnique(
        technique_id="TEC-999",
        name="Synthetic unattached technique",
        description="An invented technique with no path.",
        attack_stage="authentication",
        affected_technologies=("synthetic service",),
        prerequisites=("synthetic precondition",),
        confidence="High",
        provenance=SECURITY_KNOWLEDGE_CATALOG.provenance,
    )
    catalog = replace(
        SECURITY_KNOWLEDGE_CATALOG,
        attack_techniques=SECURITY_KNOWLEDGE_CATALOG.attack_techniques + (technique,),
    )
    result = resolve(context(technique_ids=("TEC-999",)), catalog=catalog)
    assert result.status == ResolutionStatus.PARTIALLY_RESOLVED
    assert [item.object_id for item in result.techniques] == ["TEC-999"]
    assert result.attack_paths == ()


def test_context_without_explicit_knowledge_is_unresolved_without_text_inference() -> (
    None
):
    result = resolve(context())
    assert result.status == ResolutionStatus.UNRESOLVED
    assert result.attack_paths == ()
    assert {item.code for item in result.findings} == {
        "THREAT_RESOLUTION_NO_EXPLICIT_KNOWLEDGE_REFERENCE"
    }


def test_expired_and_future_contexts_are_inactive() -> None:
    expired = context(valid_until=NOW - timedelta(seconds=1))
    future = context(
        lifecycle_status=LifecycleStatus.DRAFT,
        valid_from=NOW + timedelta(seconds=1),
        valid_until=NOW + timedelta(days=1),
    )
    assert resolve(expired).status == ResolutionStatus.INACTIVE
    assert resolve(future).status == ResolutionStatus.INACTIVE


def test_valid_until_endpoint_is_exclusive() -> None:
    item = context(valid_until=NOW)
    assert not item.is_active(NOW)
    assert resolve(item).status == ResolutionStatus.INACTIVE


def test_unknown_technique_and_path_block_active_participation() -> None:
    technique = resolve(
        context(technique_ids=("TEC-999",), attack_path_ids=("AP-019",))
    )
    path = resolve(context(attack_path_ids=("AP-999",), technique_ids=("TEC-016",)))
    assert technique.status == ResolutionStatus.UNRESOLVED
    assert path.status == ResolutionStatus.UNRESOLVED
    assert technique.attack_paths == ()
    assert path.attack_paths == ()


def test_unresolved_applicability_blocks_participation() -> None:
    result = resolve(
        context(
            attack_path_ids=("AP-019",),
            applicability_scope=ThreatApplicabilityScope.UNRESOLVED,
        )
    )
    assert result.status == ResolutionStatus.UNRESOLVED
    assert result.attack_paths == ()
    assert result.findings[0].code == "THREAT_RESOLUTION_APPLICABILITY_BLOCKER"


def _inactive_path(lifecycle: str, successors: tuple[str, ...] = ()):  # type: ignore[no-untyped-def]
    path = SECURITY_KNOWLEDGE_CATALOG.get_attack_path("AP-019").model_copy(
        update={"lifecycle_status": lifecycle, "successor_ids": successors}
    )
    paths = tuple(
        path if item.attack_path_id == "AP-019" else item
        for item in SECURITY_KNOWLEDGE_CATALOG.attack_paths
    )
    return replace(SECURITY_KNOWLEDGE_CATALOG, attack_paths=paths)


def test_deprecated_reference_normal_and_historical_modes() -> None:
    catalog = _inactive_path("deprecated")
    normal = resolve(context(attack_path_ids=("AP-019",)), catalog=catalog)
    historical = resolve(
        context(attack_path_ids=("AP-019",)), catalog=catalog, historical_mode=True
    )
    assert normal.status == ResolutionStatus.REVIEW_REQUIRED
    assert normal.attack_paths == ()
    assert historical.status == ResolutionStatus.RESOLVED
    assert historical.historical_mode
    assert any(
        item.code == "THREAT_RESOLUTION_HISTORICAL_REFERENCE"
        for item in historical.findings
    )


def test_superseded_reference_has_one_successor_suggestion_without_remapping() -> None:
    result = resolve(
        context(attack_path_ids=("AP-019",)),
        catalog=_inactive_path("superseded", ("AP-020",)),
    )
    assert result.status == ResolutionStatus.REVIEW_REQUIRED
    assert result.attack_paths == ()
    assert result.findings[0].code == "THREAT_RESOLUTION_SUCCESSOR_REVIEW_REQUIRED"
    assert result.findings[0].successor_candidate_ids == ("AP-020",)


def test_superseded_reference_preserves_multiple_successor_candidates() -> None:
    result = resolve(
        context(attack_path_ids=("AP-019",)),
        catalog=_inactive_path("superseded", ("AP-018", "AP-020")),
    )
    assert result.status == ResolutionStatus.REVIEW_REQUIRED
    assert (
        result.findings[0].code
        == "THREAT_RESOLUTION_MULTIPLE_SUCCESSORS_REVIEW_REQUIRED"
    )
    assert result.findings[0].successor_candidate_ids == ("AP-018", "AP-020")


def test_superseded_reference_without_successor_is_explicit() -> None:
    result = resolve(
        context(attack_path_ids=("AP-019",)),
        catalog=_inactive_path("superseded"),
    )
    assert result.status == ResolutionStatus.REVIEW_REQUIRED
    assert result.findings[0].code == "THREAT_RESOLUTION_NO_SUCCESSOR_REVIEW_REQUIRED"
    assert result.findings[0].successor_candidate_ids == ()


def test_path_without_boundary_or_outcome_is_partial() -> None:
    original = SECURITY_KNOWLEDGE_CATALOG.get_attack_path("AP-019")
    for field, code in (
        ("boundary_ids", "THREAT_RESOLUTION_PATH_WITHOUT_BOUNDARY"),
        ("security_outcome_ids", "THREAT_RESOLUTION_PATH_WITHOUT_OUTCOME"),
    ):
        changed = original.model_copy(update={field: ()})
        paths = tuple(
            changed if item.attack_path_id == changed.attack_path_id else item
            for item in SECURITY_KNOWLEDGE_CATALOG.attack_paths
        )
        result = resolve(
            context(attack_path_ids=("AP-019",)),
            catalog=replace(SECURITY_KNOWLEDGE_CATALOG, attack_paths=paths),
        )
        assert result.status == ResolutionStatus.PARTIALLY_RESOLVED
        assert code in {item.code for item in result.findings}


def test_resolution_confidence_is_conservative() -> None:
    result = resolve(context(attack_path_ids=("AP-019",), confidence=Confidence.LOW))
    assert result.confidence == Confidence.LOW
    assert all(item.confidence == Confidence.LOW for item in result.attack_paths)


def test_serialization_is_deterministic_and_input_order_independent() -> None:
    first = resolve(
        context(
            technique_ids=("TEC-016", "TEC-007"),
            attack_path_ids=("AP-019", "AP-016"),
        )
    )
    second = resolve(
        context(
            technique_ids=("TEC-007", "TEC-016"),
            attack_path_ids=("AP-016", "AP-019"),
        )
    )
    assert first.to_deterministic_json() == first.to_deterministic_json()
    assert first.to_deterministic_json() == second.to_deterministic_json()


def test_coverage_report_counts_threat_knowledge_only() -> None:
    results = (
        resolve(context(attack_path_ids=("AP-019",))),
        resolve(context(technique_ids=("TEC-999",))),
        resolve(context()),
        resolve(context(valid_until=NOW)),
        resolve(
            context(attack_path_ids=("AP-019",)), catalog=_inactive_path("deprecated")
        ),
    )
    report = build_resolution_coverage_report(results)
    assert report.model_dump() == {
        "resolved": 1,
        "partially_resolved": 0,
        "review_required": 1,
        "unresolved": 2,
        "inactive": 1,
        "referenced_techniques": 1,
        "resolved_attack_paths": 1,
        "resolved_boundaries": 1,
        "resolved_outcomes": 3,
        "unresolved_external_catalog_references": 1,
    }
    assert "control" not in report.to_deterministic_json()


def test_catalog_is_not_mutated_and_mandatory_does_not_reference_resolver() -> None:
    before = SECURITY_KNOWLEDGE_CATALOG.to_deterministic_json()
    _ = resolve(context(technique_ids=("TEC-016",)))
    assert SECURITY_KNOWLEDGE_CATALOG.to_deterministic_json() == before
    mandatory_dir = Path(__file__).parents[1] / "src" / "cis_pdf2csv" / "mandatory"
    assert all(
        "threat_intelligence" not in path.read_text()
        and "threat_resolution" not in path.read_text()
        for path in mandatory_dir.glob("*.py")
    )
