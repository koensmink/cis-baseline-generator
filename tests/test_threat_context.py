from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cis_pdf2csv.security_knowledge.catalog import SECURITY_KNOWLEDGE_CATALOG
from cis_pdf2csv.security_knowledge.identifiers import build_threat_context_id
from cis_pdf2csv.security_knowledge.provenance import Confidence, LifecycleStatus
from cis_pdf2csv.security_knowledge.threat_intelligence import (
    FindingLevel,
    ThreatApplicabilityScope,
    ThreatContext,
    ThreatContextProvenance,
    ThreatContextValidationFinding,
    ThreatEvidence,
    ThreatEvidenceProvenance,
    ThreatEvidenceType,
    ThreatSeverity,
    ThreatSourceType,
    validate_catalog_references,
    validate_threat_context,
)

NOW = datetime(2026, 8, 21, 12, tzinfo=timezone.utc)


def evidence(reference: str = "SYNTH-ADV-001") -> ThreatEvidence:
    return ThreatEvidence(
        evidence_type=ThreatEvidenceType.ANALYST_ASSERTION,
        source="Invented security research group",
        external_reference=reference,
        assertion="Synthetic observations indicate the described technique is feasible.",
        confidence=Confidence.HIGH,
        published_at=NOW - timedelta(days=2),
        retrieved_at=NOW - timedelta(days=1),
        provenance=ThreatEvidenceProvenance(
            collection_method="synthetic test fixture",
            source_revision="1",
            retrieved_at=NOW - timedelta(days=1),
        ),
    )


def context(**updates: object) -> ThreatContext:
    values: dict[str, object] = {
        "threat_context_id": "THRCTX-SYNTH-001",
        "title": "Synthetic credential and session replay activity",
        "description": "Invented activity may replay authenticated state against cloud authentication.",
        "source_type": ThreatSourceType.THREAT_RESEARCH,
        "source_name": "Invented security research group",
        "source_reference": "SYNTH-ADV-001",
        "observed_at": NOW - timedelta(days=3),
        "published_at": NOW - timedelta(days=2),
        "valid_from": NOW - timedelta(days=3),
        "valid_until": NOW + timedelta(days=7),
        "confidence": Confidence.HIGH,
        "severity": ThreatSeverity.MEDIUM,
        "lifecycle_status": LifecycleStatus.ACTIVE,
        "threat_scenario_ids": ("TS-126",),
        "technique_ids": ("TEC-016",),
        "attack_path_ids": ("AP-019",),
        "targeted_asset_classes": ("cloud sessions", "identity tokens"),
        "affected_technology_families": ("Microsoft 365 cloud authentication",),
        "applicability_scope": ThreatApplicabilityScope.TECHNOLOGY_FAMILY,
        "evidence": (evidence(),),
        "provenance": ThreatContextProvenance(
            authority="Invented test authority",
            creation_method="synthetic deterministic fixture",
            model_version="1.0",
            object_version="1.0",
        ),
    }
    values.update(updates)
    return ThreatContext.model_validate(values)


def codes(findings: tuple[ThreatContextValidationFinding, ...]) -> set[str]:
    return {item.code for item in findings}


def test_valid_active_credential_session_replay_context() -> None:
    item = context()
    assert item.is_active(NOW)
    assert validate_threat_context(item, at_time=NOW) == ()
    assert validate_catalog_references(item, SECURITY_KNOWLEDGE_CATALOG) == ()


def test_internal_identifier_generation_is_stable_and_not_an_external_id() -> None:
    first = build_threat_context_id("Invented Authority", "internal assertion 17")
    assert first == build_threat_context_id("Invented Authority", "internal assertion 17")
    assert first.startswith("THRCTX-INVENTED-AUTHORITY-")
    assert "SYNTH-ADV" not in first


def test_valid_expired_context_remains_readable_but_inactive() -> None:
    item = context(
        lifecycle_status=LifecycleStatus.DEPRECATED,
        valid_from=NOW - timedelta(days=20),
        valid_until=NOW - timedelta(days=1),
    )
    findings = validate_threat_context(item, at_time=NOW)
    assert not item.is_active(NOW)
    assert codes(findings) == {"THREAT_CONTEXT_EXPIRED"}
    assert findings[0].severity == FindingLevel.INFO


def test_future_context_does_not_silently_become_active() -> None:
    item = context(
        lifecycle_status=LifecycleStatus.DRAFT,
        valid_from=NOW + timedelta(days=1),
        valid_until=NOW + timedelta(days=8),
    )
    assert not item.is_active(NOW)
    assert codes(validate_threat_context(item, at_time=NOW)) == {"THREAT_CONTEXT_FUTURE"}


def test_invalid_validity_range_is_blocking() -> None:
    item = context(valid_from=NOW + timedelta(days=2), valid_until=NOW + timedelta(days=1))
    findings = validate_threat_context(item, at_time=NOW)
    assert "THREAT_CONTEXT_INVALID_TIME_RANGE" in codes(findings)
    assert any(finding.blocking for finding in findings)


def test_technique_only_weak_authentication_context_is_valid() -> None:
    item = context(
        threat_context_id="THRCTX-SYNTH-WEAK-AUTH",
        title="Synthetic weak authentication advisory",
        threat_scenario_ids=(),
        technique_ids=("TEC-011",),
        attack_path_ids=(),
    )
    assert validate_catalog_references(item, SECURITY_KNOWLEDGE_CATALOG) == ()


def test_attack_path_privilege_activation_context_with_scenarios() -> None:
    item = context(
        threat_context_id="THRCTX-SYNTH-PRIV-ACTIVATION",
        title="Synthetic privilege activation activity",
        threat_scenario_ids=("TS-122",),
        technique_ids=("TEC-007",),
        attack_path_ids=("AP-016",),
    )
    assert validate_catalog_references(item, SECURITY_KNOWLEDGE_CATALOG) == ()


def test_unresolved_advisory_is_reviewable_not_invalid() -> None:
    item = context(
        lifecycle_status=LifecycleStatus.DRAFT,
        applicability_scope=ThreatApplicabilityScope.UNRESOLVED,
        threat_scenario_ids=(),
        technique_ids=(),
        attack_path_ids=(),
        evidence=(),
    )
    findings = validate_threat_context(item, at_time=NOW)
    assert codes(findings) == {
        "THREAT_CONTEXT_APPLICABILITY_UNRESOLVED",
        "THREAT_CONTEXT_NO_EVIDENCE",
    }
    assert not any(finding.blocking for finding in findings)


@pytest.mark.parametrize(
    ("update", "expected"),
    [
        ({"technique_ids": ("TEC-999",)}, "THREAT_CONTEXT_UNKNOWN_TECHNIQUE"),
        ({"attack_path_ids": ("AP-999",)}, "THREAT_CONTEXT_UNKNOWN_ATTACK_PATH"),
    ],
)
def test_unknown_catalog_reference_is_explicit_review_warning(
    update: dict[str, object], expected: str
) -> None:
    findings = validate_catalog_references(context(**update), SECURITY_KNOWLEDGE_CATALOG)
    assert codes(findings) == {expected}
    assert findings[0].severity == FindingLevel.WARNING


def test_deprecated_and_superseded_references_require_historical_mode() -> None:
    technique = SECURITY_KNOWLEDGE_CATALOG.attack_techniques[15].model_copy(
        update={"lifecycle_status": "deprecated"}
    )
    path = SECURITY_KNOWLEDGE_CATALOG.attack_paths[18].model_copy(
        update={"lifecycle_status": "superseded"}
    )
    catalog = replace(
        SECURITY_KNOWLEDGE_CATALOG,
        attack_techniques=SECURITY_KNOWLEDGE_CATALOG.attack_techniques[:15]
        + (technique,)
        + SECURITY_KNOWLEDGE_CATALOG.attack_techniques[16:],
        attack_paths=SECURITY_KNOWLEDGE_CATALOG.attack_paths[:18]
        + (path,)
        + SECURITY_KNOWLEDGE_CATALOG.attack_paths[19:],
    )
    normal = validate_catalog_references(context(), catalog)
    historical = validate_catalog_references(context(), catalog, historical_mode=True)
    assert all(finding.blocking for finding in normal)
    assert all(finding.severity == FindingLevel.INFO for finding in historical)


def test_deterministic_serialization_and_input_order_independence() -> None:
    first = context(
        technique_ids=("TEC-016", "TEC-014"),
        targeted_asset_classes=("identity tokens", "cloud sessions"),
        evidence=(evidence("SYNTH-2"), evidence("SYNTH-1")),
    )
    second = context(
        technique_ids=("TEC-014", "TEC-016"),
        targeted_asset_classes=("cloud sessions", "identity tokens"),
        evidence=(evidence("SYNTH-1"), evidence("SYNTH-2")),
    )
    assert first.to_deterministic_json() == first.to_deterministic_json()
    assert first.to_deterministic_json() == second.to_deterministic_json()


def test_source_confidence_and_severity_are_independent() -> None:
    assert context(confidence=Confidence.HIGH, severity=ThreatSeverity.MEDIUM).severity == ThreatSeverity.MEDIUM
    assert context(confidence=Confidence.MEDIUM, severity=ThreatSeverity.CRITICAL).confidence == Confidence.MEDIUM


def test_no_reverse_catalog_mutation_or_production_import() -> None:
    before = SECURITY_KNOWLEDGE_CATALOG.to_deterministic_json()
    _ = context()
    after = SECURITY_KNOWLEDGE_CATALOG.to_deterministic_json()
    assert before == after
    assert all("threat_context" not in field for item in SECURITY_KNOWLEDGE_CATALOG.attack_paths for field in item.model_fields)

    mandatory_dir = Path(__file__).parents[1] / "src" / "cis_pdf2csv" / "mandatory"
    assert all("threat_intelligence" not in path.read_text() for path in mandatory_dir.glob("*.py"))
    assert "cis_pdf2csv.security_knowledge.threat_intelligence" in sys.modules
