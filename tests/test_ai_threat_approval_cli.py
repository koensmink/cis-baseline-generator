from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cis_pdf2csv.mandatory.pipeline import assess_controls
from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.catalog import SECURITY_KNOWLEDGE_CATALOG
from cis_pdf2csv.security_knowledge.provenance import Confidence
from cis_pdf2csv.security_knowledge.threat_intelligence.ai.approval import (
    InterpretationApprovalError,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.ai.approval_cli import main
from cis_pdf2csv.security_knowledge.threat_intelligence.ai.approval_workflow import (
    ApprovalBlockedError,
    ProposedInterpretationArtifact,
    material_decisions,
    review_proposed_interpretation,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.ai.contract import (
    DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT,
    build_document_id,
    build_interpretation_id,
    content_hash,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.ai.provenance import (
    AdvisoryDocumentProvenance,
    AIInterpretationProvenance,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.ai.schema import (
    AdvisoryContentFormat,
    AIContractFinding,
    AIContractFindingSeverity,
    ApprovalModification,
    ApprovalStatus,
    EvidenceSupportType,
    InterpretationEvidenceAssertion,
    ProposedThreatInterpretation,
    ThreatActivityState,
    ThreatAdvisoryDocument,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.ai.validation import (
    validate_interpretation,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.cli import main as analyze_main
from cis_pdf2csv.security_knowledge.threat_intelligence.resolution import (
    ResolutionStatus,
    resolve_threat_context,
)
from cis_pdf2csv.security_knowledge.threat_intelligence.schema import (
    ThreatApplicabilityScope,
    ThreatSeverity,
    ThreatSourceType,
)

NOW = datetime(2026, 8, 24, 12, tzinfo=UTC)
CONTRACT = DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT


def evidence(assertion_id: str, kind: str, value: str) -> InterpretationEvidenceAssertion:
    return InterpretationEvidenceAssertion(
        assertion_id=assertion_id,
        assertion_type=kind,
        value=value,
        source_locator=f"paragraph:{assertion_id}",
        support_type=EvidenceSupportType.EXPLICITLY_STATED,
        confidence=Confidence.HIGH,
        explicitly_stated=True,
        inference_required=False,
    )


def source_document() -> ThreatAdvisoryDocument:
    content = "An invented advisory describes a theoretical authentication path."
    return ThreatAdvisoryDocument(
        document_id=build_document_id("approval-tests", "document-1"),
        source_type=ThreatSourceType.ANALYST,
        source_name="Synthetic Lab",
        source_reference="SYNTH-APPROVAL-1",
        published_at=NOW,
        retrieved_at=NOW,
        content_hash=content_hash(content),
        title="Synthetic approval advisory",
        content=content,
        content_format=AdvisoryContentFormat.PLAIN_TEXT,
        provenance=AdvisoryDocumentProvenance(
            supplied_by="test", collection_method="caller_supplied"
        ),
    )


def proposal(doc: ThreatAdvisoryDocument | None = None, **updates: object) -> ProposedThreatInterpretation:
    doc = doc or source_document()
    assertions = (
        evidence("A-SOURCE", "source_reference", doc.source_reference),
        evidence("A-PUBLISHED", "published_at", NOW.isoformat()),
        evidence("A-ACTIVITY", "activity_state", "theoretical"),
        evidence("A-CONFIDENCE", "confidence", "High"),
        evidence("A-SEVERITY", "severity", "High"),
        evidence("A-TECH", "technique_id", "TEC-001"),
        evidence("A-PATH", "attack_path_id", "AP-001"),
        evidence("A-FAMILY", "affected_technology_family", "generic"),
        evidence("A-ASSET", "targeted_asset_class", "synthetic-session"),
    )
    values: dict[str, object] = {
        "interpretation_id": build_interpretation_id(
            doc.document_id, "openai", "synthetic-model", CONTRACT.contract_id, "run-1"
        ),
        "interpretation_revision": "revision-1",
        "schema_version": CONTRACT.schema_version,
        "model_provider": "openai",
        "model_name": "synthetic-model",
        "model_version": "synthetic-model-version",
        "prompt_id": CONTRACT.prompt_id,
        "prompt_version": CONTRACT.prompt_version,
        "generated_at": NOW,
        "input_document_id": doc.document_id,
        "input_hash": doc.content_hash,
        "title": "Synthetic proposal",
        "summary": "A candidate authentication relationship for human review.",
        "source_type": doc.source_type,
        "source_name": doc.source_name,
        "source_reference": doc.source_reference,
        "published_at": NOW,
        "proposed_confidence": Confidence.HIGH,
        "proposed_severity": ThreatSeverity.HIGH,
        "proposed_activity_state": ThreatActivityState.THEORETICAL,
        "proposed_technique_ids": ("TEC-001",),
        "proposed_attack_path_ids": ("AP-001",),
        "proposed_affected_technology_families": ("generic",),
        "proposed_targeted_asset_classes": ("synthetic-session",),
        "proposed_applicability_scope": ThreatApplicabilityScope.GLOBAL,
        "evidence_assertions": assertions,
        "provenance": AIInterpretationProvenance(
            contract_id=CONTRACT.contract_id,
            contract_version=CONTRACT.contract_version,
            authority_policy_version="1.0",
            generation_parameters_id="GEN-SYNTHETIC",
            input_document_hash=doc.content_hash,
        ),
    }
    values.update(updates)
    return ProposedThreatInterpretation.model_validate(values)


def artifact(item: ProposedThreatInterpretation | None = None) -> ProposedInterpretationArtifact:
    doc = source_document()
    item = item or proposal(doc)
    validation = validate_interpretation(item, doc, SECURITY_KNOWLEDGE_CATALOG)
    return ProposedInterpretationArtifact(
        provider="openai",
        model="synthetic-model",
        model_version="synthetic-model-version",
        request_id="resp_synthetic",
        contract_id=CONTRACT.contract_id,
        contract_version=CONTRACT.contract_version,
        prompt_id=CONTRACT.prompt_id,
        prompt_version=CONTRACT.prompt_version,
        document_id=doc.document_id,
        document_hash=doc.content_hash,
        catalog_version=SECURITY_KNOWLEDGE_CATALOG.catalog_version,
        catalog_vocabulary_hash="1" * 64,
        generation_parameter_identity="GEN-SYNTHETIC",
        raw_response_hash="2" * 64,
        interpretation=item,
        validation=validation,
    )


def decisions(item: ProposedInterpretationArtifact) -> tuple[str, ...]:
    return material_decisions(item)


def review(
    item: ProposedInterpretationArtifact | None = None,
    *,
    status: ApprovalStatus = ApprovalStatus.APPROVED,
    accepted: tuple[str, ...] | None = None,
    rejected: tuple[str, ...] = (),
    modifications: tuple[ApprovalModification, ...] = (),
    catalog=SECURITY_KNOWLEDGE_CATALOG,
):
    item = item or artifact()
    return review_proposed_interpretation(
        item,
        reviewer="security-engineer",
        reviewed_at=NOW,
        status=status,
        accepted_assertion_ids=decisions(item) if accepted is None else accepted,
        rejected_assertion_ids=rejected,
        modifications=modifications,
        rationale="Reviewed against the invented source.",
        catalog=catalog,
    )


def write_artifact(tmp_path: Path, item: ProposedInterpretationArtifact | None = None) -> Path:
    path = tmp_path / "proposed-threat.json"
    path.write_text((item or artifact()).to_deterministic_json())
    return path


def cli_args(input_path: Path, output: Path, decision: str = "approved") -> list[str]:
    item = ProposedInterpretationArtifact.model_validate_json(input_path.read_text())
    args = [
        str(input_path), "--reviewer", "security-engineer", "--approval", decision,
        "--reviewed-at", NOW.isoformat(), "--rationale", "Reviewed synthetic evidence",
        "-o", str(output),
    ]
    for assertion_id in decisions(item):
        args.extend(("--accept", assertion_id))
    return args


def test_help_works() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0


def test_list_assertions_requires_no_approval(tmp_path: Path) -> None:
    assert main([str(write_artifact(tmp_path)), "--list-assertions"]) == 0
    assert list(tmp_path.glob("*-approval.json")) == []


def test_approved_explicit_decisions_create_threat_context(tmp_path: Path) -> None:
    input_path = write_artifact(tmp_path)
    output = tmp_path / "threat-context.json"
    assert main(cli_args(input_path, output)) == 0
    assert output.is_file()
    assert (tmp_path / "threat-context-approval.json").is_file()
    assert (tmp_path / "threat-context-approval-summary.json").is_file()


def test_undecided_material_assertion_fails_closed() -> None:
    item = artifact()
    with pytest.raises(ApprovalBlockedError, match="undecided"):
        review(item, accepted=decisions(item)[:-1])


@pytest.mark.parametrize("status", [ApprovalStatus.REJECTED, ApprovalStatus.NEEDS_REVISION])
def test_nonapproved_decision_creates_no_context(status: ApprovalStatus) -> None:
    result = review(status=status, accepted=())
    assert result.threat_context is None
    assert result.approval.status == status


def test_rejected_cli_writes_approval_only(tmp_path: Path) -> None:
    input_path = write_artifact(tmp_path)
    output = tmp_path / "threat-context.json"
    args = cli_args(input_path, output, "rejected")
    assert main(args) == 0
    assert not output.exists()
    assert (tmp_path / "threat-context-approval.json").is_file()


def test_needs_revision_cli_writes_approval_only(tmp_path: Path) -> None:
    input_path = write_artifact(tmp_path)
    output = tmp_path / "threat-context.json"
    assert main(cli_args(input_path, output, "needs_revision")) == 0
    assert not output.exists()


def test_blocking_phase4a_finding_prevents_approval() -> None:
    item = artifact()
    blocked = item.validation.model_copy(
        update={
            "findings": (
                AIContractFinding(
                    code="AI_INTERPRETATION_MISSING_EVIDENCE",
                    severity=AIContractFindingSeverity.ERROR,
                    object_id=item.interpretation.interpretation_id,
                    message="Synthetic blocker.",
                ),
            )
        }
    )
    with pytest.raises(ApprovalBlockedError):
        review(item.model_copy(update={"validation": blocked}))


def test_missing_reviewer_prevents_approval() -> None:
    item = artifact()
    with pytest.raises(ValueError, match="reviewer"):
        review_proposed_interpretation(
            item, reviewer="", reviewed_at=NOW, status=ApprovalStatus.APPROVED,
            accepted_assertion_ids=decisions(item), rejected_assertion_ids=(),
            modifications=(), rationale="review", catalog=SECURITY_KNOWLEDGE_CATALOG,
        )


def test_timezone_naive_review_time_is_rejected() -> None:
    item = artifact()
    with pytest.raises(ValueError, match="timezone-aware"):
        review_proposed_interpretation(
            item, reviewer="reviewer", reviewed_at=NOW.replace(tzinfo=None),
            status=ApprovalStatus.REJECTED, accepted_assertion_ids=(),
            rejected_assertion_ids=(), modifications=(), rationale="review",
            catalog=SECURITY_KNOWLEDGE_CATALOG,
        )


def test_explicit_time_is_deterministic() -> None:
    assert review().to_deterministic_json() == review().to_deterministic_json()


def test_rejected_assertion_is_excluded_and_accepted_assertion_included() -> None:
    item = artifact()
    accepted = tuple(value for value in decisions(item) if value != "A-TECH")
    result = review(item, accepted=accepted, rejected=("A-TECH",))
    assert result.threat_context is not None
    assert result.threat_context.technique_ids == ()
    assert result.threat_context.attack_path_ids == ("AP-001",)


@pytest.mark.parametrize(
    ("accepted", "rejected", "message"),
    [(('A-UNKNOWN',), (), "unknown"), (("A-SOURCE",), ("A-SOURCE",), "same assertion")],
)
def test_invalid_assertion_decisions_are_rejected(
    accepted: tuple[str, ...], rejected: tuple[str, ...], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        review(status=ApprovalStatus.REJECTED, accepted=accepted, rejected=rejected)


@pytest.mark.parametrize("identifier", ["TEC-BAD", "TEC-999"])
def test_invalid_catalog_id_cannot_be_human_overridden(identifier: str) -> None:
    item = proposal(proposed_technique_ids=(identifier,))
    proposal_artifact = artifact(item)
    with pytest.raises(ApprovalBlockedError):
        review(proposal_artifact)


def test_deprecated_catalog_reference_retains_review_finding() -> None:
    deprecated = SECURITY_KNOWLEDGE_CATALOG.attack_techniques[0].model_copy(
        update={"lifecycle_status": "deprecated"}
    )
    catalog = replace(
        SECURITY_KNOWLEDGE_CATALOG,
        attack_techniques=(deprecated, *SECURITY_KNOWLEDGE_CATALOG.attack_techniques[1:]),
    )
    result = review(catalog=catalog)
    assert "AI_INTERPRETATION_INACTIVE_CATALOG_ID" in {
        finding.code for finding in result.validation.findings
    }


@pytest.mark.parametrize(
    ("field", "value", "attribute", "expected"),
    [
        ("proposed_confidence", "Medium", "confidence", Confidence.MEDIUM),
        ("proposed_severity", "Critical", "severity", ThreatSeverity.CRITICAL),
        ("valid_from", "2026-08-24T10:00:00+00:00", "valid_from", datetime(2026, 8, 24, 10, tzinfo=UTC)),
    ],
)
def test_allowed_modification_is_recorded_and_applied(
    field: str, value: str, attribute: str, expected: object
) -> None:
    modification = ApprovalModification(field_name=field, value=value, rationale="Human correction")
    result = review(modifications=(modification,))
    assert result.threat_context is not None
    assert getattr(result.threat_context, attribute) == expected
    assert result.approval.modifications == (modification,)


def test_forbidden_modification_is_rejected() -> None:
    modification = ApprovalModification(
        field_name="mandatory_status", value="Candidate Mandatory", rationale="Forbidden"
    )
    with pytest.raises(InterpretationApprovalError, match="forbidden"):
        review(modifications=(modification,))


def test_confidence_cannot_exceed_validated_cap() -> None:
    item = artifact()
    capped = item.validation.model_copy(update={"capped_confidence": Confidence.MEDIUM})
    result = review(
        item.model_copy(update={"validation": capped}),
        modifications=(ApprovalModification(field_name="proposed_confidence", value="High", rationale="Requested"),),
    )
    assert result.threat_context is not None
    assert result.threat_context.confidence == Confidence.MEDIUM


def test_severity_modification_does_not_imply_activity() -> None:
    result = review(
        modifications=(ApprovalModification(field_name="proposed_severity", value="Critical", rationale="Reviewed"),)
    )
    assert result.threat_context is not None
    assert result.threat_context.severity == ThreatSeverity.CRITICAL
    assert not hasattr(result.threat_context, "activity_state")


def test_activity_modification_is_forbidden() -> None:
    with pytest.raises(InterpretationApprovalError, match="forbidden"):
        review(
            modifications=(ApprovalModification(field_name="proposed_activity_state", value="observed", rationale="Unsupported"),)
        )


def test_context_has_no_control_decision_fields() -> None:
    result = review()
    assert result.threat_context is not None
    serialized = result.threat_context.to_deterministic_json()
    for forbidden in ("control_id", "mandatory_status", "threat_relevance", "advisory_action"):
        assert forbidden not in serialized


def test_approval_cli_has_no_provider_network_mandatory_or_phase3_imports() -> None:
    contents = "\n".join(
        Path(path).read_text()
        for path in (
            "src/cis_pdf2csv/security_knowledge/threat_intelligence/ai/approval_cli.py",
            "src/cis_pdf2csv/security_knowledge/threat_intelligence/ai/approval_workflow.py",
        )
    )
    for forbidden in (
        "openai", "requests", "httpx", "socket", ".providers", "cis_pdf2csv.mandatory",
        "prioritize_threat_projections", "project_threat_resolutions",
    ):
        assert forbidden not in contents


def test_input_order_independence() -> None:
    item = artifact()
    reversed_item = item.model_copy(
        update={
            "interpretation": item.interpretation.model_copy(
                update={"evidence_assertions": tuple(reversed(item.interpretation.evidence_assertions))}
            )
        }
    )
    assert review(item).to_deterministic_json() == review(reversed_item).to_deterministic_json()


def test_provenance_chain_and_sensitive_provider_data_are_absent() -> None:
    result = review()
    assert result.threat_context is not None
    method = result.threat_context.provenance.creation_method
    assert result.approval.approval_id in method
    assert result.approval.interpretation_id in method
    serialized = result.to_deterministic_json()
    assert "sk-" not in serialized
    assert "raw_response" not in serialized


def test_cli_exit_2_for_malformed_input(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not-json")
    with pytest.raises(SystemExit) as caught:
        main([str(path), "--list-assertions"])
    assert caught.value.code == 2


def test_cli_exit_4_for_blocked_approval(tmp_path: Path) -> None:
    item = artifact()
    input_path = write_artifact(tmp_path, item)
    output = tmp_path / "context.json"
    args = cli_args(input_path, output)
    rejected_id = args[-1]
    assert rejected_id.startswith("A-")
    del args[-2:]
    assert main(args) == 4


def test_generated_context_is_accepted_by_phase2() -> None:
    result = review()
    assert result.threat_context is not None
    resolution = resolve_threat_context(
        result.threat_context, SECURITY_KNOWLEDGE_CATALOG, at_time=NOW
    )
    assert resolution.status == ResolutionStatus.RESOLVED


def test_catalog_is_not_mutated() -> None:
    before = repr(SECURITY_KNOWLEDGE_CATALOG)
    review()
    assert repr(SECURITY_KNOWLEDGE_CATALOG) == before


def test_no_implicit_approval(tmp_path: Path) -> None:
    input_path = write_artifact(tmp_path)
    with pytest.raises(SystemExit) as caught:
        main([str(input_path), "--reviewer", "reviewer"])
    assert caught.value.code == 2
    assert not (tmp_path / "threat-context.json").exists()


def test_approval_identity_distinguishes_review_timestamp() -> None:
    first = review()
    item = artifact()
    second = review_proposed_interpretation(
        item,
        reviewer="security-engineer",
        reviewed_at=datetime(2026, 8, 24, 12, 1, tzinfo=UTC),
        status=ApprovalStatus.APPROVED,
        accepted_assertion_ids=decisions(item),
        rejected_assertion_ids=(),
        modifications=(),
        rationale="Reviewed against the invented source.",
        catalog=SECURITY_KNOWLEDGE_CATALOG,
    )
    assert first.approval.approval_id != second.approval.approval_id


def test_modification_order_is_deterministic() -> None:
    modifications = (
        ApprovalModification(field_name="proposed_severity", value="Critical", rationale="Review"),
        ApprovalModification(field_name="proposed_confidence", value="Medium", rationale="Review"),
    )
    assert review(modifications=modifications).to_deterministic_json() == review(
        modifications=tuple(reversed(modifications))
    ).to_deterministic_json()


def test_cli_artifacts_are_byte_deterministic(tmp_path: Path) -> None:
    input_path = write_artifact(tmp_path)
    first = tmp_path / "first" / "context.json"
    second = tmp_path / "second" / "context.json"
    first.parent.mkdir()
    second.parent.mkdir()
    assert main(cli_args(input_path, first)) == 0
    assert main(cli_args(input_path, second)) == 0
    for name in ("context.json", "context-approval.json", "context-approval-summary.json"):
        assert (first.parent / name).read_bytes() == (second.parent / name).read_bytes()


def test_approval_record_contains_hash_audit_chain(tmp_path: Path) -> None:
    input_path = write_artifact(tmp_path)
    output = tmp_path / "context.json"
    assert main(cli_args(input_path, output)) == 0
    record = (tmp_path / "context-approval.json").read_text()
    assert artifact().document_hash in record
    assert artifact().raw_response_hash in record
    assert CONTRACT.contract_id in record


def test_generated_context_is_accepted_by_threat_analyze(tmp_path: Path) -> None:
    input_path = write_artifact(tmp_path)
    context_path = tmp_path / "context.json"
    assert main(cli_args(input_path, context_path)) == 0
    overlay = tmp_path / "overlay.csv"
    assert analyze_main(
        [
            "controls-windows-server-2025-l1.jsonl",
            "--threat-context",
            str(context_path),
            "--at-time",
            NOW.isoformat(),
            "-o",
            str(overlay),
        ]
    ) == 0
    assert overlay.is_file()
    structured = tmp_path / "overlay.json"
    assert structured.is_file()
    overlays = json.loads(structured.read_text())
    assert overlays
    assert {item["base_proposal"] for item in overlays} <= {
        "Candidate Mandatory",
        "Review Required",
        "Regular Control",
    }


def test_base_mandatory_counts_remain_unchanged() -> None:
    controls = [
        ControlRecord.model_validate_json(line)
        for line in Path("controls-windows-server-2025-l1.jsonl").read_text().splitlines()
        if line.strip()
    ]
    counts = Counter(item.proposal for item in assess_controls(controls))
    assert counts == {
        "Candidate Mandatory": 27,
        "Review Required": 5,
        "Regular Control": 275,
    }
