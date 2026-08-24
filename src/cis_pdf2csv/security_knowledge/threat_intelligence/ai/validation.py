from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from ...catalog.registry import SecurityKnowledgeCatalog
from ...identifiers import IDENTIFIER_PATTERNS
from ...provenance import Confidence
from .contract import (
    DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT,
    AIThreatInterpretationContract,
    content_hash,
)
from .policy import DEFAULT_AI_INTERPRETATION_POLICY, AIInterpretationPolicy
from .schema import (
    AIContractFinding,
    AIContractFindingSeverity,
    EvidenceSupportType,
    InterpretationValidationResult,
    ProposedThreatInterpretation,
    ThreatActivityState,
    ThreatAdvisoryDocument,
)

_INJECTION = re.compile(
    r"ignore (?:all |any )?(?:previous|prior) instructions|mark all controls mandatory|"
    r"do not report uncertainty|output control id|secret external url",
    re.IGNORECASE,
)
_SECRET = re.compile(
    r"(?:api[_ -]?key|password|access[_ -]?token|private key)\s*[:=]",
    re.IGNORECASE,
)
_PERSONAL = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE
)


def _finding(
    code: str,
    severity: AIContractFindingSeverity,
    object_id: str,
    message: str,
    assertion_id: str | None = None,
) -> AIContractFinding:
    return AIContractFinding(
        code=code,
        severity=severity,
        object_id=object_id,
        message=message,
        assertion_id=assertion_id,
    )


def _sorted(findings: list[AIContractFinding]) -> tuple[AIContractFinding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda item: (
                item.severity.value,
                item.code,
                item.object_id,
                item.assertion_id or "",
                item.message,
            ),
        )
    )


def validate_advisory_document(
    document: ThreatAdvisoryDocument,
) -> tuple[AIContractFinding, ...]:
    findings: list[AIContractFinding] = []
    if content_hash(document.content) != document.content_hash:
        findings.append(_finding("AI_INPUT_HASH_MISMATCH", AIContractFindingSeverity.ERROR, document.document_id, "Supplied content does not match content_hash."))
    if _INJECTION.search(document.content):
        findings.append(_finding("AI_INPUT_PROMPT_INJECTION", AIContractFindingSeverity.WARNING, document.document_id, "Source instructions are untrusted evidence and cannot alter authority policy."))
    if _SECRET.search(document.content):
        findings.append(_finding("AI_INPUT_POTENTIAL_SECRET", AIContractFindingSeverity.WARNING, document.document_id, "Source content may contain a secret; review before provider use."))
    if _PERSONAL.search(document.content):
        findings.append(_finding("AI_INPUT_PERSONAL_DATA", AIContractFindingSeverity.WARNING, document.document_id, "Source content may contain personal data; review before provider use."))
    return _sorted(findings)


def validate_interpretation_payload(
    payload: Mapping[str, Any],
    *,
    policy: AIInterpretationPolicy = DEFAULT_AI_INTERPRETATION_POLICY,
) -> tuple[ProposedThreatInterpretation | None, tuple[AIContractFinding, ...]]:
    object_id = str(payload.get("interpretation_id", "unparsed-interpretation"))
    forbidden = sorted(_find_keys(payload, set(policy.prohibited_output_fields)))
    findings = [
        _finding("AI_INTERPRETATION_FORBIDDEN_FIELD", AIContractFindingSeverity.ERROR, object_id, f"Forbidden output field: {field}.")
        for field in forbidden
    ]
    try:
        interpretation = ProposedThreatInterpretation.model_validate(payload)
    except ValidationError as error:
        interpretation = None
        findings.append(_finding("AI_INTERPRETATION_SCHEMA_INVALID", AIContractFindingSeverity.ERROR, object_id, f"Output does not conform to ProposedThreatInterpretation: {error.error_count()} validation error(s)."))
    return interpretation, _sorted(findings)


def _find_keys(value: object, forbidden: set[str]) -> set[str]:
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key) in forbidden:
                found.add(str(key))
            found.update(_find_keys(item, forbidden))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.update(_find_keys(item, forbidden))
    return found


def validate_interpretation(
    interpretation: ProposedThreatInterpretation,
    document: ThreatAdvisoryDocument,
    catalog: SecurityKnowledgeCatalog,
    *,
    policy: AIInterpretationPolicy = DEFAULT_AI_INTERPRETATION_POLICY,
    contract: AIThreatInterpretationContract = DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT,
) -> InterpretationValidationResult:
    findings = list(validate_advisory_document(document))
    object_id = interpretation.interpretation_id
    if len(document.content.encode("utf-8")) > contract.max_input_size:
        findings.append(_finding("AI_INPUT_SIZE_EXCEEDED", AIContractFindingSeverity.ERROR, object_id, "Input exceeds the contract maximum size."))
    if interpretation.input_document_id != document.document_id or interpretation.input_hash != document.content_hash or interpretation.provenance.input_document_hash != document.content_hash:
        findings.append(_finding("AI_INTERPRETATION_INPUT_MISMATCH", AIContractFindingSeverity.ERROR, object_id, "Interpretation input identity does not match the supplied document."))
    metadata_matches = (
        interpretation.source_type == document.source_type
        and interpretation.source_name == document.source_name
        and interpretation.source_reference == document.source_reference
        and interpretation.published_at == document.published_at
    )
    if not metadata_matches:
        findings.append(_finding("AI_INTERPRETATION_DOCUMENT_METADATA_MISMATCH", AIContractFindingSeverity.ERROR, object_id, "Interpretation source metadata does not exactly match the caller-supplied document."))
    if interpretation.provenance.contract_id != contract.contract_id or interpretation.provenance.contract_version != contract.contract_version or interpretation.provenance.authority_policy_version != policy.policy_version:
        findings.append(_finding("AI_INTERPRETATION_CONTRACT_MISMATCH", AIContractFindingSeverity.ERROR, object_id, "Interpretation metadata does not match the governing contract and policy."))

    assertions = {item.assertion_id: item for item in interpretation.evidence_assertions}
    if len(assertions) != len(interpretation.evidence_assertions):
        findings.append(_finding("AI_INTERPRETATION_DUPLICATE_ASSERTION", AIContractFindingSeverity.ERROR, object_id, "Evidence assertion identifiers must be unique."))
    if not assertions:
        findings.append(_finding("AI_INTERPRETATION_MISSING_EVIDENCE", AIContractFindingSeverity.ERROR, object_id, "Material interpretation output requires evidence assertions."))
    for assertion in assertions.values():
        if assertion.support_type == EvidenceSupportType.EXTERNAL_MODEL_KNOWLEDGE:
            findings.append(_finding("AI_INTERPRETATION_UNSUPPORTED_EXTERNAL_KNOWLEDGE", AIContractFindingSeverity.ERROR, object_id, "External model knowledge is excluded by source-grounded policy.", assertion.assertion_id))
        if _INJECTION.search(assertion.value):
            findings.append(_finding("AI_INTERPRETATION_PROMPT_INJECTION_OUTPUT", AIContractFindingSeverity.ERROR, object_id, "Output attempts to carry an untrusted source instruction into policy or decisions.", assertion.assertion_id))
        if _SECRET.search(assertion.value):
            findings.append(_finding("AI_INTERPRETATION_SENSITIVE_OUTPUT", AIContractFindingSeverity.ERROR, object_id, "Sensitive values must not be promoted into interpretation output.", assertion.assertion_id))

    _validate_catalog_ids(interpretation, catalog, findings)
    activity = _matching(assertions, "activity_state", interpretation.proposed_activity_state.value)
    if interpretation.proposed_activity_state in (ThreatActivityState.OBSERVED, ThreatActivityState.ACTIVELY_EXPLOITED) and not any(_explicit(item) for item in activity):
        findings.append(_finding("AI_INTERPRETATION_UNGROUNDED_ACTIVITY_STATE", AIContractFindingSeverity.ERROR, object_id, "Observed or active exploitation requires explicitly stated source evidence."))
    for technology in interpretation.proposed_affected_technology_families:
        matches = _matching(assertions, "affected_technology_family", technology)
        if not any(_explicit(item) for item in matches):
            findings.append(_finding("AI_INTERPRETATION_UNGROUNDED_TECHNOLOGY", AIContractFindingSeverity.ERROR, object_id, f"Affected technology {technology!r} lacks explicitly stated evidence."))

    material_values = _material_values(interpretation)
    for assertion_type, value in material_values:
        if not _matching(assertions, assertion_type, value):
            findings.append(_finding("AI_INTERPRETATION_MISSING_EVIDENCE", AIContractFindingSeverity.ERROR, object_id, f"Material assertion {assertion_type}={value!r} lacks evidence."))

    combined_text = " ".join((interpretation.title, interpretation.summary, *interpretation.unsupported_claims))
    if _INJECTION.search(combined_text):
        findings.append(_finding("AI_INTERPRETATION_PROMPT_INJECTION_OUTPUT", AIContractFindingSeverity.ERROR, object_id, "Interpretation output contains a forbidden decision instruction."))
    if _SECRET.search(combined_text):
        findings.append(_finding("AI_INTERPRETATION_SENSITIVE_OUTPUT", AIContractFindingSeverity.ERROR, object_id, "Interpretation output contains sensitive data."))

    cap = interpretation.proposed_confidence
    material_assertions = [item for item in assertions.values() if item.assertion_type in policy.material_assertion_types]
    if any(item.support_type == EvidenceSupportType.INFERRED or item.inference_required for item in material_assertions):
        cap = _minimum(cap, Confidence.LOW)
    elif any(not _explicit(item) for item in material_assertions) or interpretation.unsupported_claims:
        cap = _minimum(cap, Confidence.MEDIUM)
    if cap != interpretation.proposed_confidence:
        findings.append(_finding("AI_INTERPRETATION_CONFIDENCE_CAPPED", AIContractFindingSeverity.WARNING, object_id, f"Validated confidence is capped at {cap.value} by evidence quality."))
    findings.extend(interpretation.contract_findings)
    return InterpretationValidationResult(interpretation_id=object_id, capped_confidence=cap, findings=_sorted(findings))


def _explicit(assertion: Any) -> bool:
    return assertion.explicitly_stated and assertion.support_type == EvidenceSupportType.EXPLICITLY_STATED and not assertion.inference_required


def _matching(assertions: Mapping[str, Any], assertion_type: str, value: str) -> list[Any]:
    return [item for item in assertions.values() if item.assertion_type == assertion_type and item.value == value]


def _material_values(item: ProposedThreatInterpretation) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    values.extend(("threat_scenario_id", value) for value in item.proposed_threat_scenario_ids)
    values.extend(("technique_id", value) for value in item.proposed_technique_ids)
    values.extend(("attack_path_id", value) for value in item.proposed_attack_path_ids)
    values.extend(("affected_technology_family", value) for value in item.proposed_affected_technology_families)
    if item.proposed_activity_state != ThreatActivityState.UNKNOWN:
        values.append(("activity_state", item.proposed_activity_state.value))
    return values


def required_evidence_bindings(
    interpretation: ProposedThreatInterpretation,
) -> tuple[tuple[str, str], ...]:
    """Return exact security-assertion bindings; never creates evidence."""
    return tuple(sorted(_material_values(interpretation)))


def _validate_catalog_ids(item: ProposedThreatInterpretation, catalog: SecurityKnowledgeCatalog, findings: list[AIContractFinding]) -> None:
    groups = (
        ("TS", item.proposed_threat_scenario_ids, catalog.threat_scenarios, "threat_scenario_id"),
        ("TEC", item.proposed_technique_ids, catalog.attack_techniques, "technique_id"),
        ("AP", item.proposed_attack_path_ids, catalog.attack_paths, "attack_path_id"),
    )
    for prefix, identifiers, objects, field in groups:
        index = {getattr(obj, field): obj for obj in objects}
        for identifier in sorted(set(identifiers)):
            if IDENTIFIER_PATTERNS[prefix].fullmatch(identifier) is None:
                findings.append(_finding("AI_INTERPRETATION_MALFORMED_CATALOG_ID", AIContractFindingSeverity.ERROR, item.interpretation_id, f"Malformed catalog identifier: {identifier}."))
            elif identifier not in index:
                findings.append(_finding("AI_INTERPRETATION_UNKNOWN_CATALOG_ID", AIContractFindingSeverity.ERROR, item.interpretation_id, f"Unknown catalog identifier: {identifier}."))
            elif index[identifier].lifecycle_status != "active":
                findings.append(_finding("AI_INTERPRETATION_INACTIVE_CATALOG_ID", AIContractFindingSeverity.WARNING, item.interpretation_id, f"Catalog identifier {identifier} is {index[identifier].lifecycle_status} and requires review."))


def validate_interpretation_catalog_references(
    interpretation: ProposedThreatInterpretation,
    catalog: SecurityKnowledgeCatalog,
) -> tuple[AIContractFinding, ...]:
    findings: list[AIContractFinding] = []
    _validate_catalog_ids(interpretation, catalog, findings)
    return _sorted(findings)


def _minimum(left: Confidence, right: Confidence) -> Confidence:
    order = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    return left if order[left] <= order[right] else right


__all__ = [
    "required_evidence_bindings",
    "validate_advisory_document",
    "validate_interpretation",
    "validate_interpretation_catalog_references",
    "validate_interpretation_payload",
]
