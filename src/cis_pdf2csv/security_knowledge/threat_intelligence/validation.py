from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict

from ..catalog.registry import SecurityKnowledgeCatalog
from ..identifiers import IDENTIFIER_PATTERNS
from ..provenance import LifecycleStatus
from .schema import ThreatApplicabilityScope, ThreatContext


class FindingLevel(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ThreatContextValidationFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    severity: FindingLevel
    object_type: str = "threat_context"
    object_id: str
    message: str
    required_action: str

    @property
    def blocking(self) -> bool:
        return self.severity == FindingLevel.ERROR


def _finding(
    code: str,
    severity: FindingLevel,
    context: ThreatContext,
    message: str,
    action: str,
) -> ThreatContextValidationFinding:
    return ThreatContextValidationFinding(
        code=code,
        severity=severity,
        object_id=context.threat_context_id,
        message=message,
        required_action=action,
    )


def _aware(value: datetime | None) -> bool:
    return value is None or (value.tzinfo is not None and value.utcoffset() is not None)


def validate_threat_context(
    context: ThreatContext,
    *,
    at_time: datetime,
) -> tuple[ThreatContextValidationFinding, ...]:
    if not _aware(at_time):
        raise ValueError("at_time must be timezone-aware")
    findings: list[ThreatContextValidationFinding] = []
    if IDENTIFIER_PATTERNS["THRCTX"].fullmatch(context.threat_context_id) is None:
        findings.append(_finding("THREAT_CONTEXT_INVALID_ID", FindingLevel.ERROR, context, "The identifier is outside the THRCTX grammar.", "Assign a deterministic THRCTX identifier."))
    temporal_values = (context.observed_at, context.published_at, context.valid_from, context.valid_until)
    if not all(_aware(value) for value in temporal_values):
        findings.append(_finding("THREAT_CONTEXT_TIMEZONE_REQUIRED", FindingLevel.ERROR, context, "Threat timestamps must be timezone-aware.", "Add an explicit UTC offset to each timestamp."))
    evidence_times = tuple(
        value
        for item in context.evidence
        for value in (
            item.published_at,
            item.retrieved_at,
            item.provenance.retrieved_at,
        )
    )
    if not all(_aware(value) for value in evidence_times):
        findings.append(_finding("THREAT_CONTEXT_EVIDENCE_TIMEZONE_REQUIRED", FindingLevel.ERROR, context, "Threat evidence timestamps must be timezone-aware.", "Add an explicit UTC offset to each evidence timestamp."))
    comparable = all(_aware(value) for value in (context.valid_from, context.valid_until))
    if comparable and context.valid_from is not None and context.valid_until is not None and context.valid_from > context.valid_until:
        findings.append(_finding("THREAT_CONTEXT_INVALID_TIME_RANGE", FindingLevel.ERROR, context, "valid_from is later than valid_until.", "Correct the validity window."))
    if not context.evidence:
        findings.append(_finding("THREAT_CONTEXT_NO_EVIDENCE", FindingLevel.WARNING, context, "No supporting threat evidence is attached.", "Obtain evidence or retain for analyst review."))
    if context.applicability_scope == ThreatApplicabilityScope.UNRESOLVED:
        findings.append(_finding("THREAT_CONTEXT_APPLICABILITY_UNRESOLVED", FindingLevel.WARNING, context, "Threat applicability is unresolved.", "Resolve generic applicability before future priority use."))
    if context.valid_until is not None and _aware(context.valid_until) and context.valid_until < at_time:
        findings.append(_finding("THREAT_CONTEXT_EXPIRED", FindingLevel.INFO, context, "The validity window has expired; the context remains historical and readable.", "Exclude from active future resolution unless historical mode is used."))
        if context.lifecycle_status == LifecycleStatus.ACTIVE:
            findings.append(_finding("THREAT_CONTEXT_LIFECYCLE_CONTRADICTION", FindingLevel.ERROR, context, "An active lifecycle status contradicts the expired validity window.", "Deprecate or supersede the context."))
    if context.valid_from is not None and _aware(context.valid_from) and context.valid_from > at_time:
        findings.append(_finding("THREAT_CONTEXT_FUTURE", FindingLevel.INFO, context, "The context is not valid yet.", "Do not use it as active before valid_from."))
        if context.lifecycle_status == LifecycleStatus.ACTIVE:
            findings.append(_finding("THREAT_CONTEXT_LIFECYCLE_CONTRADICTION", FindingLevel.ERROR, context, "An active lifecycle status contradicts the future validity window.", "Keep the context draft until valid_from."))
    return tuple(sorted(findings, key=lambda item: (item.severity.value, item.code, item.message)))


def validate_catalog_references(
    context: ThreatContext,
    catalog: SecurityKnowledgeCatalog,
    *,
    historical_mode: bool = False,
) -> tuple[ThreatContextValidationFinding, ...]:
    findings: list[ThreatContextValidationFinding] = []
    groups = (
        (context.technique_ids, catalog.attack_techniques, "technique_id", "THREAT_CONTEXT_UNKNOWN_TECHNIQUE"),
        (context.attack_path_ids, catalog.attack_paths, "attack_path_id", "THREAT_CONTEXT_UNKNOWN_ATTACK_PATH"),
        (context.threat_scenario_ids, catalog.threat_scenarios, "threat_scenario_id", "THREAT_CONTEXT_UNKNOWN_THREAT_SCENARIO"),
    )
    for identifiers, objects, field, unknown_code in groups:
        index = {getattr(item, field): item for item in objects}
        for identifier in sorted(set(identifiers)):
            item = index.get(identifier)
            if item is None:
                findings.append(_finding(unknown_code, FindingLevel.WARNING, context, f"Referenced {field} {identifier} is unresolved.", "Resolve the reference or retain it explicitly for review."))
            elif item.lifecycle_status != "active":
                level = FindingLevel.INFO if historical_mode else FindingLevel.ERROR
                findings.append(_finding("THREAT_CONTEXT_INACTIVE_CATALOG_REFERENCE", level, context, f"Referenced {field} {identifier} is {item.lifecycle_status}.", "Use historical mode only for historical analysis; otherwise resolve an active successor."))
    return tuple(sorted(findings, key=lambda item: (item.severity.value, item.code, item.message)))
