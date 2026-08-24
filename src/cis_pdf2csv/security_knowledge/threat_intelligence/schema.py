from __future__ import annotations

import json
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from ..identifiers import AttackPathId, TechniqueId, ThreatContextId, ThreatScenarioId
from ..provenance import Confidence, LifecycleStatus
from .provenance import ThreatContextProvenance, ThreatEvidenceProvenance


class ThreatSourceType(str, Enum):
    VENDOR = "vendor"
    GOVERNMENT = "government"
    VULNERABILITY_DATABASE = "vulnerability_database"
    THREAT_RESEARCH = "threat_research"
    INCIDENT = "incident"
    INTERNAL = "internal"
    ANALYST = "analyst"


class ThreatSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ThreatApplicabilityScope(str, Enum):
    GLOBAL = "global"
    TECHNOLOGY_FAMILY = "technology_family"
    PRODUCT_FAMILY = "product_family"
    DEPLOYMENT_SPECIFIC = "deployment_specific"
    SECTOR_SPECIFIC = "sector_specific"
    ENVIRONMENT_SPECIFIC = "environment_specific"
    UNRESOLVED = "unresolved"


class ThreatEvidenceType(str, Enum):
    VENDOR_ADVISORY = "vendor_advisory"
    GOVERNMENT_ADVISORY = "government_advisory"
    VULNERABILITY_RECORD = "vulnerability_record"
    THREAT_RESEARCH_REPORT = "threat_research_report"
    INCIDENT_OBSERVATION = "incident_observation"
    INTERNAL_SECURITY_OBSERVATION = "internal_security_observation"
    ANALYST_ASSERTION = "analyst_assertion"


class ThreatEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_type: ThreatEvidenceType
    source: str = Field(min_length=1)
    external_reference: str = Field(min_length=1)
    assertion: str = Field(min_length=1)
    confidence: Confidence
    published_at: datetime | None = None
    retrieved_at: datetime | None = None
    provenance: ThreatEvidenceProvenance


class ThreatContext(BaseModel):
    """Time-sensitive evidence pointing to immutable Security Knowledge objects."""

    model_config = ConfigDict(frozen=True)

    threat_context_id: ThreatContextId
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source_type: ThreatSourceType
    source_name: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    observed_at: datetime | None = None
    published_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    confidence: Confidence
    severity: ThreatSeverity
    lifecycle_status: LifecycleStatus
    threat_scenario_ids: tuple[ThreatScenarioId, ...] = ()
    technique_ids: tuple[TechniqueId, ...] = ()
    attack_path_ids: tuple[AttackPathId, ...] = ()
    targeted_asset_classes: tuple[str, ...] = ()
    affected_technology_families: tuple[str, ...] = ()
    applicability_scope: ThreatApplicabilityScope
    evidence: tuple[ThreatEvidence, ...] = ()
    provenance: ThreatContextProvenance

    def is_active(self, at_time: datetime) -> bool:
        """Return active state at an explicit instant; never reads the system clock."""
        if at_time.tzinfo is None or at_time.utcoffset() is None:
            raise ValueError("at_time must be timezone-aware")
        if self.lifecycle_status != LifecycleStatus.ACTIVE:
            return False
        if self.valid_from is not None and at_time < self.valid_from:
            return False
        return self.valid_until is None or at_time < self.valid_until

    def to_deterministic_json(self) -> str:
        """Serialize canonically, including canonical ordering for set-like fields."""
        payload = self.model_dump(mode="json")
        for field in (
            "threat_scenario_ids",
            "technique_ids",
            "attack_path_ids",
            "targeted_asset_classes",
            "affected_technology_families",
        ):
            payload[field] = sorted(set(payload[field]))
        payload["evidence"] = sorted(
            payload["evidence"],
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
