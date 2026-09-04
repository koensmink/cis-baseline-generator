from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EnvironmentSource(str, Enum):
    INTUNE = "intune"
    GPO = "gpo"


class CollectionStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class ObservationScope(str, Enum):
    DECLARED_CONFIGURATION = "declared_configuration"
    DEVICE_INVENTORY = "device_inventory"
    EFFECTIVE_STATE = "effective_state"


class AssignmentKind(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class PolicyAssignment(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: AssignmentKind
    target_type: str
    target_id: str | None = None
    filter_id: str | None = None
    filter_type: str | None = None


class ObservedSetting(BaseModel):
    model_config = ConfigDict(frozen=True)

    identity: str
    display_name: str
    value: str
    policy_id: str
    policy_name: str
    source_path: str
    scope: ObservationScope = ObservationScope.DECLARED_CONFIGURATION


class ObservedPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_id: str
    name: str
    policy_type: str
    platform: str | None = None
    technologies: str | None = None
    settings: tuple[ObservedSetting, ...] = ()
    assignments: tuple[PolicyAssignment, ...] = ()


class ManagedAsset(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_id: str
    name: str
    operating_system: str | None = None
    os_version: str | None = None
    compliance_state: str | None = None
    management_agent: str | None = None
    encrypted: bool | None = None
    last_sync_at: str | None = None


class PotentialConflict(BaseModel):
    model_config = ConfigDict(frozen=True)

    setting_identity: str
    display_name: str
    values: tuple[str, ...]
    policy_ids: tuple[str, ...]
    policy_names: tuple[str, ...]
    reason: str = (
        "Different declared values were found; assignment overlap is not proven."
    )


class SecuritySignal(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability: str
    status: str
    evidence: tuple[str, ...] = ()
    scope: ObservationScope = ObservationScope.DECLARED_CONFIGURATION


class ScanProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: EnvironmentSource
    collected_at_utc: str
    collector_version: str
    input_sha256: str | None = None
    tenant_id: str | None = None
    source_reference: str | None = None


class CurrentStateSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.0"
    status: CollectionStatus
    scopes: tuple[ObservationScope, ...]
    provenance: ScanProvenance
    policies: tuple[ObservedPolicy, ...] = ()
    assets: tuple[ManagedAsset, ...] = ()
    potential_conflicts: tuple[PotentialConflict, ...] = ()
    security_signals: tuple[SecuritySignal, ...] = ()
    warnings: tuple[str, ...] = ()
    collection_errors: tuple[str, ...] = ()
    policy_count: int = Field(ge=0)
    setting_count: int = Field(ge=0)
    asset_count: int = Field(ge=0)
