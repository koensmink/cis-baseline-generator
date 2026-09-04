from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from cis_pdf2csv.source_identity import SourceIdentity


class SecurityCategory(str, Enum):
    ACCOUNT_POLICY = "Account Policy"
    APPLICATION_CONTROL = "Application Control"
    AUDIT_LOGGING = "Audit & Logging"
    DATA_PROTECTION = "Data Protection"
    ENDPOINT_PROTECTION = "Endpoint Protection"
    IDENTITY_ACCESS = "Identity & Access"
    NETWORK_SECURITY = "Network Security"
    PRIVILEGED_ACCESS = "Privileged Access"
    REMOTE_ACCESS = "Remote Access"
    SYSTEM_HARDENING = "System Hardening"
    UPDATE_MANAGEMENT = "Update Management"


class PlanningLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class PriorityTier(str, Enum):
    NORMAL = "Normal"
    ELEVATED = "Elevated"
    HIGH = "High"
    CRITICAL = "Critical"


class DeploymentReadiness(str, Enum):
    DEPLOYMENT_READY = "deployment_ready"
    NEEDS_VALIDATION = "needs_validation"
    MANUAL_IMPLEMENTATION = "manual_implementation"


class ReviewStatus(str, Enum):
    DETERMINISTIC = "deterministic"
    PROPOSED = "proposed"
    MANUAL_REVIEW = "manual_review"


class EnrichedControl(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_identity: SourceIdentity
    benchmark_name: str
    benchmark_version: str
    control_id: str
    profile: str
    assessment: str
    title: str
    risk_statement: str
    prevents: tuple[str, ...]
    security_category: SecurityCategory
    work_package: str
    implementation_complexity: PlanningLevel
    operational_impact: PlanningLevel
    user_impact: PlanningLevel
    testing_requirement: str
    rollback_complexity: PlanningLevel
    mandatory_proposal: str
    intune_mapping_status: str
    deployment_readiness: DeploymentReadiness
    priority_score: int = Field(ge=0, le=100)
    priority_tier: PriorityTier
    recommended_wave: int = Field(ge=0, le=5)
    execution_phase: str
    wave_rationale: str
    dependencies: tuple[str, ...] = ()
    evidence_sources: tuple[str, ...] = ()
    review_status: ReviewStatus = ReviewStatus.DETERMINISTIC


class WorkPackage(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    security_category: SecurityCategory
    execution_phases: tuple[str, ...]
    control_count: int = Field(ge=1)
    control_ids: tuple[str, ...]
    objective: str
    dependencies: tuple[str, ...]
    highest_priority: PriorityTier
    highest_operational_impact: PlanningLevel
    deployment_ready_controls: int = Field(ge=0)
    review_required_controls: int = Field(ge=0)


class ImplementationPhase(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    wave: int = Field(ge=0, le=5)
    control_count: int = Field(ge=1)
    work_packages: tuple[str, ...]
    control_ids: tuple[str, ...]
    dependencies: tuple[str, ...]
    highest_operational_impact: PlanningLevel


class BaselinePlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    controls: tuple[EnrichedControl, ...]
    work_packages: tuple[WorkPackage, ...]
    implementation_phases: tuple[ImplementationPhase, ...]
    prerequisites: tuple[str, ...]
