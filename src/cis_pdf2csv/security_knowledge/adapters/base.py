from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from pydantic import BaseModel, ConfigDict

from cis_pdf2csv.schema import ControlRecord


class BenchmarkFamily(str, Enum):
    MICROSOFT_WINDOWS_SERVER = "microsoft-windows-server"
    MICROSOFT_365_FOUNDATIONS = "microsoft-365-foundations"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"


class LicenseScope(str, Enum):
    E3 = "E3"
    E5 = "E5"
    E3_OR_E5 = "E3_or_E5"
    UNKNOWN = "unknown"


class DeploymentScope(str, Enum):
    TENANT_WIDE = "tenant_wide"
    FEATURE_SPECIFIC = "feature_specific"
    SERVICE_SPECIFIC = "service_specific"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"


class FamilyApplicabilityStatus(str, Enum):
    APPLICABLE = "applicable"
    MANDATORY_WHEN_FEATURE_DEPLOYED = "mandatory_when_feature_deployed"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


class NormalizedApplicability(BaseModel):
    model_config = ConfigDict(frozen=True)

    license_scope: LicenseScope = LicenseScope.UNKNOWN
    deployment_scope: DeploymentScope = DeploymentScope.UNKNOWN
    applicability_status: FamilyApplicabilityStatus = FamilyApplicabilityStatus.UNRESOLVED


class BoundaryCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    semantic_mapping_id: str
    semantic_domain: str
    security_effect: str
    evidence: tuple[str, ...]
    satisfied_sub_boundaries: tuple[str, ...] = ()
    boundary_role: str = "boundary_set_core_member"
    non_compensable: bool = False


class BenchmarkFamilyAdapter(ABC):
    family: BenchmarkFamily

    @abstractmethod
    def supports(self, control: ControlRecord) -> bool: ...

    @abstractmethod
    def normalize_applicability(self, control: ControlRecord) -> NormalizedApplicability: ...

    @abstractmethod
    def derive_semantic_subjects(self, control: ControlRecord) -> tuple[str, ...]: ...

    @abstractmethod
    def identify_boundary_candidates(self, control: ControlRecord) -> tuple[BoundaryCandidate, ...]: ...

    @abstractmethod
    def classify_security_role(self, control: ControlRecord) -> str: ...

    @abstractmethod
    def extract_family_specific_evidence(self, control: ControlRecord) -> tuple[str, ...]: ...

    def applicability_status(self, control: ControlRecord) -> FamilyApplicabilityStatus:
        return self.normalize_applicability(control).applicability_status
