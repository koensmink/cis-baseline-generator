from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .provenance import Confidence


class EvidenceType(str, Enum):
    SOURCE_CONTROL = "source_control_evidence"
    CURATED_SECURITY = "curated_security_evidence"
    EXTERNAL_REFERENCE = "external_reference"
    ANALYST_INFERENCE = "analyst_inference"
    TEST = "test_evidence"
    REVIEW = "review_evidence"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_type: EvidenceType
    source: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    assertion: str = Field(min_length=1)
    collection_method: str = Field(min_length=1)
    confidence: Confidence
    timestamp: datetime | None = None

