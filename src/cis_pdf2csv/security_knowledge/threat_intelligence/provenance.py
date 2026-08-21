from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ThreatEvidenceProvenance(BaseModel):
    """Traceability for a concise threat assertion, not copied source content."""

    model_config = ConfigDict(frozen=True, protected_namespaces=())

    collection_method: str = Field(min_length=1)
    source_revision: str | None = None
    retrieved_at: datetime | None = None
    analyst: str | None = None


class ThreatContextProvenance(BaseModel):
    """Authorship and revision metadata for a ThreatContext."""

    model_config = ConfigDict(frozen=True, protected_namespaces=())

    authority: str = Field(min_length=1)
    creation_method: str = Field(min_length=1)
    model_version: str = Field(min_length=1)
    object_version: str = Field(min_length=1)
    created_at: datetime | None = None
    supersedes_id: str | None = None
