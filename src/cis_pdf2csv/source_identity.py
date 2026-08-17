from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict

from cis_pdf2csv.schema import ControlRecord


class SourceIdentity(BaseModel):
    """Immutable, benchmark-scoped identity for one source recommendation."""

    model_config = ConfigDict(frozen=True)

    source_framework: str = "cis"
    benchmark_family: str
    benchmark_name: str
    benchmark_version: str
    benchmark_profile: str
    control_id: str

    def as_tuple(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.source_framework,
            self.benchmark_family,
            self.benchmark_name,
            self.benchmark_version,
            self.benchmark_profile,
            self.control_id,
        )

    def benchmark_scope(self) -> tuple[str, str, str, str, str]:
        return self.as_tuple()[:-1]

    def serialize(self) -> str:
        return json.dumps(self.as_tuple(), ensure_ascii=False, separators=(",", ":"))


def source_identity_for_control(control: ControlRecord) -> SourceIdentity:
    # Import lazily because adapters themselves depend on ControlRecord.
    from cis_pdf2csv.security_knowledge.adapters import select_adapter

    selection = select_adapter(control)
    return SourceIdentity(
        benchmark_family=selection.family.value,
        benchmark_name=control.benchmark_name,
        benchmark_version=control.benchmark_version,
        benchmark_profile=control.profile,
        control_id=control.control_id,
    )


def index_controls_by_source_identity(
    controls: list[ControlRecord],
) -> dict[SourceIdentity, ControlRecord]:
    indexed: dict[SourceIdentity, ControlRecord] = {}
    for control in controls:
        identity = source_identity_for_control(control)
        if identity in indexed:
            raise ValueError(f"Duplicate composite source identity: {identity.serialize()}")
        indexed[identity] = control
    return indexed
