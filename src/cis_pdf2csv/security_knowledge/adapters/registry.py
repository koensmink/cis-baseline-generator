from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from cis_pdf2csv.schema import ControlRecord

from .base import BenchmarkFamily, BenchmarkFamilyAdapter
from .microsoft_365 import Microsoft365Adapter
from .windows_server import WindowsServerAdapter

ADAPTERS: tuple[BenchmarkFamilyAdapter, ...] = (
    WindowsServerAdapter(),
    Microsoft365Adapter(),
)


class AdapterSelection(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    family: BenchmarkFamily
    adapter: BenchmarkFamilyAdapter | None = None
    finding: str | None = None


def select_adapter(control: ControlRecord) -> AdapterSelection:
    matches = tuple(adapter for adapter in ADAPTERS if adapter.supports(control))
    if len(matches) == 1:
        return AdapterSelection(family=matches[0].family, adapter=matches[0])
    if not matches:
        return AdapterSelection(
            family=BenchmarkFamily.UNKNOWN,
            finding="BENCHMARK_FAMILY_UNSUPPORTED",
        )
    return AdapterSelection(
        family=BenchmarkFamily.AMBIGUOUS,
        finding="BENCHMARK_FAMILY_AMBIGUOUS",
    )
