from __future__ import annotations

from pathlib import Path

from .registry import SecurityKnowledgeCatalog


def write_catalog_json(catalog: SecurityKnowledgeCatalog, path: Path) -> None:
    path.write_text(catalog.to_deterministic_json(), encoding="utf-8")
