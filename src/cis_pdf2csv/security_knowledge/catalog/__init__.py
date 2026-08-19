from __future__ import annotations

from .attack_paths import ATTACK_PATHS
from .boundaries import BOUNDARIES
from .boundary_sets import BOUNDARY_SETS
from .capabilities import CAPABILITIES, PROVENANCE
from .mappings import LEGACY_MIGRATION_MAP
from .outcomes import SECURITY_OUTCOMES
from .registry import SecurityKnowledgeCatalog
from .techniques import TECHNIQUES
from .threat_scenarios import THREAT_SCENARIOS


def build_catalog() -> SecurityKnowledgeCatalog:
    return SecurityKnowledgeCatalog(
        catalog_id="SKC-CORE",
        catalog_version="1.2.0",
        ontology_version="1.0.0",
        lifecycle_status="active",
        capabilities=CAPABILITIES,
        boundary_definitions=BOUNDARIES,
        boundary_set_definitions=BOUNDARY_SETS,
        threat_scenarios=THREAT_SCENARIOS,
        attack_techniques=TECHNIQUES,
        attack_paths=ATTACK_PATHS,
        security_outcomes=SECURITY_OUTCOMES,
        migration_map=LEGACY_MIGRATION_MAP,
        provenance=PROVENANCE,
    )


SECURITY_KNOWLEDGE_CATALOG = build_catalog()

__all__ = ["SECURITY_KNOWLEDGE_CATALOG", "SecurityKnowledgeCatalog", "build_catalog"]
