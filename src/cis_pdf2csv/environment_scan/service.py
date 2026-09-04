from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .analysis import potential_conflicts, security_signals
from .models import (
    CollectionStatus,
    CurrentStateSnapshot,
    EnvironmentSource,
    ManagedAsset,
    ObservationScope,
    ObservedPolicy,
    ScanProvenance,
)

COLLECTOR_VERSION = "1.0"


def sha256_files(paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.name).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def build_snapshot(
    *,
    source: EnvironmentSource,
    policies: tuple[ObservedPolicy, ...],
    assets: tuple[ManagedAsset, ...] = (),
    errors: tuple[str, ...] = (),
    input_sha256: str | None = None,
    tenant_id: str | None = None,
    source_reference: str | None = None,
    collected_at: datetime | None = None,
) -> CurrentStateSnapshot:
    timestamp = (collected_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    scopes = [ObservationScope.DECLARED_CONFIGURATION]
    if assets:
        scopes.append(ObservationScope.DEVICE_INVENTORY)
    warnings = [
        "Configured settings are declared intent, not proof of effective device state.",
        "Potential conflicts require assignment-overlap and per-device validation.",
    ]
    if not assets and source == EnvironmentSource.INTUNE:
        warnings.append("No managed-device inventory was observed.")
    if source == EnvironmentSource.GPO:
        warnings.append("GPO XML does not prove resultant set of policy on any device.")
    ordered_policies = tuple(
        sorted(policies, key=lambda item: (item.policy_type, item.name, item.policy_id))
    )
    ordered_assets = tuple(sorted(assets, key=lambda item: (item.name, item.asset_id)))
    return CurrentStateSnapshot(
        status=CollectionStatus.PARTIAL if errors else CollectionStatus.COMPLETE,
        scopes=tuple(scopes),
        provenance=ScanProvenance(
            source=source,
            collected_at_utc=timestamp.isoformat().replace("+00:00", "Z"),
            collector_version=COLLECTOR_VERSION,
            input_sha256=input_sha256,
            tenant_id=tenant_id,
            source_reference=source_reference,
        ),
        policies=ordered_policies,
        assets=ordered_assets,
        potential_conflicts=potential_conflicts(ordered_policies),
        security_signals=security_signals(ordered_policies, ordered_assets),
        warnings=tuple(warnings),
        collection_errors=errors,
        policy_count=len(ordered_policies),
        setting_count=sum(len(policy.settings) for policy in ordered_policies),
        asset_count=len(ordered_assets),
    )
