from __future__ import annotations

from collections import defaultdict

from .models import (
    ManagedAsset,
    ObservationScope,
    ObservedPolicy,
    PotentialConflict,
    SecuritySignal,
)

CAPABILITY_KEYWORDS = {
    "bitlocker_or_disk_encryption": ("bitlocker", "filevault", "disk encryption"),
    "endpoint_protection": (
        "defender",
        "antivirus",
        "endpoint detection",
        "attack surface reduction",
    ),
    "firewall": ("firewall",),
    "legacy_ntlm": ("ntlm", "lan manager authentication"),
    "legacy_smbv1": ("smb v1", "smb1", "smbv1"),
}


def potential_conflicts(
    policies: tuple[ObservedPolicy, ...],
) -> tuple[PotentialConflict, ...]:
    grouped: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
    for policy in policies:
        for setting in policy.settings:
            grouped[setting.identity].append(
                (setting.value, policy.policy_id, policy.name, setting.display_name)
            )
    conflicts: list[PotentialConflict] = []
    for identity, observations in sorted(grouped.items()):
        values = tuple(sorted({item[0] for item in observations}))
        if len(values) < 2:
            continue
        conflicts.append(
            PotentialConflict(
                setting_identity=identity,
                display_name=observations[0][3],
                values=values,
                policy_ids=tuple(sorted({item[1] for item in observations})),
                policy_names=tuple(sorted({item[2] for item in observations})),
            )
        )
    return tuple(conflicts)


def security_signals(
    policies: tuple[ObservedPolicy, ...], assets: tuple[ManagedAsset, ...]
) -> tuple[SecuritySignal, ...]:
    settings = [setting for policy in policies for setting in policy.settings]
    signals: list[SecuritySignal] = []
    for capability, keywords in CAPABILITY_KEYWORDS.items():
        evidence = tuple(
            sorted(
                {
                    f"{setting.policy_name}: {setting.display_name}"
                    for setting in settings
                    if any(
                        keyword
                        in f"{setting.identity} {setting.display_name}".casefold()
                        for keyword in keywords
                    )
                }
            )
        )
        signals.append(
            SecuritySignal(
                capability=capability,
                status="configured" if evidence else "not_observed",
                evidence=evidence,
            )
        )
    encrypted = [asset for asset in assets if asset.encrypted is not None]
    signals.append(
        SecuritySignal(
            capability="device_encryption_inventory",
            status="observed" if encrypted else "not_observed",
            evidence=tuple(
                sorted(
                    f"{asset.name}: encrypted={asset.encrypted}" for asset in encrypted
                )
            ),
            scope=ObservationScope.DEVICE_INVENTORY,
        )
    )
    return tuple(signals)
