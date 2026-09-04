from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from cis_pdf2csv.environment_scan.cli import main
from cis_pdf2csv.environment_scan.gpo import parse_gpo_report, parse_gpo_reports
from cis_pdf2csv.environment_scan.intune import (
    collect_graph_bundle,
    normalize_intune_bundle,
)
from cis_pdf2csv.environment_scan.models import (
    CollectionStatus,
    CurrentStateSnapshot,
    EnvironmentSource,
)
from cis_pdf2csv.environment_scan.service import build_snapshot


def intune_bundle() -> dict[str, object]:
    def policy(policy_id: str, value: str) -> dict[str, object]:
        return {
            "id": policy_id,
            "name": f"Policy {policy_id}",
            "platforms": "windows10",
            "technologies": "mdm",
            "settings": [
                {
                    "settingInstance": {
                        "settingDefinitionId": "vendor_msft_firewall_enable",
                        "simpleSettingValue": {"value": value},
                    }
                }
            ],
            "assignments": [
                {
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": "group-1",
                    }
                },
                {
                    "target": {
                        "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
                        "groupId": "excluded-group",
                    }
                },
            ],
        }

    return {
        "configurationPolicies": [policy("p1", "enabled"), policy("p2", "disabled")],
        "deviceConfigurations": [],
        "groupPolicyConfigurations": [],
        "managedDevices": [
            {
                "id": "device-1",
                "deviceName": "WIN-01",
                "operatingSystem": "Windows",
                "osVersion": "10.0.26100",
                "complianceState": "compliant",
                "managementAgent": "mdm",
                "isEncrypted": True,
            }
        ],
    }


def test_intune_bundle_preserves_assignments_assets_and_potential_conflicts() -> None:
    policies, assets, errors = normalize_intune_bundle(intune_bundle())
    snapshot = build_snapshot(
        source=EnvironmentSource.INTUNE,
        policies=policies,
        assets=assets,
        errors=errors,
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert snapshot.status == CollectionStatus.COMPLETE
    assert snapshot.policy_count == 2
    assert snapshot.setting_count == 2
    assert snapshot.asset_count == 1
    assert len(snapshot.potential_conflicts) == 1
    assert {item.kind.value for item in policies[0].assignments} == {
        "include",
        "exclude",
    }
    assert (
        next(
            item for item in snapshot.security_signals if item.capability == "firewall"
        ).status
        == "configured"
    )
    assert (
        next(
            item
            for item in snapshot.security_signals
            if item.capability == "device_encryption_inventory"
        ).status
        == "observed"
    )
    assert "effective_state" not in {scope.value for scope in snapshot.scopes}


def test_partial_graph_collection_is_explicit_and_fail_closed() -> None:
    bundle = intune_bundle()
    bundle["_errors"] = ["managedDevices: forbidden"]
    policies, assets, errors = normalize_intune_bundle(bundle)
    snapshot = build_snapshot(
        source=EnvironmentSource.INTUNE,
        policies=policies,
        assets=assets,
        errors=errors,
    )

    assert snapshot.status == CollectionStatus.PARTIAL
    assert snapshot.collection_errors == ("managedDevices: forbidden",)


def test_gpo_xml_extracts_declared_setting_and_link(tmp_path: Path) -> None:
    report = tmp_path / "baseline.xml"
    report.write_text(
        """<?xml version="1.0"?>
<GPO>
  <Identifier>{ABC}</Identifier>
  <Name>CIS Workstation Baseline</Name>
  <LinksTo><SOMName>Workstations</SOMName><Enabled>true</Enabled></LinksTo>
  <Computer><ExtensionData><Extension>
    <Policy><Name>Configure Windows Defender Firewall</Name><State>Enabled</State></Policy>
  </Extension></ExtensionData></Computer>
</GPO>
""",
        encoding="utf-8",
    )

    policy = parse_gpo_report(report)

    assert policy.policy_id == "{ABC}"
    assert policy.name == "CIS Workstation Baseline"
    assert policy.settings[0].display_name == "Configure Windows Defender Firewall"
    assert policy.assignments[0].target_id == "Workstations"


def test_combined_gpo_report_preserves_each_policy(tmp_path: Path) -> None:
    report = tmp_path / "all.xml"
    report.write_text(
        "<GPOS><GPO><Identifier>one</Identifier><Name>One</Name></GPO>"
        "<GPO><Identifier>two</Identifier><Name>Two</Name></GPO></GPOS>",
        encoding="utf-8",
    )

    policies = parse_gpo_reports(report)

    assert [(item.policy_id, item.name) for item in policies] == [
        ("one", "One"),
        ("two", "Two"),
    ]


def test_cli_imports_offline_intune_export(tmp_path: Path) -> None:
    input_path = tmp_path / "intune-export.json"
    input_path.write_text(json.dumps(intune_bundle()), encoding="utf-8")
    output_path = tmp_path / "current-state.json"

    assert (
        main(["--source", "intune", "--input", str(input_path), "-o", str(output_path)])
        == 0
    )

    snapshot = CurrentStateSnapshot.model_validate_json(
        output_path.read_text(encoding="utf-8")
    )
    assert snapshot.provenance.input_sha256
    assert snapshot.policy_count == 2


def test_cli_imports_gpo_report_directory(tmp_path: Path) -> None:
    report = tmp_path / "baseline.xml"
    report.write_text(
        "<GPO><Identifier>id</Identifier><Name>Baseline</Name>"
        "<Policy><Name>Firewall</Name><State>Enabled</State></Policy></GPO>",
        encoding="utf-8",
    )
    output_path = tmp_path / "current-state.json"

    assert (
        main(["--source", "gpo", "--input", str(tmp_path), "-o", str(output_path)]) == 0
    )

    snapshot = CurrentStateSnapshot.model_validate_json(
        output_path.read_text(encoding="utf-8")
    )
    assert snapshot.provenance.source == EnvironmentSource.GPO
    assert snapshot.policy_count == 1


def test_live_intune_scan_requires_local_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("MS_GRAPH_ACCESS_TOKEN", raising=False)

    with pytest.raises(SystemExit):
        main(["--source", "intune", "-o", str(tmp_path / "state.json")])


class FakeTransport:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def get(self, url: str) -> dict[str, Any]:
        self.urls.append(url)
        if url.endswith(("/settings", "/assignments")) or "definitionValues?" in url:
            return {"value": []}
        if "configurationPolicies" in url:
            return {"value": [{"id": "p1", "name": "Policy"}]}
        return {"value": []}


def test_live_graph_bundle_uses_separate_settings_and_assignment_collections() -> None:
    transport = FakeTransport()

    bundle = collect_graph_bundle(transport, base_url="https://graph.example")

    assert bundle["_errors"] == []
    assert any(
        url.endswith("configurationPolicies/p1/settings") for url in transport.urls
    )
    assert any(
        url.endswith("configurationPolicies/p1/assignments") for url in transport.urls
    )
