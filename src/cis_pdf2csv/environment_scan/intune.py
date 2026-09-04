from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import (
    AssignmentKind,
    ManagedAsset,
    ObservedPolicy,
    ObservedSetting,
    PolicyAssignment,
)


class GraphError(RuntimeError):
    """Raised when a Microsoft Graph response cannot be collected safely."""


class GraphTransport(Protocol):
    def get(self, url: str) -> Mapping[str, Any]: ...


class UrllibGraphTransport:
    def __init__(
        self,
        access_token: str,
        *,
        opener: Callable[..., Any] = urlopen,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._access_token = access_token
        self._opener = opener
        self._timeout_seconds = timeout_seconds

    def get(self, url: str) -> Mapping[str, Any]:
        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Accept": "application/json",
            },
        )
        try:
            with self._opener(request, timeout=self._timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise GraphError(
                f"Microsoft Graph returned HTTP {exc.code} for {url}"
            ) from exc
        except URLError as exc:
            raise GraphError(
                f"Microsoft Graph request failed for {url}: {exc.reason}"
            ) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GraphError(
                f"Microsoft Graph returned invalid JSON for {url}"
            ) from exc
        if not isinstance(payload, dict):
            raise GraphError(
                f"Microsoft Graph returned a non-object response for {url}"
            )
        return payload


GRAPH_COLLECTIONS = {
    "configurationPolicies": ("beta", "/deviceManagement/configurationPolicies"),
    "deviceConfigurations": ("v1.0", "/deviceManagement/deviceConfigurations"),
    "groupPolicyConfigurations": (
        "beta",
        "/deviceManagement/groupPolicyConfigurations",
    ),
    "managedDevices": (
        "v1.0",
        (
            "/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,"
            "complianceState,managementAgent,isEncrypted,lastSyncDateTime"
        ),
    ),
}

POLICY_SUBRESOURCES = {
    "configurationPolicies": (
        ("_settings", "beta", "settings"),
        ("_assignments", "beta", "assignments"),
    ),
    "deviceConfigurations": (("_assignments", "v1.0", "assignments"),),
    "groupPolicyConfigurations": (
        ("_assignments", "beta", "assignments"),
        (
            "_settings",
            "beta",
            "definitionValues?$expand=definition,presentationValues",
        ),
    ),
}


def _pages(transport: GraphTransport, url: str) -> Iterator[Mapping[str, Any]]:
    next_url: str | None = url
    while next_url:
        payload = transport.get(next_url)
        yield payload
        candidate = payload.get("@odata.nextLink")
        next_url = candidate if isinstance(candidate, str) and candidate else None


def _collection(transport: GraphTransport, url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for page in _pages(transport, url):
        value = page.get("value", [])
        if not isinstance(value, list):
            raise GraphError(
                f"Microsoft Graph collection response has no list value: {url}"
            )
        rows.extend(item for item in value if isinstance(item, dict))
    return rows


def collect_graph_bundle(
    transport: GraphTransport, *, base_url: str = "https://graph.microsoft.com"
) -> dict[str, object]:
    bundle: dict[str, object] = {}
    errors: list[str] = []
    for name, (version, path) in GRAPH_COLLECTIONS.items():
        url = f"{base_url.rstrip('/')}/{version}{path}"
        try:
            bundle[name] = _collection(transport, url)
        except GraphError as exc:
            bundle[name] = []
            errors.append(f"{name}: {exc}")
    for collection_name, subresources in POLICY_SUBRESOURCES.items():
        collection = bundle.get(collection_name, [])
        if not isinstance(collection, list):
            continue
        for policy in collection:
            if not isinstance(policy, dict) or not policy.get("id"):
                continue
            policy_id = str(policy["id"])
            for field, version, suffix in subresources:
                try:
                    policy[field] = _collection(
                        transport,
                        f"{base_url.rstrip('/')}/{version}/deviceManagement/"
                        f"{collection_name}/{policy_id}/{suffix}",
                    )
                except GraphError as exc:
                    policy[field] = []
                    errors.append(f"{collection_name}/{policy_id}/{suffix}: {exc}")
    bundle["_errors"] = errors
    return bundle


def _as_rows(value: object) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("value"), list):
        return [item for item in value["value"] if isinstance(item, dict)]
    return []


def _walk_setting_instances(value: object) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if "settingDefinitionId" in value:
            yield value
        for child in value.values():
            yield from _walk_setting_instances(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_setting_instances(child)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _configuration_settings(policy: Mapping[str, Any]) -> tuple[ObservedSetting, ...]:
    policy_id = str(policy.get("id", "unknown"))
    policy_name = str(policy.get("name") or policy.get("displayName") or policy_id)
    source = f"configurationPolicies/{policy_id}/settings"
    rows = _as_rows(policy.get("_settings", policy.get("settings", [])))
    settings: list[ObservedSetting] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        instances = tuple(_walk_setting_instances(row.get("settingInstance", row)))
        for instance in instances:
            identity = str(instance.get("settingDefinitionId", "unknown"))
            value = _canonical_json(instance)
            key = (identity, value)
            if key in seen:
                continue
            seen.add(key)
            settings.append(
                ObservedSetting(
                    identity=identity,
                    display_name=identity,
                    value=value,
                    policy_id=policy_id,
                    policy_name=policy_name,
                    source_path=source,
                )
            )
    return tuple(sorted(settings, key=lambda item: (item.identity, item.value)))


def _assignments(policy: Mapping[str, Any]) -> tuple[PolicyAssignment, ...]:
    assignments: list[PolicyAssignment] = []
    for row in _as_rows(policy.get("_assignments", policy.get("assignments", []))):
        target = row.get("target", {})
        if not isinstance(target, dict):
            continue
        target_type = str(target.get("@odata.type", "unknown")).rsplit(".", maxsplit=1)[
            -1
        ]
        kind = (
            AssignmentKind.EXCLUDE
            if "exclusion" in target_type.casefold()
            else AssignmentKind.INCLUDE
        )
        assignments.append(
            PolicyAssignment(
                kind=kind,
                target_type=target_type,
                target_id=str(target["groupId"]) if target.get("groupId") else None,
                filter_id=(
                    str(target["deviceAndAppManagementAssignmentFilterId"])
                    if target.get("deviceAndAppManagementAssignmentFilterId")
                    else None
                ),
                filter_type=(
                    str(target["deviceAndAppManagementAssignmentFilterType"])
                    if target.get("deviceAndAppManagementAssignmentFilterType")
                    else None
                ),
            )
        )
    return tuple(assignments)


LEGACY_METADATA_FIELDS = {
    "id",
    "displayName",
    "description",
    "createdDateTime",
    "lastModifiedDateTime",
    "version",
    "supportsScopeTags",
    "roleScopeTagIds",
    "@odata.type",
    "assignments",
}


def _legacy_settings(
    policy: Mapping[str, Any], policy_type: str
) -> tuple[ObservedSetting, ...]:
    policy_id = str(policy.get("id", "unknown"))
    policy_name = str(policy.get("displayName") or policy.get("name") or policy_id)
    settings = [
        ObservedSetting(
            identity=f"{policy_type}:{key}",
            display_name=key,
            value=_canonical_json(value),
            policy_id=policy_id,
            policy_name=policy_name,
            source_path=f"{policy_type}/{policy_id}",
        )
        for key, value in policy.items()
        if key not in LEGACY_METADATA_FIELDS and not key.startswith("_")
    ]
    return tuple(sorted(settings, key=lambda item: item.identity))


def _group_policy_settings(
    policy: Mapping[str, Any],
) -> tuple[ObservedSetting, ...]:
    policy_id = str(policy.get("id", "unknown"))
    policy_name = str(policy.get("displayName") or policy.get("name") or policy_id)
    settings: list[ObservedSetting] = []
    for row in _as_rows(policy.get("_settings", [])):
        definition_value = row.get("definition", {})
        definition = definition_value if isinstance(definition_value, dict) else {}
        identity = str(
            definition.get("id")
            or row.get("definitionId")
            or row.get("id")
            or "unknown"
        )
        display_name = str(
            definition.get("displayName") or definition.get("policyType") or identity
        )
        settings.append(
            ObservedSetting(
                identity=f"group_policy_configuration:{identity}",
                display_name=display_name,
                value=_canonical_json(row),
                policy_id=policy_id,
                policy_name=policy_name,
                source_path=f"groupPolicyConfigurations/{policy_id}/definitionValues",
            )
        )
    return tuple(sorted(settings, key=lambda item: (item.identity, item.value)))


def normalize_intune_bundle(
    bundle: Mapping[str, Any],
) -> tuple[tuple[ObservedPolicy, ...], tuple[ManagedAsset, ...], tuple[str, ...]]:
    policies: list[ObservedPolicy] = []
    for row in _as_rows(bundle.get("configurationPolicies", [])):
        policy_id = str(row.get("id", "unknown"))
        policies.append(
            ObservedPolicy(
                policy_id=policy_id,
                name=str(row.get("name") or row.get("displayName") or policy_id),
                policy_type="configuration_policy",
                platform=str(row["platforms"]) if row.get("platforms") else None,
                technologies=str(row["technologies"])
                if row.get("technologies")
                else None,
                settings=_configuration_settings(row),
                assignments=_assignments(row),
            )
        )
    for collection, policy_type in (
        ("deviceConfigurations", "device_configuration"),
        ("groupPolicyConfigurations", "group_policy_configuration"),
    ):
        for row in _as_rows(bundle.get(collection, [])):
            policy_id = str(row.get("id", "unknown"))
            settings = (
                _group_policy_settings(row)
                if policy_type == "group_policy_configuration"
                else _legacy_settings(row, policy_type)
            )
            policies.append(
                ObservedPolicy(
                    policy_id=policy_id,
                    name=str(row.get("displayName") or row.get("name") or policy_id),
                    policy_type=policy_type,
                    settings=settings,
                    assignments=_assignments(row),
                )
            )
    assets = tuple(
        ManagedAsset(
            asset_id=str(row.get("id", "unknown")),
            name=str(row.get("deviceName") or row.get("id") or "unknown"),
            operating_system=str(row["operatingSystem"])
            if row.get("operatingSystem")
            else None,
            os_version=str(row["osVersion"]) if row.get("osVersion") else None,
            compliance_state=str(row["complianceState"])
            if row.get("complianceState")
            else None,
            management_agent=str(row["managementAgent"])
            if row.get("managementAgent")
            else None,
            encrypted=row.get("isEncrypted")
            if isinstance(row.get("isEncrypted"), bool)
            else None,
            last_sync_at=str(row["lastSyncDateTime"])
            if row.get("lastSyncDateTime")
            else None,
        )
        for row in _as_rows(bundle.get("managedDevices", []))
    )
    raw_errors = bundle.get("_errors", [])
    errors = (
        tuple(str(item) for item in raw_errors) if isinstance(raw_errors, list) else ()
    )
    return (
        tuple(
            sorted(
                policies, key=lambda item: (item.policy_type, item.name, item.policy_id)
            )
        ),
        assets,
        errors,
    )
