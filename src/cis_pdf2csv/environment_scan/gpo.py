from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import (
    AssignmentKind,
    ObservedPolicy,
    ObservedSetting,
    PolicyAssignment,
)


class GpoParseError(ValueError):
    """Raised when a GPO report is not parseable as a GPO inventory."""


SETTING_ELEMENTS = {
    "Policy",
    "Registry",
    "RegistrySetting",
    "SecurityOptions",
    "UserRightsAssignment",
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1]


def _first_text(node: ET.Element, names: set[str]) -> str | None:
    for child in node.iter():
        if _local_name(child.tag) in names and child.text and child.text.strip():
            return child.text.strip()
    return None


def _setting_value(node: ET.Element) -> str:
    values: dict[str, list[str]] = {}
    for child in node.iter():
        if child is node or list(child):
            continue
        text = (child.text or "").strip()
        if not text:
            continue
        name = _local_name(child.tag)
        if name in {"Explain", "Supported", "Category"}:
            continue
        values.setdefault(name, []).append(text)
    return json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _settings(
    root: ET.Element, policy_id: str, policy_name: str, source: str
) -> tuple[ObservedSetting, ...]:
    settings: list[ObservedSetting] = []
    seen: set[tuple[str, str]] = set()
    for node in root.iter():
        if _local_name(node.tag) not in SETTING_ELEMENTS:
            continue
        display_name = _first_text(
            node, {"Name", "DisplayName", "ValueName", "KeyName"}
        )
        if not display_name:
            continue
        key_path = _first_text(node, {"KeyPath", "Key", "Path"})
        value_name = _first_text(node, {"ValueName", "Name"})
        identity = "gpo:" + ":".join(
            part.casefold() for part in (key_path, value_name or display_name) if part
        )
        value = _setting_value(node)
        key = (identity, value)
        if key in seen:
            continue
        seen.add(key)
        settings.append(
            ObservedSetting(
                identity=identity,
                display_name=display_name,
                value=value,
                policy_id=policy_id,
                policy_name=policy_name,
                source_path=source,
            )
        )
    return tuple(sorted(settings, key=lambda item: (item.identity, item.value)))


def _assignments(root: ET.Element) -> tuple[PolicyAssignment, ...]:
    assignments: list[PolicyAssignment] = []
    for node in root.iter():
        if _local_name(node.tag) != "LinksTo":
            continue
        target = _first_text(node, {"SOMPath", "SOMName"})
        if target:
            assignments.append(
                PolicyAssignment(
                    kind=AssignmentKind.INCLUDE,
                    target_type="gpo_link",
                    target_id=target,
                )
            )
    return tuple(assignments)


def _parse_gpo(root: ET.Element, path: Path) -> ObservedPolicy:
    policy_name = _first_text(root, {"Name"}) or path.stem
    policy_id = _first_text(root, {"Identifier", "ID", "Guid"}) or path.stem
    return ObservedPolicy(
        policy_id=policy_id,
        name=policy_name,
        policy_type="group_policy_object",
        platform="windows",
        technologies="group_policy",
        settings=_settings(root, policy_id, policy_name, str(path)),
        assignments=_assignments(root),
    )


def parse_gpo_reports(path: Path) -> tuple[ObservedPolicy, ...]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise GpoParseError(f"Cannot parse GPO XML report {path}: {exc}") from exc
    root_type = _local_name(root.tag)
    if root_type == "GPO":
        return (_parse_gpo(root, path),)
    if root_type == "GPOS":
        policies = tuple(
            _parse_gpo(child, path) for child in root if _local_name(child.tag) == "GPO"
        )
        if policies:
            return policies
    raise GpoParseError(f"GPO XML root not detected in {path}")


def parse_gpo_report(path: Path) -> ObservedPolicy:
    policies = parse_gpo_reports(path)
    if len(policies) != 1:
        raise GpoParseError(
            f"Expected one GPO in {path}, found {len(policies)}; use parse_gpo_reports"
        )
    return policies[0]


def gpo_report_paths(path: Path) -> tuple[Path, ...]:
    if path.is_file():
        return (path,)
    if path.is_dir():
        paths = tuple(sorted(item for item in path.rglob("*.xml") if item.is_file()))
        if paths:
            return paths
        raise GpoParseError(f"No XML reports found in GPO input directory: {path}")
    raise GpoParseError(f"GPO input not found: {path}")
