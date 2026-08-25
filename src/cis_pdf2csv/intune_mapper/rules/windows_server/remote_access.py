from __future__ import annotations

from ...models import ImplementationMethod, MappingCandidate, NormalizedControl
from ..base import MappingRule, build_rule_candidate


class RemoteAccessRule(MappingRule):
    rule_id = "windows_server_2025.remote_access"

    def matches(self, control: NormalizedControl) -> bool:
        t = control.title.lower()
        return "remote desktop" in t or "winrm" in t or "remote access" in t

    def apply(self, control: NormalizedControl) -> MappingCandidate:
        return build_rule_candidate(
            control,
            rule_id=self.rule_id,
            implementation_method=ImplementationMethod.SETTINGS_CATALOG,
            intune_area="Remote Access",
            setting_name="Remote management",
            confidence=0.7,
        )
